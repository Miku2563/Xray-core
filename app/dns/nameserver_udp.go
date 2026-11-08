package dns

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	classicDefaultPort   = 53
	classicEDNSUDPSize   = 1232            // DNS Flag Day 2020 推荐值
	classicPendingTTL    = 8 * time.Second // pending 请求的最长存活时间
	classicCleanupPeriod = 5 * time.Second // 过期清理周期（仅在有 pending 时运行）
	// 同一服务器上最多同时挂起的请求数。
	// 刻意低于 ID 空间（65536）的一半，保证随机探测空闲 ID 的期望次数不超过 2 次。
	classicMaxPending = 1 << 15

	// 重传：请求发出后若在 classicRetryDelay 内没有应答，用同一 ID 重发一次。
	// 剩余时间不足时按剩余时间的一半计算；低于 classicMinRetryDelay 则不重传。
	classicRetryDelay    = 1500 * time.Millisecond
	classicMinRetryDelay = 300 * time.Millisecond
)

var (
	errClassicClosed      = errors.New("DNS UDP server is closed")
	errClassicPendingFull = errors.New("too many pending DNS requests")
)

// classicStrictSource 为 true 时校验响应来源的地址与端口。
// 若某些透明代理或出站使 Source 与服务器地址不一致，可设为 false（会降低抗欺骗能力）。
var classicStrictSource = true

// ClassicNameServer implemented traditional UDP DNS.
// 收到 TC（截断）响应时：先尝试带 EDNS0 的 UDP 重试，仍被截断（或无法重试）则回退 TCP。
// 请求发出后若迟迟没有应答，会用同一 ID 重传一次，以应对 UDP 丢包。
//
// 资源模型：没有常驻 goroutine。清理定时器只在 pending 表非空时存在，表空即停止；
// 每个 pending 项最多持有一个一次性重传定时器，请求完成、被清扫或 Close 时都会停止。
// 因此即使配置重载后旧实例没有被 Close，也不会留下后台任务。
type ClassicNameServer struct {
	mu              sync.RWMutex
	cacheController *CacheController
	address         *net.Destination
	dispatcher      routing.Dispatcher
	requests        map[uint16]*udpDnsRequest
	udpServer       *udp.Dispatcher
	tcpFallback     *tcpExchanger // 与 UDP 同一目标地址的 TCP 查询能力（自带并发上限）
	clientIP        net.IP

	// 以下字段受 mu 保护
	cleanupTimer     *time.Timer
	cleanupScheduled bool
	closed           bool
}

type udpDnsRequest struct {
	dnsRequest
	ctx   context.Context
	errCh chan<- error // 回退失败时用于快速通知 queryIP，可为 nil

	// 以下字段受 ClassicNameServer.mu 保护
	payload    []byte      // 已打包的查询报文副本，仅用于重传
	retryTimer *time.Timer // 一次性重传定时器
}

// stopRetryLocked 停止重传定时器并释放报文副本。必须持有 mu。
func (r *udpDnsRequest) stopRetryLocked() {
	if r.retryTimer != nil {
		r.retryTimer.Stop()
		r.retryTimer = nil
	}
	r.payload = nil
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(classicDefaultPort)
	}

	tcpDest := net.TCPDestination(address.Address, address.Port)
	var dial func(context.Context) (net.Conn, error)
	if dispatcher == nil {
		dial = localDial(tcpDest)
	} else {
		dial = dispatcherDial(dispatcher, tcpDest)
	}

	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         &address,
		dispatcher:      dispatcher,
		requests:        make(map[uint16]*udpDnsRequest),
		tcpFallback:     newTCPExchanger(tcpDest, dial),
		clientIP:        clientIP,
	}
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)

	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

// Name implements Server.
func (s *ClassicNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *ClassicNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

// Close 停止清理与重传定时器、释放 pending 表，并关闭 UDP 分发器和 TCP 回退通道。
// 关闭后不再接受新的 pending 请求。可重复调用。
// 即使不调用 Close，空闲实例也不持有任何后台任务。
func (s *ClassicNameServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cleanupTimer != nil {
		s.cleanupTimer.Stop()
		s.cleanupTimer = nil
	}
	s.cleanupScheduled = false
	for _, req := range s.requests {
		req.stopRetryLocked()
	}
	s.requests = make(map[uint16]*udpDnsRequest)
	s.mu.Unlock()

	// 在释放 mu 之后再关闭下层资源：它们关闭时可能回调 HandleResponse，
	// 持锁关闭会有死锁风险。
	closeIfPossible(s.udpServer)
	closeIfPossible(s.tcpFallback)
	return nil
}

// RequestsCleanup 立即清理已过期的 pending 请求（保留导出方法以兼容外部调用）。
func (s *ClassicNameServer) RequestsCleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(time.Now())
	return nil
}

// sweepLocked 删除过期条目；表被清空时重建 map 以释放内存（Go 的 map 不会自动收缩）。
func (s *ClassicNameServer) sweepLocked(now time.Time) {
	removed := 0
	for id, req := range s.requests {
		if now.After(req.expire) {
			req.stopRetryLocked()
			delete(s.requests, id)
			removed++
		}
	}
	if removed > 0 && len(s.requests) == 0 {
		s.requests = make(map[uint16]*udpDnsRequest)
	}
}

// scheduleCleanupLocked 在表由空变非空时启动清理定时器。必须持有 mu。
func (s *ClassicNameServer) scheduleCleanupLocked() {
	if s.cleanupScheduled || s.closed {
		return
	}
	s.cleanupScheduled = true
	s.cleanupTimer = time.AfterFunc(classicCleanupPeriod, s.cleanupTick)
}

// cleanupTick 清理一轮；表仍非空则继续排下一轮，否则停止，不留后台任务。
func (s *ClassicNameServer) cleanupTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.cleanupScheduled = false
		return
	}
	s.sweepLocked(time.Now())
	if len(s.requests) == 0 {
		s.cleanupScheduled = false
		s.cleanupTimer = nil
		return
	}
	s.cleanupTimer.Reset(classicCleanupPeriod)
}

// HandleResponse handles udp response packet from remote DNS server.
func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	payload := packet.Payload
	defer payload.Release()
	raw := payload.Bytes()

	if !s.isFromServer(packet.Source) {
		errors.LogInfo(ctx, s.Name(), " dropped packet from unexpected source ", packet.Source.String())
		return
	}

	hdr, q, err := parseHeaderAndQuestion(raw)
	if err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " malformed response dropped")
		return
	}
	if !hdr.Response {
		return
	}

	// 重传后服务器可能对同一查询应答两次，第二个包会走到这里并被丢弃，属于正常现象
	req := s.lookupPending(hdr.ID, q)
	if req == nil {
		errors.LogInfo(ctx, s.Name(), " no matching pending request for id ", hdr.ID)
		return
	}

	// 必须在 parseResponse 之前处理 TC：被截断的报文可能在记录中间被切断，
	// 解析会失败，若先解析，回退就永远不会触发。
	// 截断响应里的任何记录都不可信，直接丢弃，不解析、不缓存。
	if hdr.Truncated {
		if s.removePending(req) { // 只有第一个到达的 TC 包触发回退
			s.handleTruncated(req)
		}
		return
	}

	ipRec, err := parseResponse(raw)
	if err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " failed to parse response")
		return
	}

	// 只有第一个通过校验的响应生效，重复包直接丢弃
	if !s.removePending(req) {
		return
	}
	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

// handleTruncated 处理 TC 位。调用时 req 已从 pending 表移除。
//
//   - 原查询没有足够大的 EDNS0：换新 ID，带 EDNS0 重发 UDP（最多一次）。
//   - 已经使用了足够大的 EDNS0 仍被截断，或 UDP 重试无法进行：回退 TCP。
//     TCP 不占用 pending 表，并发由 tcpExchanger 的信号量限制。
func (s *ClassicNameServer) handleTruncated(req *udpDnsRequest) {
	msg, ok := withEDNS0Size(req.msg, classicEDNSUDPSize)
	if !ok {
		go s.queryTCP(req)
		return
	}

	retry := &udpDnsRequest{dnsRequest: req.dnsRequest, ctx: req.ctx, errCh: req.errCh}
	retry.msg = msg
	// 换新 ID，避免上一轮晚到的包串入这一轮；addPendingUntil 仍会处理冲突
	retry.msg.ID = s.newReqID()

	// 以原请求的过期时间封顶，重试不会把总时长翻倍
	if err := s.addPendingUntil(retry, req.expire); err != nil {
		errors.LogInfoInner(req.ctx, err, s.Name(), " cannot register EDNS0 retry, falling back to TCP")
		go s.queryTCP(req)
		return
	}

	if err := s.transmit(retry); err != nil {
		s.removePending(retry)
		errors.LogInfoInner(req.ctx, err, s.Name(), " failed to pack EDNS0 retry, falling back to TCP")
		go s.queryTCP(req)
		return
	}
}

// queryTCP 在 TCP 上重新查询（RFC 7766），结果写回本服务器自己的缓存。
// 连接、ctx、信号量的释放都在 tcpExchanger.exchange 内部完成。
func (s *ClassicNameServer) queryTCP(req *udpDnsRequest) {
	ctx := session.ContextWithContent(req.ctx, &session.Content{
		Protocol:       "dns",
		SkipDNSResolve: true,
	})

	payload, err := s.tcpFallback.exchange(ctx, req.msg)
	if err != nil {
		errors.LogInfoInner(req.ctx, err, s.Name(), " TCP fallback failed")
		reportErr(req.errCh, err) // 快速失败，不让 queryIP 空等到超时
		return
	}

	ipRec, err := parseResponse(payload)
	if err != nil {
		errors.LogInfoInner(req.ctx, err, s.Name(), " failed to parse TCP response")
		reportErr(req.errCh, err)
		return
	}
	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

// newReqID 生成随机 ID，替代可预测的顺序计数器。
// 冲突由 addPendingUntil 处理。
func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(crypto.RandBetween(0, 0xFFFF))
}

// addPending 登记一个待响应的请求。
func (s *ClassicNameServer) addPending(req *udpDnsRequest) error {
	return s.addPendingUntil(req, time.Time{})
}

// addPendingUntil 登记一个待响应的请求，并分配一个当前未被占用的 ID。
// limit 非零时，过期时间不会晚于 limit。
// 会修改 req.msg.ID，因此必须在打包报文之前调用。
// 返回 errClassicClosed 表示服务器已关闭，errClassicPendingFull 表示表已满。
func (s *ClassicNameServer) addPendingUntil(req *udpDnsRequest, limit time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errClassicClosed
	}
	if len(s.requests) >= classicMaxPending {
		return errClassicPendingFull
	}
	for {
		if _, used := s.requests[req.msg.ID]; !used {
			break
		}
		req.msg.ID = s.newReqID()
	}

	// 过期时间取 TTL、query deadline、limit 中最早者
	exp := time.Now().Add(classicPendingTTL)
	if d, ok := req.ctx.Deadline(); ok && d.Before(exp) {
		exp = d
	}
	if !limit.IsZero() && limit.Before(exp) {
		exp = limit
	}
	req.expire = exp
	s.requests[req.msg.ID] = req
	s.scheduleCleanupLocked()
	return nil
}

// removePending 移除 pending 项，仅当 map 中仍是同一个请求时才删除，
// 同时停止它的重传定时器。
// 返回 false 表示该请求已被其他路径处理。
func (s *ClassicNameServer) removePending(req *udpDnsRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.requests[req.msg.ID]
	if !ok || cur != req {
		return false
	}
	cur.stopRetryLocked()
	delete(s.requests, req.msg.ID)
	return true
}

// lookupPending 按 ID 查找 pending 请求，并校验 Question 一致。
func (s *ClassicNameServer) lookupPending(id uint16, q dnsmessage.Question) *udpDnsRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.requests[id]
	if !ok || !questionMatches(req.msg, q) {
		return nil
	}
	return req
}

// transmit 打包并发送一个已登记的 pending 请求，同时武装一次性重传定时器。
// 打包失败时返回错误，调用方负责 removePending。
func (s *ClassicNameServer) transmit(req *udpDnsRequest) error {
	b, err := dns.PackMessage(req.msg)
	if err != nil {
		return err
	}
	// 必须在 Dispatch 之前武装：Dispatch 会消费并释放 b；
	// 武装时会确认请求仍在表中，避免给已完成的请求遗留定时器。
	s.armRetransmit(req, b.Bytes())
	s.udpServer.Dispatch(toDnsContext(req.ctx, s.address.String()), *s.address, b)
	return nil
}

// armRetransmit 为 pending 请求设置一次性重传定时器。
// packed 是刚打包的报文，只有真正武装时才复制一份。
func (s *ClassicNameServer) armRetransmit(req *udpDnsRequest, packed []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.requests[req.msg.ID] != req {
		return // 应答已抢先到达，或服务器已关闭
	}
	delay := classicRetryDelay
	if half := time.Until(req.expire) / 2; half < delay {
		delay = half
	}
	if delay < classicMinRetryDelay {
		return // 剩余时间太短，重传没有意义
	}
	req.payload = bytes.Clone(packed)
	req.retryTimer = time.AfterFunc(delay, func() { s.retransmit(req) })
}

// retransmit 在重传定时器到期时执行：请求仍在等待则用同一 ID 重发原报文。
// 只重传一次，之后若仍无应答则等待过期（或由 TC / 清扫路径处理）。
func (s *ClassicNameServer) retransmit(req *udpDnsRequest) {
	s.mu.Lock()
	if s.closed || s.requests[req.msg.ID] != req || req.ctx.Err() != nil || req.payload == nil {
		s.mu.Unlock()
		return
	}
	payload := req.payload
	req.payload = nil
	req.retryTimer = nil
	s.mu.Unlock()

	errors.LogInfo(req.ctx, s.Name(), " no response for ", req.domain, " ", req.reqType, ", retransmitting")
	s.udpServer.Dispatch(toDnsContext(req.ctx, s.address.String()), *s.address, buf.FromBytes(payload))
}

// isFromServer 校验响应来源是否为配置的服务器。
func (s *ClassicNameServer) isFromServer(src net.Destination) bool {
	if !classicStrictSource {
		return true
	}
	if src.Port != s.address.Port {
		return false
	}
	if !s.address.Address.Family().IsIP() {
		// 服务器配置为域名时无法比较 IP，仅校验端口
		return true
	}
	return src.Address.Family().IsIP() && src.Address.IP().Equal(s.address.Address.IP())
}

// getCacheController implements CachedNameserver.
func (s *ClassicNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *ClassicNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		// 每个启用的地址族各上报一次
		if option.IPv4Enable {
			reportErr(noResponseErrCh, err)
		}
		if option.IPv6Enable {
			reportErr(noResponseErrCh, err)
		}
		return
	}

	for _, req := range reqs {
		s.sendOne(ctx, noResponseErrCh, fqdn, req)
	}
}

// sendOne 发送单个请求（A 或 AAAA）。失败时只影响该请求，不中断其他请求。
func (s *ClassicNameServer) sendOne(ctx context.Context, errCh chan<- error, fqdn string, r *dnsRequest) {
	req := &udpDnsRequest{dnsRequest: *r, ctx: ctx, errCh: errCh}

	if err := s.addPending(req); err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " drop query for ", fqdn)
		reportErr(errCh, err)
		return
	}

	if err := s.transmit(req); err != nil {
		s.removePending(req)
		errors.LogErrorInner(ctx, err, "failed to pack dns query for ", fqdn)
		reportErr(errCh, err)
		return
	}
}

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

// parseHeaderAndQuestion 只解析报文头和第一个 Question，用于快速校验。
func parseHeaderAndQuestion(raw []byte) (dnsmessage.Header, dnsmessage.Question, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		return hdr, dnsmessage.Question{}, err
	}
	q, err := p.Question()
	if err != nil {
		return hdr, dnsmessage.Question{}, err
	}
	return hdr, q, nil
}

// questionMatches 比较请求与响应的 Question（域名忽略大小写）。
func questionMatches(req *dnsmessage.Message, q dnsmessage.Question) bool {
	if len(req.Questions) == 0 {
		return false
	}
	want := req.Questions[0]
	return want.Type == q.Type &&
		want.Class == q.Class &&
		strings.EqualFold(want.Name.String(), q.Name.String())
}

// withEDNS0Size 返回带有 EDNS0 OPT 记录（UDP 载荷大小为 size）的报文副本。
// 若已有 OPT 且其载荷大小不小于 size，返回 false，表示 UDP 重试无意义。
// 已有 OPT 的 Body（例如 ECS 选项）会被保留，不会丢失。
func withEDNS0Size(msg *dnsmessage.Message, size uint16) (*dnsmessage.Message, bool) {
	out := *msg
	out.Additionals = append([]dnsmessage.Resource(nil), msg.Additionals...)

	found := false
	for i := range out.Additionals {
		r := &out.Additionals[i]
		if r.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		if uint16(r.Header.Class) >= size {
			return nil, false
		}
		r.Header.Class = dnsmessage.Class(size)
		found = true
	}

	if !found {
		opt := dnsmessage.Resource{Body: &dnsmessage.OPTResource{}}
		common.Must(opt.Header.SetEDNS0(int(size), 0, false))
		out.Additionals = append(out.Additionals, opt)
	}
	return &out, true
}
