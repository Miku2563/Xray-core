package dns

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	classicDefaultPort    = 53
	classicEDNSUDPSize    = 1232            // DNS Flag Day 2020 推荐值
	classicPendingTTL     = 8 * time.Second // pending 请求的最长存活时间
	classicCleanupPeriod  = 5 * time.Second // 过期清理周期
	classicDefaultTimeout = 5 * time.Second // 无 deadline 时 TCP 回退的超时
	classicMaxPending     = 1 << 16         // 同一服务器上最多同时挂起的请求数（受 ID 空间限制）
)

// classicStrictSource 为 true 时校验响应来源的地址与端口。
// 若某些透明代理或出站使 Source 与服务器地址不一致，可设为 false（会降低抗欺骗能力）。
var classicStrictSource = true

// ClassicNameServer implemented traditional UDP DNS.
type ClassicNameServer struct {
	mu              sync.RWMutex
	cacheController *CacheController
	address         *net.Destination
	dispatcher      routing.Dispatcher
	requests        map[uint16]*udpDnsRequest
	udpServer       *udp.Dispatcher
	requestsCleanup *task.Periodic
	clientIP        net.IP
	closeOnce       sync.Once
}

type udpDnsRequest struct {
	dnsRequest
	ctx context.Context
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(classicDefaultPort)
	}

	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         &address,
		dispatcher:      dispatcher,
		requests:        make(map[uint16]*udpDnsRequest),
		clientIP:        clientIP,
	}
	s.requestsCleanup = &task.Periodic{
		Interval: classicCleanupPeriod,
		Execute:  s.RequestsCleanup,
	}
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)

	common.Must(s.requestsCleanup.Start())

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

// Close 停止清理任务并释放 pending 表。配置重载或销毁客户端时调用。
func (s *ClassicNameServer) Close() error {
	s.closeOnce.Do(func() {
		_ = s.requestsCleanup.Close()
		s.mu.Lock()
		s.requests = make(map[uint16]*udpDnsRequest)
		s.mu.Unlock()
	})
	return nil
}

// RequestsCleanup 清理已过期的 pending 请求。
// 返回值恒为 nil，清理任务随服务器生命周期运行，由 Close 停止。
func (s *ClassicNameServer) RequestsCleanup() error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, req := range s.requests {
		if now.After(req.expire) {
			delete(s.requests, id)
			removed++
		}
	}
	// Go 的 map 不会自动收缩，表空时重建以释放内存
	if removed > 0 && len(s.requests) == 0 {
		s.requests = make(map[uint16]*udpDnsRequest)
	}
	return nil
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

	req := s.lookupPending(hdr.ID, q)
	if req == nil {
		errors.LogInfo(ctx, s.Name(), " no matching pending request for id ", hdr.ID)
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

	if hdr.Truncated {
		s.handleTruncated(req)
		return
	}
	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

// handleTruncated 处理 TC 位：未使用 EDNS0 时升级后重发 UDP，否则回退 TCP。
func (s *ClassicNameServer) handleTruncated(req *udpDnsRequest) {
	msg, ok := withEDNS0Size(req.msg, classicEDNSUDPSize)
	if !ok {
		// 已经使用了足够大的 EDNS0 仍被截断，UDP 无法获得完整结果
		go s.queryTCP(req)
		return
	}

	retry := &udpDnsRequest{dnsRequest: req.dnsRequest, ctx: req.ctx}
	retry.msg = msg
	if !s.addPending(retry) {
		errors.LogInfo(req.ctx, s.Name(), " pending table full, skip EDNS0 retry")
		return
	}

	b, err := dns.PackMessage(retry.msg)
	if err != nil {
		s.removePending(retry)
		errors.LogErrorInner(req.ctx, err, s.Name(), " failed to pack EDNS0 retry")
		return
	}
	s.udpServer.Dispatch(toDnsContext(req.ctx, s.address.String()), *s.address, b)
}

// queryTCP 在 TCP 上重新查询（DNS over TCP，RFC 7766，报文前有 2 字节长度前缀）。
func (s *ClassicNameServer) queryTCP(req *udpDnsRequest) {
	deadline, ok := req.ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(classicDefaultTimeout)
	}
	ctx, cancel := context.WithDeadline(req.ctx, deadline)
	defer cancel()

	b, err := dns.PackMessage(req.msg)
	if err != nil {
		errors.LogErrorInner(ctx, err, s.Name(), " failed to pack TCP query")
		return
	}
	defer b.Release()
	payload := b.Bytes()

	conn, err := s.dialTCP(ctx)
	if err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " TCP fallback dial failed")
		return
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " failed to set TCP deadline")
		return
	}

	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := conn.Write(frame); err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " TCP write failed")
		return
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " TCP read length failed")
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " TCP read body failed")
		return
	}

	hdr, q, err := parseHeaderAndQuestion(body)
	if err != nil || !hdr.Response || hdr.ID != req.msg.ID || !questionMatches(req.msg, q) {
		errors.LogInfo(ctx, s.Name(), " TCP response does not match the query")
		return
	}

	ipRec, err := parseResponse(body)
	if err != nil {
		errors.LogInfoInner(ctx, err, s.Name(), " failed to parse TCP response")
		return
	}
	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

// dialTCP 通过 Xray 路由链路（或系统拨号）建立到服务器的 TCP 连接。
func (s *ClassicNameServer) dialTCP(ctx context.Context) (net.Conn, error) {
	dest := net.Destination{
		Network: net.Network_TCP,
		Address: s.address.Address,
		Port:    s.address.Port,
	}
	if s.dispatcher == nil {
		return internet.DialSystem(ctx, dest, nil)
	}

	link, err := s.dispatcher.Dispatch(toDnsContext(ctx, s.address.String()), dest)
	if err != nil {
		return nil, err
	}
	// 拨号返回后若 ctx 已结束，主动关闭链路，避免泄漏
	if ctxErr := ctx.Err(); ctxErr != nil {
		closeIfPossible(link.Writer)
		closeIfPossible(link.Reader)
		return nil, ctxErr
	}

	cc := common.ChainedClosable{}
	if cw, ok := link.Writer.(common.Closable); ok {
		cc = append(cc, cw)
	}
	if cr, ok := link.Reader.(common.Closable); ok {
		cc = append(cc, cr)
	}
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(link.Writer),
		cnc.ConnectionOutputMulti(link.Reader),
		cnc.ConnectionOnClose(cc),
	), nil
}

// newReqID 生成随机 ID，替代可预测的顺序计数器。
// 冲突由 addPending 处理。
func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(crypto.RandBetween(0, 0xFFFF))
}

// addPending 登记一个待响应的请求，并分配一个当前未被占用的 ID。
// 会修改 req.msg.ID，因此必须在打包报文之前调用。
func (s *ClassicNameServer) addPending(req *udpDnsRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.requests) >= classicMaxPending {
		return false
	}
	for {
		if _, used := s.requests[req.msg.ID]; !used {
			break
		}
		req.msg.ID = s.newReqID()
	}

	// 过期时间取 TTL 与 query deadline 中较早者
	exp := time.Now().Add(classicPendingTTL)
	if d, ok := req.ctx.Deadline(); ok && d.Before(exp) {
		exp = d
	}
	req.expire = exp
	s.requests[req.msg.ID] = req
	return true
}

// removePending 移除 pending 项，仅当 map 中仍是同一个请求时才删除。
// 返回 false 表示该请求已被其他路径处理。
func (s *ClassicNameServer) removePending(req *udpDnsRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.requests[req.msg.ID]
	if !ok || cur != req {
		return false
	}
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
		for i := 0; i < enabledFamilies(option); i++ {
			sendErr(ctx, noResponseErrCh, err)
		}
		return
	}

	for _, req := range reqs {
		s.sendOne(ctx, noResponseErrCh, fqdn, req)
	}
}

// sendOne 发送单个请求（A 或 AAAA）。失败时只影响该请求，不中断其他请求。
func (s *ClassicNameServer) sendOne(ctx context.Context, errCh chan<- error, fqdn string, r *dnsRequest) {
	req := &udpDnsRequest{dnsRequest: *r, ctx: ctx}

	if !s.addPending(req) {
		errors.LogInfo(ctx, s.Name(), " pending table full, drop query for ", fqdn)
		sendErr(ctx, errCh, errors.New("too many pending DNS requests"))
		return
	}

	b, err := dns.PackMessage(req.msg)
	if err != nil {
		s.removePending(req)
		errors.LogErrorInner(ctx, err, "failed to pack dns query for ", fqdn)
		sendErr(ctx, errCh, err)
		return
	}
	s.udpServer.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, b)
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
		common.Must(opt.Header.SetEDNS0(size, 0xfe00, true))
		out.Additionals = append(out.Additionals, opt)
	}
	return &out, true
}
