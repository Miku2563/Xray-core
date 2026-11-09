package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	stderrors "errors"
	"hash/fnv"
	"io"
	"mime"
	stdnet "net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core" // [改] 新增:dialViaDispatcher 兜底用
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

const (
	dohMediaType       = "application/dns-message"
	dohMaxResponseSize = 65535
	dohMaxErrBodySize  = 4096
	dohMaxAttempts     = 2
	dohDefaultTimeout  = 5 * time.Second

	// 同一服务器同时在途的请求数上限。
	// 服务端 MAX_CONCURRENT_STREAMS 通常 ≥100，因此最多同时 1~2 条 h2 连接，
	// 不会因突发流量无限开连接。等待受 ctx deadline 约束。
	dohMaxInflight = 128

	// 预热相关参数
	dohWarmupName        = "."              // 根域 NS 查询：报文小，几乎所有解析器都能应答
	dohWarmupTimeout     = 5 * time.Second  // 单次预热超时
	dohWarmupMinInterval = 3 * time.Second  // 去抖：两次非强制预热之间的最小间隔
	dohOldConnGrace      = 30 * time.Second // 网络切换后，旧连接池的回收宽限期
	dohNetworkPollPeriod = 5 * time.Second  // 网络变化轮询周期
)

// dohConn 封装一组 HTTP/2 连接池。网络切换时整体替换，而不是修改其内部状态。
type dohConn struct {
	transport *http2.Transport
}

// dohDialError 标记拨号阶段（含 TLS 握手、ALPN 校验）的错误。
// 这类错误立刻重试通常没有意义。
type dohDialError struct{ err error }

func (e *dohDialError) Error() string { return e.err.Error() }
func (e *dohDialError) Unwrap() error { return e.err }

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
//
// 资源模型：
//   - 同时在途请求 ≤ dohMaxInflight，h2 连接数随之受限。
//   - 网络监听使用全局唯一的 goroutine，订阅者以弱引用持有，
//     即使实例没有被 Close 也会被自动剔除，不会泄漏。
//   - 预热同一时刻最多一个。
type DoHNameServer struct {
	cacheController *CacheController
	dohURL          string
	hostname        string
	clientIP        net.IP
	dispatcher      routing.Dispatcher
	h2c             bool

	conn     atomic.Pointer[dohConn] // 当前使用的 HTTP/2 连接池，可原子替换
	inflight chan struct{}

	// ctx 派生自构造时传入的 ctx：保留其中的 value（Xray 实例、inbound tag 等），
	// 但不继承取消信号，生命周期只由 Close 控制。后台预热与网络切换重预热都以它为父级。
	ctx       context.Context
	cancel    context.CancelFunc
	startOnce sync.Once
	closeOnce sync.Once

	warmMu     sync.Mutex
	lastWarm   time.Time
	warmBusy   bool
	warmSeq    uint64
	warmCancel context.CancelFunc
}

// NewDoHNameServer creates DOH/DOHL client object for remote/local resolving.
//
// ctx 必须携带 Xray 实例（core.FromContext(ctx) != nil）；
// 为使预热与真实查询走同样的路由，调用方还应在 ctx 中写入 DNS 的 inbound tag。
func NewDoHNameServer(ctx context.Context, serverURL *url.URL, dispatcher routing.Dispatcher, h2c bool, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *DoHNameServer { // [改] 新增 ctx 参数
	// 复制 URL，避免修改调用方持有的对象
	u := *serverURL
	u.Scheme = "https"

	mode := "DOH"
	if dispatcher == nil {
		mode = "DOHL"
	}
	errors.LogInfo(ctx, "DNS: created ", mode, " client for ", u.String(), ", with h2c ", h2c) // [改] context.Background() -> ctx

	// [改] 原为 context.WithCancel(context.Background())，丢失了 Xray 实例，
	// 导致预热拨号时 core.ToBackgroundDetachedContext 的 MustFromContext panic。
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s := &DoHNameServer{
		cacheController: NewCacheController(mode+"//"+u.Host, disableCache, serveStale, serveExpiredTTL),
		dohURL:          u.String(),
		hostname:        u.Hostname(),
		clientIP:        clientIP,
		dispatcher:      dispatcher,
		h2c:             h2c,
		inflight:        make(chan struct{}, dohMaxInflight),
		ctx:             sctx,
		cancel:          cancel,
	}
	s.conn.Store(s.newConn())
	return s
}

// Start 由 DNS Client 在启动阶段调用：后台预热连接并订阅网络变化。
// 预热在后台进行，失败不影响服务可用性。
func (s *DoHNameServer) Start() {
	s.startOnce.Do(func() {
		sharedNetWatcher.subscribe(s)
		go s.warm(s.ctx, false)
	})
}

// Warmup 预先建立 TLS + HTTP/2 连接。受去抖限制。
//
// [改] 调用方的 ctx 可能不带实例/inbound，因此 value 一律取自 s.ctx，
// 仅把调用方 ctx 的取消信号转接过来。
func (s *DoHNameServer) Warmup(ctx context.Context) {
	wctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	s.warm(wctx, false)
}

// OnNetworkChanged 在网络切换时调用（如 Wi-Fi 与蜂窝之间切换、出口 IP 变化）。
// 替换连接池以丢弃依附于旧网络的连接，然后强制重新预热。
// 平台层（如 Android）也可以直接调用它。
func (s *DoHNameServer) OnNetworkChanged() {
	if s.ctx.Err() != nil {
		return
	}
	s.resetTransport()
	go s.warm(s.ctx, true)
}

// warm 发送一次轻量查询以建立连接。响应被丢弃，不写入缓存。
// 同一时刻只保留一个预热：强制预热会取消正在进行的预热，非强制预热在有预热进行时直接跳过。
func (s *DoHNameServer) warm(parent context.Context, force bool) {
	if parent.Err() != nil {
		return
	}

	s.warmMu.Lock()
	if !force && (s.warmBusy || time.Since(s.lastWarm) < dohWarmupMinInterval) {
		s.warmMu.Unlock()
		return
	}
	if s.warmCancel != nil {
		s.warmCancel() // 取消旧预热（它可能还在使用旧网络的连接）
	}
	ctx, cancel := context.WithTimeout(parent, dohWarmupTimeout)
	s.warmSeq++
	seq := s.warmSeq
	s.warmCancel = cancel
	s.warmBusy = true
	s.lastWarm = time.Now()
	s.warmMu.Unlock()

	defer func() {
		cancel()
		s.warmMu.Lock()
		if s.warmSeq == seq { // 没有被更新的预热接管
			s.warmBusy = false
			s.warmCancel = nil
		}
		s.warmMu.Unlock()
	}()

	ctx = s.reqContext(ctx)

	// [改] 记录预热实际使用的 inbound tag，便于核对预热与真实查询的路由是否一致
	if in := session.InboundFromContext(ctx); in != nil {
		errors.LogDebug(ctx, "DNS: warmup ", s.Name(), " using inbound tag ", in.Tag)
	} else {
		errors.LogDebug(ctx, "DNS: warmup ", s.Name(), " has no inbound in context")
	}

	msg := warmupMessage()
	b, err := dns.PackMessage(&msg)
	if err != nil {
		errors.LogInfoInner(ctx, err, "DNS: failed to pack warmup query for ", s.Name())
		return
	}
	payload := bytes.Clone(b.Bytes()) // 独立副本，池化缓冲区立即归还
	b.Release()

	start := time.Now()
	if _, err := s.doHTTPS(ctx, payload); err != nil {
		errors.LogInfoInner(ctx, err, "DNS: warmup failed for ", s.Name())
		return
	}
	errors.LogInfo(ctx, "DNS: warmup ", s.Name(), " finished in ", time.Since(start))
}

// warmupMessage 构造预热用的 DNS 报文：根域 NS 查询，ID 固定为 0。
func warmupMessage() dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(dohWarmupName),
			Type:  dnsmessage.TypeNS,
			Class: dnsmessage.ClassINET,
		}},
	}
}

// resetTransport 替换连接池。旧连接池先关闭空闲连接，
// 正在使用的连接在宽限期后再次尝试回收，其余由 IdleConnTimeout 与 h2 PING 兜底。
func (s *DoHNameServer) resetTransport() {
	old := s.conn.Swap(s.newConn())
	if old != nil {
		old.transport.CloseIdleConnections()
		time.AfterFunc(dohOldConnGrace, old.transport.CloseIdleConnections)
	}
}

// newConn 创建新的 HTTP/2 连接池。
func (s *DoHNameServer) newConn() *dohConn {
	return &dohConn{
		transport: &http2.Transport{
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
			PingTimeout:     15 * time.Second,
			DialTLSContext:  s.dialTLS,
		},
	}
}

// dialTLS 是 http2.Transport 使用的拨号函数。
// TLS 完全由 uTLS 管理，因此忽略 http2 传入的 *tls.Config。
// 所有错误都带上 dohDialError 标记，便于调用方判断是否值得重试。
func (s *DoHNameServer) dialTLS(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	dest, err := net.ParseDestination(network + ":" + addr)
	if err != nil {
		return nil, &dohDialError{err}
	}

	var conn net.Conn
	if s.dispatcher != nil {
		conn, err = s.dialViaDispatcher(ctx, dest)
	} else {
		log.Record(&log.AccessMessage{
			From:   "DNS",
			To:     s.dohURL,
			Status: log.AccessAccepted,
			Detour: "local",
		})
		conn, err = internet.DialSystem(ctx, dest, nil)
	}
	if err != nil {
		return nil, &dohDialError{err}
	}

	if s.h2c {
		return conn, nil
	}
	tlsConn, err := s.handshakeTLS(ctx, conn)
	if err != nil {
		return nil, &dohDialError{err}
	}
	return tlsConn, nil
}

// dialViaDispatcher 通过 Xray 路由链路建立连接。
func (s *DoHNameServer) dialViaDispatcher(ctx context.Context, dest net.Destination) (net.Conn, error) {
	// [改] 兜底：此函数运行在 net/http 的拨号 goroutine 中，panic 无法被调用方 recover，
	// 会直接使进程崩溃。拿不到实例时返回普通错误。
	if core.FromContext(ctx) == nil {
		return nil, errors.New("DoH dial context carries no xray instance")
	}

	dnsCtx := toDnsContext(ctx, s.dohURL)
	if s.h2c {
		dnsCtx = session.ContextWithMitmAlpn11(dnsCtx, false)
		dnsCtx = session.ContextWithMitmServerName(dnsCtx, s.hostname)
	}

	link, err := s.dispatcher.Dispatch(dnsCtx, dest)
	if err != nil {
		return nil, err
	}

	// 拨号返回后若 ctx 已取消，需要主动关闭链路，否则会泄漏
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

// handshakeTLS 使用 uTLS 完成握手，并校验协商的 ALPN 必须为 h2。
func (s *DoHNameServer) handshakeTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	uconn := utls.UClient(conn, &utls.Config{ServerName: s.hostname}, utls.HelloChrome_Auto)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		_ = uconn.Close()
		return nil, errors.New("DoH server did not negotiate h2, negotiated: ", proto)
	}
	return uconn, nil
}

// Name implements Server.
func (s *DoHNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *DoHNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

// newReqID RFC 8484 建议 DNS ID 为 0，有利于 HTTP 缓存。
func (s *DoHNameServer) newReqID() uint16 {
	return 0
}

// getCacheController implements CachedNameserver.
func (s *DoHNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// Close 停止后台任务、取消订阅并关闭空闲连接。可重复调用。
func (s *DoHNameServer) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		sharedNetWatcher.unsubscribe(s)
	})
	if c := s.conn.Load(); c != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

// sendQuery implements CachedNameserver.
func (s *DoHNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", fqdn)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dohDefaultTimeout)
	}
	// 错误上报用带 deadline 的 ctx，保证即使调用方 ctx 没有 deadline，
	// 在消费方退出后 goroutine 也一定会结束
	reportCtx, cancelReport := context.WithDeadline(ctx, deadline)
	defer cancelReport()

	if s.isSelfQuery(fqdn) {
		errors.LogError(ctx, s.Name(), " tries to resolve itself! Use IP or set \"hosts\" instead")
		err := errors.New("tries to resolve itself! ", s.Name())
		for i := 0; i < enabledFamilies(option); i++ {
			sendErr(reportCtx, noResponseErrCh, err)
		}
		return
	}

	// 随机长度 padding（而非 RFC 8467 的 Block-Length padding），降低流量特征
	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, int(crypto.RandBetween(100, 300))))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		for i := 0; i < enabledFamilies(option); i++ {
			sendErr(reportCtx, noResponseErrCh, err)
		}
		return
	}

	for _, req := range reqs {
		go s.resolveOne(ctx, deadline, noResponseErrCh, fqdn, req)
	}
}

// reqContext 为请求附加 Content 信息。查询与预热共用。
// [改] 注释更正：parent 中的实例与 inbound 由调用方保证——
// 普通查询来自 Client.QueryIP，预热来自 s.ctx（构造时已写入）。
func (s *DoHNameServer) reqContext(parent context.Context) context.Context {
	return session.ContextWithContent(parent, &session.Content{
		Protocol:       "https",
		SkipDNSResolve: true,
	})
}

// resolveOne 处理单个请求（A 或 AAAA），使用独立的子 context。
func (s *DoHNameServer) resolveOne(parent context.Context, deadline time.Time, errCh chan<- error, fqdn string, r *dnsRequest) {
	dnsCtx, cancel := context.WithDeadline(s.reqContext(parent), deadline)
	defer cancel()

	// 并发上限：等待受 deadline 约束，不会无限排队
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	case <-dnsCtx.Done():
		err := errors.New("too many concurrent DoH queries on ", s.Name()).Base(dnsCtx.Err())
		errors.LogInfoInner(parent, err, "dropped query for ", fqdn)
		sendErr(dnsCtx, errCh, err)
		return
	}

	b, err := dns.PackMessage(r.msg)
	if err != nil {
		errors.LogErrorInner(parent, err, "failed to pack dns query for ", fqdn)
		sendErr(dnsCtx, errCh, err)
		return
	}
	// 请求体必须使用独立副本：出错或取消后 RoundTrip 可能先于 h2 写 goroutine 返回，
	// 若仍引用池化缓冲区，归还后会产生数据竞争
	payload := bytes.Clone(b.Bytes())
	b.Release()

	body, err := s.doHTTPS(dnsCtx, payload)
	if err != nil {
		errors.LogErrorInner(parent, err, "failed to retrieve response for ", fqdn)
		sendErr(dnsCtx, errCh, err)
		return
	}

	rec, err := parseResponse(body)
	if err != nil {
		errors.LogErrorInner(parent, err, "failed to handle DOH response for ", fqdn)
		sendErr(dnsCtx, errCh, err)
		return
	}
	s.cacheController.updateRecord(r, rec)
}

// doHTTPS 对可恢复的传输层错误做有限次重试（例如复用的连接已被服务端关闭）。
func (s *DoHNameServer) doHTTPS(ctx context.Context, payload []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < dohMaxAttempts; attempt++ {
		body, retryable, err := s.doOnce(ctx, payload)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// dohRetryable 判断 RoundTrip 错误是否值得立刻重试。
func dohRetryable(err error) bool {
	var dialErr *dohDialError
	if stderrors.As(err, &dialErr) {
		// 拨号/握手/ALPN 失败：立刻重试没有意义。
		// 例外：h2 连接池的拨号可能被多个请求共享，别的请求取消会连带本请求失败，
		// 此时本请求自己的 ctx 仍然有效（doHTTPS 会检查 ctx.Err()），重试是合理的。
		return stderrors.Is(err, context.Canceled)
	}
	return true
}

// doOnce 执行一次 DoH 请求。第二个返回值表示该错误是否可重试。
func (s *DoHNameServer) doOnce(ctx context.Context, payload []byte) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.dohURL, bytes.NewReader(payload))
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("Accept", dohMediaType)
	req.Header.Set("Content-Type", dohMediaType)
	utils.TryDefaultHeadersWith(req.Header, "fetch")
	req.Header.Set("X-Padding", utils.H2Base62Pad(crypto.RandBetween(100, 1000)))

	// 直接使用 RoundTrip：不需要 http.Client 的重定向跟随，
	// 否则重定向目标会再走一遍 dispatcher 拨号
	resp, err := s.conn.Load().transport.RoundTrip(req)
	if err != nil {
		return nil, dohRetryable(err), err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dohMaxErrBodySize))
		return nil, false, errors.New("DoH server returned code ", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if mediaType, _, err := mime.ParseMediaType(ct); err != nil || mediaType != dohMediaType {
			return nil, false, errors.New("unexpected content-type from DoH server: ", ct)
		}
	}

	body, err := readDoHBody(resp)
	if err != nil {
		return nil, !stderrors.Is(err, errDoHTooLarge), err
	}
	return body, false, nil
}

var errDoHTooLarge = stderrors.New("DoH response exceeds maximum DNS message size")

// readDoHBody 读取响应体：长度已知时精确分配，未知时用带上限的 ReadAll。
func readDoHBody(resp *http.Response) ([]byte, error) {
	if resp.ContentLength > dohMaxResponseSize {
		return nil, errDoHTooLarge
	}
	if n := resp.ContentLength; n > 0 {
		body := make([]byte, n)
		if _, err := io.ReadFull(resp.Body, body); err != nil {
			return nil, err
		}
		return body, nil
	}
	// 未知长度（例如响应被透明解压）：多读 1 字节用于检测超限
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dohMaxResponseSize {
		return nil, errDoHTooLarge
	}
	return body, nil
}

// isSelfQuery 检测是否在解析 DoH 服务器自身的域名（会导致循环依赖）。
func (s *DoHNameServer) isSelfQuery(fqdn string) bool {
	return strings.EqualFold(strings.TrimSuffix(fqdn, "."), s.hostname)
}

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

// ---------------------------------------------------------------------------
// 全局唯一的网络变化监听
// ---------------------------------------------------------------------------

// netWatcher 用一个 goroutine 服务所有 DoH 实例。
// 订阅者以弱引用保存：实例被丢弃（即使没有 Close）后会在下一轮自动剔除，
// 订阅表为空时 goroutine 自行退出，不留后台任务。
type netWatcher struct {
	mu      sync.Mutex
	subs    map[weak.Pointer[DoHNameServer]]struct{}
	running bool
}

var sharedNetWatcher = &netWatcher{subs: make(map[weak.Pointer[DoHNameServer]]struct{})}

func (w *netWatcher) subscribe(s *DoHNameServer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.subs[weak.Make(s)] = struct{}{}
	if !w.running {
		w.running = true
		go w.loop()
	}
}

func (w *netWatcher) unsubscribe(s *DoHNameServer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.subs, weak.Make(s))
}

// snapshot 返回仍然存活的订阅者；没有订阅者时把 running 置 false 并通知 loop 退出。
// 判断与置位在同一把锁内完成，与 subscribe 不会产生"漏启动"的竞态。
func (w *netWatcher) snapshot() ([]*DoHNameServer, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	live := make([]*DoHNameServer, 0, len(w.subs))
	for wp := range w.subs {
		if s := wp.Value(); s != nil {
			live = append(live, s)
		} else {
			delete(w.subs, wp)
		}
	}
	if len(live) == 0 {
		w.running = false
		return nil, false
	}
	return live, true
}

func (w *netWatcher) loop() {
	last, haveLast := interfaceSignature()
	ticker := time.NewTicker(dohNetworkPollPeriod)
	defer ticker.Stop()

	for range ticker.C {
		servers, ok := w.snapshot()
		if !ok {
			return
		}
		cur, ok := interfaceSignature()
		if !ok {
			continue // 部分平台无法枚举接口，应由平台层调用 OnNetworkChanged
		}
		if !haveLast {
			last, haveLast = cur, true // 初始读取失败：只记录基线，不触发回调
			continue
		}
		if cur == last {
			continue
		}
		last = cur
		for _, s := range servers {
			s.OnNetworkChanged()
		}
	}
}

// interfaceSignature 返回所有"有意义"的接口地址的哈希。
// 忽略回环与链路本地地址，减少虚拟网卡带来的误报。
func interfaceSignature() (uint64, bool) {
	addrs, err := stdnet.InterfaceAddrs()
	if err != nil {
		return 0, false
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipNet, ok := a.(*stdnet.IPNet); ok {
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
		}
		parts = append(parts, a.String())
	}
	sort.Strings(parts)
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64(), true
}

// ---------------------------------------------------------------------------
// 包内共享的小工具
// ---------------------------------------------------------------------------

// enabledFamilies 返回启用的地址族数量（IPv4 / IPv6）。
func enabledFamilies(option dns_feature.IPOption) int {
	n := 0
	if option.IPv4Enable {
		n++
	}
	if option.IPv6Enable {
		n++
	}
	return n
}

// sendErr 发送错误：先非阻塞尝试（通道有缓冲时立即成功，且不受 ctx 已结束的影响），
// 否则阻塞到发送成功或 ctx 结束。调用方必须传入带 deadline 或会被取消的 ctx，
// 否则消费方退出后 goroutine 会永久阻塞。
func sendErr(ctx context.Context, ch chan<- error, err error) {
	if ch == nil {
		return
	}
	select {
	case ch <- err:
		return
	default:
	}
	select {
	case ch <- err:
	case <-ctx.Done():
	}
}

// closeIfPossible 关闭实现了 common.Closable 的对象。
func closeIfPossible(v interface{}) {
	if c, ok := v.(common.Closable); ok {
		_ = c.Close()
	}
}
