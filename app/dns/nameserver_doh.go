package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	stdnet "net"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	// 预热相关参数
	dohWarmupName        = "."              // 根域 NS 查询：报文小，几乎所有解析器都能应答
	dohWarmupTimeout     = 5 * time.Second  // 单次预热超时
	dohWarmupMinInterval = 3 * time.Second  // 去抖：两次非强制预热之间的最小间隔
	dohOldConnGrace      = 30 * time.Second // 网络切换后，旧连接池的回收宽限期
	dohNetworkPollPeriod = 5 * time.Second  // 网络变化轮询周期
)

// dohConn 封装一组 HTTP/2 连接池。网络切换时整体替换，而不是修改其内部状态。
type dohConn struct {
	client    *http.Client
	transport *http2.Transport
}

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	cacheController *CacheController
	dohURL          string
	hostname        string
	clientIP        net.IP
	dispatcher      routing.Dispatcher
	h2c             bool

	conn atomic.Pointer[dohConn] // 当前使用的 HTTP 客户端，可原子替换

	ctx       context.Context
	cancel    context.CancelFunc
	startOnce sync.Once
	closeOnce sync.Once

	warmMu   sync.Mutex
	lastWarm time.Time
}

// NewDoHNameServer creates DOH/DOHL client object for remote/local resolving.
func NewDoHNameServer(serverURL *url.URL, dispatcher routing.Dispatcher, h2c bool, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *DoHNameServer {
	// 复制 URL，避免修改调用方持有的对象
	u := *serverURL
	u.Scheme = "https"

	mode := "DOH"
	if dispatcher == nil {
		mode = "DOHL"
	}
	errors.LogInfo(context.Background(), "DNS: created ", mode, " client for ", u.String(), ", with h2c ", h2c)

	ctx, cancel := context.WithCancel(context.Background())
	s := &DoHNameServer{
		cacheController: NewCacheController(mode+"//"+u.Host, disableCache, serveStale, serveExpiredTTL),
		dohURL:          u.String(),
		hostname:        u.Hostname(),
		clientIP:        clientIP,
		dispatcher:      dispatcher,
		h2c:             h2c,
		ctx:             ctx,
		cancel:          cancel,
	}
	s.conn.Store(s.newConn())
	return s
}

// Start 由 DNS Client 在启动阶段调用：后台预热连接并开启网络变化监听。
// 预热在后台进行，失败不影响服务可用性。
func (s *DoHNameServer) Start() {
	s.startOnce.Do(func() {
		go s.Warmup(s.ctx)
		go watchNetwork(s.ctx, dohNetworkPollPeriod, s.OnNetworkChanged)
	})
}

// Warmup 预先建立 TLS + HTTP/2 连接。受去抖限制。
func (s *DoHNameServer) Warmup(ctx context.Context) {
	s.warm(ctx, false)
}

// OnNetworkChanged 在网络切换时调用（如 Wi-Fi 与蜂窝之间切换、出口 IP 变化）。
// 替换连接池以丢弃依附于旧网络的连接，然后强制重新预热。
func (s *DoHNameServer) OnNetworkChanged() {
	s.resetTransport()
	go s.warm(s.ctx, true)
}

// warm 发送一次轻量查询以建立连接。响应被丢弃，不写入缓存。
func (s *DoHNameServer) warm(parent context.Context, force bool) {
	s.warmMu.Lock()
	if !force && time.Since(s.lastWarm) < dohWarmupMinInterval {
		s.warmMu.Unlock()
		return
	}
	s.lastWarm = time.Now()
	s.warmMu.Unlock()

	if parent.Err() != nil {
		return
	}

	ctx, cancel := context.WithTimeout(parent, dohWarmupTimeout)
	defer cancel()
	ctx = s.reqContext(ctx)

	msg := warmupMessage()
	b, err := dns.PackMessage(&msg)
	if err != nil {
		errors.LogInfoInner(ctx, err, "DNS: failed to pack warmup query for ", s.Name())
		return
	}
	defer b.Release()

	start := time.Now()
	if _, err := s.doHTTPS(ctx, b.Bytes()); err != nil {
		// 即使服务端返回非 200，连接通常已经建立，这里仅记录日志
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
// 正在使用的连接在宽限期后再次尝试回收。
func (s *DoHNameServer) resetTransport() {
	old := s.conn.Swap(s.newConn())
	if old != nil {
		old.transport.CloseIdleConnections()
		time.AfterFunc(dohOldConnGrace, old.transport.CloseIdleConnections)
	}
}

// newConn 创建新的 HTTP/2 客户端。
func (s *DoHNameServer) newConn() *dohConn {
	t := &http2.Transport{
		IdleConnTimeout: net.ConnIdleTimeout,
		ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
		PingTimeout:     15 * time.Second,
		DialTLSContext:  s.dialTLS,
	}
	return &dohConn{
		client:    &http.Client{Transport: t},
		transport: t,
	}
}

// dialTLS 是 http2.Transport 使用的拨号函数。
// TLS 完全由 uTLS 管理，因此忽略 http2 传入的 *tls.Config。
func (s *DoHNameServer) dialTLS(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	dest, err := net.ParseDestination(network + ":" + addr)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if s.h2c {
		return conn, nil
	}
	return s.handshakeTLS(ctx, conn)
}

// dialViaDispatcher 通过 Xray 路由链路建立连接。
func (s *DoHNameServer) dialViaDispatcher(ctx context.Context, dest net.Destination) (net.Conn, error) {
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

// Close 停止后台任务并关闭空闲连接。
func (s *DoHNameServer) Close() error {
	s.closeOnce.Do(s.cancel)
	if c := s.conn.Load(); c != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

// sendQuery implements CachedNameserver.
func (s *DoHNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", fqdn)

	if s.isSelfQuery(fqdn) {
		errors.LogError(ctx, s.Name(), " tries to resolve itself! Use IP or set \"hosts\" instead")
		err := errors.New("tries to resolve itself!", s.Name())
		for i := 0; i < enabledFamilies(option); i++ {
			sendErr(ctx, noResponseErrCh, err)
		}
		return
	}

	// 随机长度 padding（而非 RFC 8467 的 Block-Length padding），降低流量特征
	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, int(crypto.RandBetween(100, 300))))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		for i := 0; i < enabledFamilies(option); i++ {
			sendErr(ctx, noResponseErrCh, err)
		}
		return
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dohDefaultTimeout)
	}

	for _, req := range reqs {
		go s.resolveOne(ctx, deadline, noResponseErrCh, fqdn, req)
	}
}

// reqContext 为请求附加 Inbound 与 Content 信息。查询与预热共用。
func (s *DoHNameServer) reqContext(parent context.Context) context.Context {
	ctx := parent
	if inbound := session.InboundFromContext(parent); inbound != nil {
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	return session.ContextWithContent(ctx, &session.Content{
		Protocol:       "https",
		SkipDNSResolve: true,
	})
}

// resolveOne 处理单个请求（A 或 AAAA），使用独立的子 context。
func (s *DoHNameServer) resolveOne(parent context.Context, deadline time.Time, errCh chan<- error, fqdn string, r *dnsRequest) {
	dnsCtx, cancel := context.WithDeadline(s.reqContext(parent), deadline)
	defer cancel()

	b, err := dns.PackMessage(r.msg)
	if err != nil {
		errors.LogErrorInner(parent, err, "failed to pack dns query for ", fqdn)
		sendErr(parent, errCh, err)
		return
	}
	defer b.Release()

	body, err := s.doHTTPS(dnsCtx, b.Bytes())
	if err != nil {
		errors.LogErrorInner(parent, err, "failed to retrieve response for ", fqdn)
		sendErr(parent, errCh, err)
		return
	}

	rec, err := parseResponse(body)
	if err != nil {
		errors.LogErrorInner(parent, err, "failed to handle DOH response for ", fqdn)
		sendErr(parent, errCh, err)
		return
	}
	s.cacheController.updateRecord(r, rec)
}

// doHTTPS 对传输层错误做有限次重试（例如复用的连接已被服务端关闭）。
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

	resp, err := s.conn.Load().client.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dohMaxErrBodySize))
		return nil, false, errors.New("DoH server returned code ", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, dohMediaType) {
		return nil, false, errors.New("unexpected content-type from DoH server: ", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseSize+1))
	if err != nil {
		return nil, true, err
	}
	if len(body) > dohMaxResponseSize {
		return nil, false, errors.New("DoH response exceeds maximum DNS message size")
	}
	return body, false, nil
}

// isSelfQuery 检测是否在解析 DoH 服务器自身的域名（会导致循环依赖）。
func (s *DoHNameServer) isSelfQuery(fqdn string) bool {
	return strings.EqualFold(strings.TrimSuffix(fqdn, "."), s.hostname)
}

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

// watchNetwork 定时检查本机接口地址签名，变化时回调。
// 在 Android 等平台上可能无法枚举接口，此时应由平台层调用 OnNetworkChanged。
func watchNetwork(ctx context.Context, period time.Duration, onChange func()) {
	last, _ := interfaceSignature()
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, err := interfaceSignature()
			if err != nil || cur == last {
				continue
			}
			last = cur
			onChange()
		}
	}
}

// interfaceSignature 返回所有接口地址的稳定字符串表示。
func interfaceSignature() (string, error) {
	addrs, err := stdnet.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "|"), nil
}

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

// sendErr 非阻塞地发送错误：调用方不再接收时直接放弃，避免协程泄漏。
func sendErr(ctx context.Context, ch chan<- error, err error) {
	if ch == nil {
		return
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
