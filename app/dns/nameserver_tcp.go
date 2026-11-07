package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	// 上层 ctx 没有 deadline 时的默认超时
	tcpDefaultTimeout = 5 * time.Second
	// 单个 tcpExchanger 同时进行的 TCP 查询数上限（每个对应一条连接）
	tcpMaxConcurrent = 128
	// DNS 报文头固定 12 字节，小于该值一定不是合法报文
	dnsHeaderSize = 12
)

// reportErr 非阻塞地上报错误，ch 为 nil 或已满时直接丢弃。
// 后台 goroutine 必须用它，避免消费方提前返回后永久阻塞。
// 每个请求最多上报一次，而 queryIP 的通道有缓冲，因此不会丢失有效错误。
func reportErr(ch chan<- error, err error) {
	if ch == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}

// ---------------------------------------------------------------------------
// tcpExchanger：与 nameserver 无关的"单次 TCP 查询"能力，带并发上限。
// TCPNameServer 使用它，UDP 收到 TC 位时也用它做回退。
// ---------------------------------------------------------------------------

type tcpExchanger struct {
	destination net.Destination
	dial        func(context.Context) (net.Conn, error)
	sem         chan struct{}
}

func newTCPExchanger(dest net.Destination, dial func(context.Context) (net.Conn, error)) *tcpExchanger {
	return &tcpExchanger{
		destination: dest,
		dial:        dial,
		sem:         make(chan struct{}, tcpMaxConcurrent),
	}
}

// dnsLinkCloser 把函数适配成 io.Closer，用于连接关闭时释放 dispatcher 的 link。
type dnsLinkCloser func() error

func (f dnsLinkCloser) Close() error { return f() }

// dispatcherDial 经由 Xray 路由/出站拨号。
// 返回的连接在 Close 时会中断 link 的读端并关闭写端，保证底层 pipe 与出站 goroutine 被回收。
func dispatcherDial(dispatcher routing.Dispatcher, dest net.Destination) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		link, err := dispatcher.Dispatch(toDnsContext(ctx, dest.String()), dest)
		if err != nil {
			return nil, err
		}
		release := func() error {
			_ = common.Interrupt(link.Reader)
			_ = common.Close(link.Writer)
			return nil
		}
		// 拨号返回后若 ctx 已结束，立即释放，避免泄漏
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = release()
			return nil, ctxErr
		}
		return cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
			cnc.ConnectionOnClose(dnsLinkCloser(release)),
		), nil
	}
}

// localDial 使用系统网络直连（对应本地 TCPL / UDPL 的回退）。
func localDial(dest net.Destination) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return internet.DialSystem(ctx, dest, nil)
	}
}

// exchange 发送一个查询并返回完整的原始响应报文（不含长度前缀）。
// 返回前已校验：长度合法、QR 位为响应、ID 与 Question 与请求一致。
//
// 资源释放顺序（defer，后进先出）：停止 AfterFunc → 关闭连接 → cancel ctx → 释放信号量。
func (e *tcpExchanger) exchange(ctx context.Context, msg *dnsmessage.Message) ([]byte, error) {
	// 总是派生可取消的 ctx：返回时 cancel，保证 dispatcher 的 link 不依赖父 ctx 的生命周期
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); ok {
		ctx, cancel = context.WithCancel(ctx)
	} else {
		ctx, cancel = context.WithTimeout(ctx, tcpDefaultTimeout)
	}
	defer cancel()

	// 并发上限：等待受 ctx 约束，不会无限排队
	if err := ctx.Err(); err != nil {
		return nil, errors.New("query aborted").Base(err)
	}
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return nil, errors.New("too many concurrent TCP DNS queries to ", e.destination.NetAddr()).Base(ctx.Err())
	}

	// 构造 [2 字节长度][报文]，一次 Write 发出
	packed, err := dns.PackMessage(msg)
	if err != nil {
		return nil, errors.New("failed to pack dns query").Base(err)
	}
	frame := make([]byte, 2+int(packed.Len()))
	binary.BigEndian.PutUint16(frame, uint16(packed.Len()))
	copy(frame[2:], packed.Bytes())
	packed.Release()

	conn, err := e.dial(ctx)
	if err != nil {
		return nil, errors.New("failed to dial nameserver ", e.destination.NetAddr()).Base(err)
	}
	defer conn.Close()

	// 双保险：尽力设置 deadline，同时 ctx 结束时强制关闭连接，
	// 因为部分连接实现（如 cnc）的 deadline 并不可靠。
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := conn.Write(frame); err != nil {
		return nil, ctxOr(ctx, errors.New("failed to send query").Base(err))
	}

	var lengthBytes [2]byte
	if _, err := io.ReadFull(conn, lengthBytes[:]); err != nil {
		return nil, ctxOr(ctx, errors.New("failed to read response length").Base(err))
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length < dnsHeaderSize {
		return nil, errors.New("invalid response length: ", length)
	}

	// 按实际长度分配（≤ 65535），支持 UDP 被截断的大响应
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, ctxOr(ctx, errors.New("failed to read response body").Base(err))
	}

	hdr, q, err := parseHeaderAndQuestion(payload)
	if err != nil {
		return nil, errors.New("malformed response").Base(err)
	}
	if !hdr.Response {
		return nil, errors.New("received a query instead of a response")
	}
	if hdr.ID != msg.ID || !questionMatches(msg, q) {
		return nil, errors.New("response does not match the query")
	}
	return payload, nil
}

// ctxOr：ctx 已结束时，把"use of closed connection"之类的噪声错误替换为 ctx 的错误。
func ctxOr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.New("query aborted").Base(ctxErr)
	}
	return err
}

// ---------------------------------------------------------------------------
// TCPNameServer
// ---------------------------------------------------------------------------

// TCPNameServer implemented DNS over TCP (RFC7766).
// 没有后台 goroutine 或定时器，不需要 Close。
type TCPNameServer struct {
	cacheController *CacheController
	exchanger       *tcpExchanger
	reqID           uint32
	clientIP        net.IP
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
	dispatcher routing.Dispatcher,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	clientIP net.IP,
) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCP", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}
	s.exchanger.dial = dispatcherDial(dispatcher, s.exchanger.destination)

	errors.LogInfo(context.Background(), "DNS: created TCP client initialized for ", url.String())
	return s, nil
}

// NewTCPLocalNameServer creates DNS over TCP client object for local resolving
func NewTCPLocalNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCPL", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}
	s.exchanger.dial = localDial(s.exchanger.destination)

	errors.LogInfo(context.Background(), "DNS: created Local TCP client initialized for ", url.String())
	return s, nil
}

func baseTCPNameServer(url *url.URL, prefix string, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	dest := net.TCPDestination(net.ParseAddress(url.Hostname()), port)

	return &TCPNameServer{
		cacheController: NewCacheController(prefix+"//"+dest.NetAddr(), disableCache, serveStale, serveExpiredTTL),
		exchanger:       newTCPExchanger(dest, nil), // dial 由调用方设置
		clientIP:        clientIP,
	}, nil
}

// Name implements Server.
func (s *TCPNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *TCPNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

// getCacheController implements CachedNameserver.
func (s *TCPNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *TCPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		// 与原行为一致：每个启用的地址族各上报一次
		if option.IPv4Enable {
			reportErr(noResponseErrCh, err)
		}
		if option.IPv6Enable {
			reportErr(noResponseErrCh, err)
		}
		return
	}

	// A、AAAA 共享同一个截止时间
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(tcpDefaultTimeout)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			dnsCtx := session.ContextWithContent(ctx, &session.Content{
				Protocol:       "dns",
				SkipDNSResolve: true,
			})
			dnsCtx, cancel := context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			payload, err := s.exchanger.exchange(dnsCtx, r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "DNS over TCP query failed for ", fqdn)
				reportErr(noResponseErrCh, err)
				return
			}

			rec, err := parseResponse(payload)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse DNS over TCP response")
				reportErr(noResponseErrCh, err)
				return
			}

			s.cacheController.updateRecord(r, rec)
		}(req)
	}
}

// QueryIP implements Server.
func (s *TCPNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
