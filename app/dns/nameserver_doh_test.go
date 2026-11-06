package dns_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/app/dns"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// ---------------------------------------------------------------------------
// 假 DoH 服务器（明文 HTTP/2，配合 h2c=true 使用，不需要证书）
// ---------------------------------------------------------------------------

type fakeMode int

const (
	modeOK fakeMode = iota
	modeHTTPError
	modeOversize
	modeBadContentType
	modeGarbageBody
)

type fakeDoH struct {
	mode fakeMode
	ttl  uint32
	v4   netip.Addr
	v6   netip.Addr

	mu        sync.Mutex
	hits      int
	questions []dnsmessage.Type
}

func newFakeDoH() *fakeDoH {
	return &fakeDoH{
		ttl: 300,
		v4:  netip.MustParseAddr("1.2.3.4"),
		v6:  netip.MustParseAddr("2001:db8::1"),
	}
}

// snapshot 返回请求次数与收到的查询类型副本。
func (f *fakeDoH) snapshot() (int, []dnsmessage.Type) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits, append([]dnsmessage.Type(nil), f.questions...)
}

func (f *fakeDoH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()

	switch f.mode {
	case modeHTTPError:
		w.WriteHeader(http.StatusInternalServerError)
		return
	case modeOversize:
		// 超过客户端上限（65535）的响应体
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(make([]byte, 70000))
		return
	case modeBadContentType:
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
		return
	case modeGarbageBody:
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0x01, 0x02, 0x03})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65535))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req dnsmessage.Message
	if err := req.Unpack(body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	for _, q := range req.Questions {
		f.questions = append(f.questions, q.Type)
	}
	f.mu.Unlock()

	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: req.ID, Response: true, RecursionAvailable: true},
		Questions: req.Questions,
	}
	for _, q := range req.Questions {
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: f.ttl}
		switch {
		case q.Type == dnsmessage.TypeA && f.v4.IsValid():
			hdr.Type = dnsmessage.TypeA
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: hdr,
				Body:   &dnsmessage.AResource{A: f.v4.As4()},
			})
		case q.Type == dnsmessage.TypeAAAA && f.v6.IsValid():
			hdr.Type = dnsmessage.TypeAAAA
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: hdr,
				Body:   &dnsmessage.AAAAResource{AAAA: f.v6.As16()},
			})
		}
	}

	packed, err := resp.Pack()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(packed)
}

// ---------------------------------------------------------------------------
// 测试辅助函数
// ---------------------------------------------------------------------------

// newTestServer 启动假服务器并构造 DoH 客户端（h2c 模式，明文）。
func newTestServer(t *testing.T, f *fakeDoH, disableCache bool) *DoHNameServer {
	t.Helper()
	srv := httptest.NewServer(h2c.NewHandler(f, &http2.Server{}))
	t.Cleanup(srv.Close)

	u := mustParseURL(t, srv.URL+"/dns-query")
	s := NewDoHNameServer(u, nil, true, disableCache, false, 0, nil)
	// t.Cleanup 为后进先出：先关闭客户端连接，再关闭服务端，避免 srv.Close 阻塞
	t.Cleanup(func() { closeIfCloser(s) })
	return s
}

// lookup 执行查询并把结果转换为已 Unmap 的 netip.Addr。
func lookup(t *testing.T, s *DoHNameServer, domain string, v4, v6 bool) []netip.Addr {
	t.Helper()
	ips, _, err := s.QueryIP(queryCtx(t), domain, dns_feature.IPOption{
		IPv4Enable: v4,
		IPv6Enable: v6,
	})
	if err != nil {
		t.Fatalf("QueryIP(%q) error: %v", domain, err)
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice([]byte(ip))
		if !ok {
			t.Fatalf("invalid IP length %d", len(ip))
		}
		addrs = append(addrs, a.Unmap())
	}
	return addrs
}

// addrStrings 转换为排序后的字符串，便于与期望值比较（结果顺序不保证）。
func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out
}

func queryCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func closeIfCloser(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}

func skipUnlessLive(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping live DoH test in -short mode")
	}
	if os.Getenv("XRAY_LIVE_DNS") == "" {
		t.Skip("set XRAY_LIVE_DNS=1 to run live DoH tests")
	}
}

// ---------------------------------------------------------------------------
// 离线测试（hermetic）：默认运行，结果可复现
// ---------------------------------------------------------------------------

func TestDoHResolveIPv4AndIPv6(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, newFakeDoH(), false)

	got := lookup(t, s, "example.test", true, true)
	want := []string{"1.2.3.4", "2001:db8::1"}
	if diff := cmp.Diff(want, addrStrings(got)); diff != "" {
		t.Fatalf("unexpected result (-want +got):\n%s", diff)
	}
}

func TestDoHIPv4OnlyQueriesOnlyA(t *testing.T) {
	t.Parallel()
	f := newFakeDoH()
	s := newTestServer(t, f, false)

	got := lookup(t, s, "example.test", true, false)
	if diff := cmp.Diff([]string{"1.2.3.4"}, addrStrings(got)); diff != "" {
		t.Fatalf("unexpected result (-want +got):\n%s", diff)
	}

	_, types := f.snapshot()
	if len(types) == 0 {
		t.Fatal("server received no queries")
	}
	for _, typ := range types {
		if typ != dnsmessage.TypeA {
			t.Errorf("IPv4-only query sent unexpected type %v", typ)
		}
	}
}

func TestDoHIPv6OnlyQueriesOnlyAAAA(t *testing.T) {
	t.Parallel()
	f := newFakeDoH()
	s := newTestServer(t, f, false)

	got := lookup(t, s, "example.test", false, true)
	if diff := cmp.Diff([]string{"2001:db8::1"}, addrStrings(got)); diff != "" {
		t.Fatalf("unexpected result (-want +got):\n%s", diff)
	}

	_, types := f.snapshot()
	if len(types) == 0 {
		t.Fatal("server received no queries")
	}
	for _, typ := range types {
		if typ != dnsmessage.TypeAAAA {
			t.Errorf("IPv6-only query sent unexpected type %v", typ)
		}
	}
}

func TestDoHCacheHit(t *testing.T) {
	t.Parallel()
	f := newFakeDoH()
	s := newTestServer(t, f, false)

	first := lookup(t, s, "example.test", true, false)
	second := lookup(t, s, "example.test", true, false)

	// 第二次应命中缓存，服务器只收到一次请求
	if hits, _ := f.snapshot(); hits != 1 {
		t.Errorf("expected 1 request to server with cache enabled, got %d", hits)
	}
	if diff := cmp.Diff(addrStrings(first), addrStrings(second)); diff != "" {
		t.Fatalf("cached result differs (-first +second):\n%s", diff)
	}
}

func TestDoHCacheDisabled(t *testing.T) {
	t.Parallel()
	f := newFakeDoH()
	s := newTestServer(t, f, true)

	lookup(t, s, "example.test", true, false)
	lookup(t, s, "example.test", true, false)

	if hits, _ := f.snapshot(); hits != 2 {
		t.Errorf("expected 2 requests with cache disabled, got %d", hits)
	}
}

func TestDoHErrorResponses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mode fakeMode
	}{
		{"http 500", modeHTTPError},
		{"oversized body", modeOversize},
		{"wrong content-type", modeBadContentType},
		{"garbage body", modeGarbageBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeDoH()
			f.mode = tc.mode
			s := newTestServer(t, f, true)

			_, _, err := s.QueryIP(queryCtx(t), "example.test", dns_feature.IPOption{IPv4Enable: true})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestDoHCanceledContext(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, newFakeDoH(), true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := s.QueryIP(ctx, "example.test", dns_feature.IPOption{IPv4Enable: true})
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}

func TestDoHConcurrentQueries(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, newFakeDoH(), false)

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := s.QueryIP(ctx, "example.test", dns_feature.IPOption{IPv4Enable: true, IPv6Enable: true})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent query failed: %v", err)
	}
}

// TestDoHSelfQueryRejected 检测 DoH 服务器自身域名的解析被拒绝（DOH 与 DOHL 模式均适用）。
// 原实现仅在 DOH 模式下有效，此用例可作为回归测试。
func TestDoHSelfQueryRejected(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"dns.example", "DNS.example.", "Dns.Example"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			u := mustParseURL(t, "https://dns.example/dns-query")
			// dispatcher 为 nil，即 DOHL 模式；h2c=true 保证不会发生真实网络访问
			s := NewDoHNameServer(u, nil, true, false, false, 0, nil)
			t.Cleanup(func() { closeIfCloser(s) })

			_, _, err := s.QueryIP(queryCtx(t), name, dns_feature.IPOption{IPv4Enable: true})
			if err == nil {
				t.Fatalf("self query %q was not rejected", name)
			}
		})
	}
}

// TestDoHConstructorDoesNotMutateURL 构造函数不应修改调用方传入的 URL。
func TestDoHConstructorDoesNotMutateURL(t *testing.T) {
	t.Parallel()
	u := mustParseURL(t, "https+local://dns.example/dns-query")
	s := NewDoHNameServer(u, nil, false, false, false, 0, nil)
	t.Cleanup(func() { closeIfCloser(s) })

	if u.Scheme != "https+local" {
		t.Errorf("constructor mutated caller's URL scheme: got %q", u.Scheme)
	}
}

// ---------------------------------------------------------------------------
// 在线测试（live）：访问公网，默认跳过
// 运行方式：XRAY_LIVE_DNS=1 go test -run DoHLive -v ./app/dns/
// ---------------------------------------------------------------------------

func TestDoHLive(t *testing.T) {
	skipUnlessLive(t)

	u := mustParseURL(t, "https+local://1.1.1.1/dns-query")
	// dispatcher 为 nil，即 DOHL 模式（直接系统拨号）
	s := NewDoHNameServer(u, nil, false, false, false, 0, nil)
	t.Cleanup(func() { closeIfCloser(s) })

	t.Run("ipv4 and ipv6", func(t *testing.T) {
		got := lookup(t, s, "google.com", true, true)
		if len(got) == 0 {
			t.Fatal("expected some IPs, got 0")
		}
	})

	t.Run("ipv4 only", func(t *testing.T) {
		got := lookup(t, s, "google.com", true, false)
		if len(got) == 0 {
			t.Fatal("expected some IPv4 addresses, got 0")
		}
		for _, a := range got {
			if !a.Is4() {
				t.Errorf("expected only IPv4 response, got %s", a)
			}
		}
	})

	t.Run("ipv6 only", func(t *testing.T) {
		got := lookup(t, s, "google.com", false, true)
		if len(got) == 0 {
			t.Skip("no AAAA records available on this network")
		}
		for _, a := range got {
			if !a.Is6() || a.Is4In6() {
				t.Errorf("expected only IPv6 response, got %s", a)
			}
		}
	})
}
