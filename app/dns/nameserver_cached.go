package dns

import (
	"context"
	go_errors "errors"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/features/dns"
)

const (
	// 单次上游查询(含 singleflight 共享)的最长时间
	defaultFetchTimeout = 8 * time.Second
	// 部分成功 / 过期边界情况下返回给调用方的 TTL
	shortTTL uint32 = 1
)

type CachedNameserver interface {
	getCacheController() *CacheController

	sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns.IPOption)
}

// queryIP is called from dns.Server->queryIPTimeout
func queryIP(ctx context.Context, s CachedNameserver, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	cache := s.getCacheController()
	if !cache.disableCache {
		// rec 是不可变快照,锁外读取安全
		if rec := cache.findRecords(fqdn); rec != nil {
			ips, ttl, err := merge(option, rec.A, rec.AAAA)
			if !go_errors.Is(err, errRecordNotFound) {
				if ttl > 0 {
					errors.LogDebugInner(ctx, err, cache.name, " cache HIT ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
					return ips, uint32(ttl), err
				}
				if cache.serveStale && (cache.serveExpiredTTL == 0 || cache.serveExpiredTTL < ttl) {
					errors.LogDebugInner(ctx, err, cache.name, " cache OPTIMISTE ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheOptimiste, Elapsed: 0, Error: err})
					refreshAsync(ctx, s, fqdn, option)
					return ips, shortTTL, err
				}
			}
		}
	} else {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", fqdn, " at ", cache.name)
	}

	return fetch(ctx, s, fqdn, option)
}

// refreshAsync 在后台刷新 stale 记录。同一 key 同时只会有一个刷新任务,
// 避免上游持续失败时每次命中都新建 goroutine。
func refreshAsync(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) {
	cache := s.getCacheController()
	key := flightKey(fqdn, option)
	if !cache.beginRefresh(key) {
		return
	}
	go func() {
		defer cache.endRefresh(key)
		pull(ctx, s, fqdn, option)
	}()
}

func pull(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) {
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultFetchTimeout)
	defer cancel()

	fetch(nctx, s, fqdn, option)
}

func flightKey(fqdn string, option dns.IPOption) string {
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		return fqdn + "46"
	case option.IPv4Enable:
		return fqdn + "4"
	case option.IPv6Enable:
		return fqdn + "6"
	}
	return fqdn
}

// fetch 用 singleflight 合并相同请求。
//
// 实际的上游查询运行在"脱离调用者取消信号"的独立 ctx 中(保留 Value 和 deadline 上限),
// 因此首个调用者取消不会连累其他共享者;每个调用者仍只等待自己的 ctx。
func fetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) ([]net.IP, uint32, error) {
	key := flightKey(fqdn, option)

	ch := s.getCacheController().requestGroup.DoChan(key, func() (v any, err error) {
		defer func() {
			if r := recover(); r != nil {
				v, err = nil, errors.New("panic in dns fetch for ", fqdn, ": ", r)
			}
		}()

		timeout := defaultFetchTimeout
		if d, ok := ctx.Deadline(); ok {
			if remaining := time.Until(d); remaining < timeout {
				timeout = remaining
			}
		}
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()

		return doFetch(fctx, s, fqdn, option), nil
	})

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, 0, res.Err
		}
		r, ok := res.Val.(result)
		if !ok {
			return nil, 0, errors.New("unexpected fetch result type for ", fqdn)
		}
		return r.ips, r.ttl, r.error
	}
}

type result struct {
	ips []net.IP
	ttl uint32
	error
}

func doFetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) result {
	cache := s.getCacheController()

	// 必须先订阅、后发请求,否则应答可能在订阅前就已发布
	sub4, sub6 := cache.registerSubscribers(fqdn, option)
	defer closeSubscribers(sub4, sub6)

	// 容量 2:每个地址族最多回报一个错误,sendQuery 不会阻塞
	noResponseErrCh := make(chan error, 2)

	start := time.Now()
	s.sendQuery(ctx, noResponseErrCh, fqdn, option)

	rec4, rec6, errs := waitResponses(ctx, sub4, sub6, noResponseErrCh)
	res := mergeResponse(option, rec4, rec6, errs)

	log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: res.ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: res.error})
	return res
}

// waitResponses 在一个 select 循环里同时等待两个地址族的应答和错误。
//
// 错误 channel 由两族共享且不带族标识,因此这里不做归属,
// 只把"应答"或"错误"都算作一个已完成的结果,全部完成就返回。
// 这样不会出现:错误被另一族的等待逻辑抢走,导致该族一直等到 ctx 超时。
func waitResponses(ctx context.Context, sub4, sub6 *pubsub.Subscriber, errCh <-chan error) (rec4, rec6 *IPRecord, errs []error) {
	var ch4, ch6 <-chan interface{}
	pending := 0
	if sub4 != nil {
		ch4 = sub4.Wait()
		pending++
	}
	if sub6 != nil {
		ch6 = sub6.Wait()
		pending++
	}

	for pending > 0 {
		select {
		case msg := <-ch4:
			ch4 = nil // nil channel 在 select 中永远阻塞
			pending--
			if r, ok := msg.(*IPRecord); ok {
				rec4 = r
			} else {
				errs = append(errs, go_errors.New("unexpected message type on ipv4 subscription"))
			}

		case msg := <-ch6:
			ch6 = nil
			pending--
			if r, ok := msg.(*IPRecord); ok {
				rec6 = r
			} else {
				errs = append(errs, go_errors.New("unexpected message type on ipv6 subscription"))
			}

		case err := <-errCh:
			pending--
			if err != nil {
				errs = append(errs, err)
			}

		case <-ctx.Done():
			// select 随机选择:取消的同时可能已有应答到达,先取尽再放弃
			if r, ok := recvRecord(ch4); ok {
				rec4, ch4 = r, nil
				pending--
			}
			if r, ok := recvRecord(ch6); ok {
				rec6, ch6 = r, nil
				pending--
			}
		drain:
			for pending > 0 {
				select {
				case err := <-errCh:
					pending--
					if err != nil {
						errs = append(errs, err)
					}
				default:
					break drain
				}
			}
			if pending > 0 {
				errs = append(errs, ctx.Err())
			}
			return
		}
	}
	return
}

// recvRecord 非阻塞接收;ch 为 nil 时直接返回 false。
func recvRecord(ch <-chan interface{}) (*IPRecord, bool) {
	select {
	case msg := <-ch:
		r, ok := msg.(*IPRecord)
		return r, ok
	default:
		return nil, false
	}
}

// mergeResponse 合并一次真实上游查询的结果(区别于 merge:merge 用于读缓存,
// 缓存只有一半有效就必须视为 miss;这里则允许部分成功,并保留传输层错误)。
//
//   - 任一族有 IP          → 成功;若有族没拿到应答,则 TTL 缩短为 shortTTL
//   - 都没有 IP,有应答     → 返回合并后的 RCode / 空应答错误
//   - 一个应答都没有       → 返回传输层错误(超时、取消等),TTL=0
func mergeResponse(option dns.IPOption, rec4, rec6 *IPRecord, errs []error) result {
	var (
		allIPs   []net.IP
		minTTL   int32 = dns.DefaultTTL
		answered int // 拿到有效应答的地址族数量
		missing  int // 启用了但没拿到应答的地址族数量
		failures []error
	)

	for _, p := range [...]struct {
		enabled bool
		rec     *IPRecord
	}{
		{option.IPv4Enable, rec4},
		{option.IPv6Enable, rec6},
	} {
		if !p.enabled {
			continue
		}
		ips, ttl, err := p.rec.getIPs() // nil 安全,返回 errRecordNotFound
		if go_errors.Is(err, errRecordNotFound) {
			missing++
			continue
		}
		answered++
		if ttl < minTTL {
			minTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else if err != nil {
			failures = append(failures, err)
		}
	}

	// 传输层错误排在应答错误之后
	failures = append(failures, errs...)

	switch {
	case len(allIPs) > 0:
		// edge case: 快的应答 TTL 在等待慢的应答期间过期 → 1
		ttl := shortTTL
		if minTTL > 0 && missing == 0 {
			ttl = uint32(minTTL)
		}
		return result{allIPs, ttl, nil}

	case answered == 0:
		if err := combineErrors(failures); err != nil {
			return result{nil, 0, err}
		}
		return result{nil, 0, errRecordNotFound}

	default:
		// 有应答但没有 IP(RCode 错误 / 空应答)
		var ttl uint32
		if missing == 0 { // 另一族没拿到应答时不宜把整体当作负缓存
			ttl = shortTTL
			if minTTL > 0 {
				ttl = uint32(minTTL)
			}
		}
		return result{nil, ttl, combineErrors(failures)}
	}
}

// combineErrors 去重后合并;只有一个错误时原样返回,
// 以便调用方继续用 errors.Is / == 判断 ErrEmptyResponse、RCodeError 等。
func combineErrors(errs []error) error {
	uniq := make([]error, 0, len(errs))
outer:
	for _, e := range errs {
		if e == nil {
			continue
		}
		for _, u := range uniq {
			if go_errors.Is(e, u) {
				continue outer
			}
		}
		uniq = append(uniq, e)
	}

	switch len(uniq) {
	case 0:
		return nil
	case 1:
		return uniq[0]
	}
	return errors.Combine(uniq...)
}

// merge 用于读缓存:双族请求时,任一族缺失(errRecordNotFound)即视为整体 miss。
func merge(option dns.IPOption, rec4 *IPRecord, rec6 *IPRecord, errs ...error) ([]net.IP, int32, error) {
	var allIPs []net.IP
	var rTTL int32 = dns.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable {
		ips, ttl, err := rec4.getIPs() // it's safe
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if option.IPv6Enable {
		ips, ttl, err := rec6.getIPs() // it's safe
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if len(allIPs) > 0 {
		return allIPs, rTTL, nil
	}
	if len(errs) == 2 && go_errors.Is(errs[0], errs[1]) {
		return nil, rTTL, errs[0]
	}
	return nil, rTTL, errors.Combine(errs...)
}
