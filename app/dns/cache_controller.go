package dns

import (
	"context"
	go_errors "errors"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	minSizeForEmptyRebuild  = 512
	shrinkAbsoluteThreshold = 10240
	shrinkRatioThreshold    = 0.65
	migrationBatchSize      = 4096
)

// errNothingToDo 让 task.Periodic 在缓存为空时自动停止,
// 下一次 updateRecord 会重新拉起。
var errNothingToDo = go_errors.New("nothing to do. stopping...")

// CacheController 约定:
//   - *record 与 *IPRecord 一旦放入 map(或被 findRecords 返回)就视为不可变;
//   - 任何修改都必须新建 record 再替换 map 中的指针(copy-on-write)。
//
// 这样 findRecords 返回的指针在释放锁之后仍可被无锁读取。
type CacheController struct {
	name            string
	disableCache    bool
	serveStale      bool
	serveExpiredTTL int32 // 存为负数

	mu            sync.RWMutex
	ips           map[string]*record
	dirtyips      map[string]*record // 缩容迁移期间的旧 map(只读)
	highWatermark int

	pub          *pubsub.Service
	cacheCleanup *task.Periodic
	requestGroup singleflight.Group

	// 正在进行的 stale 后台刷新,key 与 singleflight 的 key 相同
	refreshing sync.Map
}

func NewCacheController(name string, disableCache bool, serveStale bool, serveExpiredTTL uint32) *CacheController {
	// 防止 uint32 -> int32 溢出
	if serveExpiredTTL > math.MaxInt32 {
		serveExpiredTTL = math.MaxInt32
	}

	c := &CacheController{
		name:            name,
		disableCache:    disableCache,
		serveStale:      serveStale,
		serveExpiredTTL: -int32(serveExpiredTTL),
		ips:             make(map[string]*record),
		pub:             pubsub.NewService(),
	}

	c.cacheCleanup = &task.Periodic{
		Interval: 300 * time.Second,
		Execute:  c.CacheCleanup,
	}
	return c
}

// expireCutoff 返回清理时使用的"当前时间"。
// 开启 serve-stale 且有限期时,把时间往前拨,让过期记录多保留 serveExpiredTTL 秒。
func (c *CacheController) expireCutoff() time.Time {
	now := time.Now()
	if c.serveStale && c.serveExpiredTTL != 0 {
		now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
	}
	return now
}

func isExpired(r *IPRecord, cutoff time.Time) bool {
	return r != nil && r.Expire.Before(cutoff)
}

// recordOf 取出 record 中指定类型的 IPRecord,r 为 nil 时安全返回 nil。
func recordOf(r *record, t dnsmessage.Type) *IPRecord {
	if r == nil {
		return nil
	}
	switch t {
	case dnsmessage.TypeA:
		return r.A
	case dnsmessage.TypeAAAA:
		return r.AAAA
	}
	return nil
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
	expiredKeys, err := c.collectExpiredKeys()
	if err != nil {
		return err
	}
	if len(expiredKeys) == 0 {
		return nil
	}
	c.writeAndShrink(expiredKeys)
	return nil
}

func (c *CacheController) collectExpiredKeys() ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 迁移期间 ips 只是半成品,先判断迁移再判断空,避免误停定时器
	if c.dirtyips != nil {
		return nil, nil
	}

	if len(c.ips) == 0 {
		return nil, errNothingToDo
	}

	cutoff := c.expireCutoff()
	expiredKeys := make([]string, 0, len(c.ips)/4)

	for domain, rec := range c.ips {
		if isExpired(rec.A, cutoff) || isExpired(rec.AAAA, cutoff) {
			expiredKeys = append(expiredKeys, domain)
		}
	}

	return expiredKeys, nil
}

func (c *CacheController) writeAndShrink(expiredKeys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// double check:迁移已开始则放弃
	if c.dirtyips != nil {
		return
	}

	lenBefore := len(c.ips)
	if lenBefore > c.highWatermark {
		c.highWatermark = lenBefore
	}

	// 写锁内重新取时间,避免误删刚被刷新的记录
	cutoff := c.expireCutoff()

	for _, domain := range expiredKeys {
		rec := c.ips[domain]
		if rec == nil {
			continue
		}

		expA := isExpired(rec.A, cutoff)
		expAAAA := isExpired(rec.AAAA, cutoff)
		if !expA && !expAAAA {
			continue // 已被刷新
		}

		// copy-on-write:绝不原地修改已发布的 record
		nr := &record{A: rec.A, AAAA: rec.AAAA}
		if expA {
			nr.A = nil
		}
		if expAAAA {
			nr.AAAA = nil
		}

		if nr.A == nil && nr.AAAA == nil {
			delete(c.ips, domain)
		} else {
			c.ips[domain] = nr
		}
	}

	lenAfter := len(c.ips)

	if lenAfter == 0 {
		if c.highWatermark >= minSizeForEmptyRebuild {
			errors.LogDebug(
				context.Background(), c.name,
				" rebuilding empty cache map to reclaim memory.",
				" size_before_cleanup=", lenBefore,
				" peak_size_before_rebuild=", c.highWatermark,
			)

			c.ips = make(map[string]*record)
			c.highWatermark = 0
		}
		return
	}

	if reductionFromPeak := c.highWatermark - lenAfter; reductionFromPeak > shrinkAbsoluteThreshold &&
		float64(reductionFromPeak) > float64(c.highWatermark)*shrinkRatioThreshold {
		errors.LogDebug(
			context.Background(), c.name,
			" shrinking cache map to reclaim memory.",
			" new_size=", lenAfter,
			" peak_size_before_shrink=", c.highWatermark,
			" reduction_since_peak=", reductionFromPeak,
		)

		dirty := c.ips
		c.dirtyips = dirty
		c.ips = make(map[string]*record, int(float64(lenAfter)*1.1))
		c.highWatermark = lenAfter
		go c.migrate(dirty)
	}
}

type migrationEntry struct {
	key   string
	value *record
}

// migrate 在后台把 dirty(旧 map)分批搬进 c.ips。
// dirty 在迁移期间只读(清理被禁止、updateRecord 只读它),可无锁遍历。
func (c *CacheController) migrate(dirty map[string]*record) {
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), c.name, " panic during cache migration: ", r)
			c.mu.Lock()
			c.dirtyips = nil // 放弃剩余未迁移的条目,只损失部分缓存
			c.mu.Unlock()
		}
	}()

	if dirty == nil {
		return
	}

	errors.LogDebug(context.Background(), c.name, " starting background cache migration for ", len(dirty), " items")

	batch := make([]migrationEntry, 0, migrationBatchSize)
	for domain, rec := range dirty {
		batch = append(batch, migrationEntry{domain, rec})

		if len(batch) >= migrationBatchSize {
			c.flush(batch)
			batch = batch[:0]
			runtime.Gosched()
		}
	}
	if len(batch) > 0 {
		c.flush(batch)
	}

	c.mu.Lock()
	c.dirtyips = nil
	c.mu.Unlock()

	errors.LogDebug(context.Background(), c.name, " cache migration completed")
}

// flush 合并规则:新 map 中已有的值优先,缺失的类型用旧值补齐。
func (c *CacheController) flush(batch []migrationEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, dirty := range batch {
		cur := c.ips[dirty.key]
		if cur == nil {
			c.ips[dirty.key] = dirty.value
			continue
		}
		if cur.A != nil && cur.AAAA != nil {
			continue // 新值已完整
		}

		merged := &record{A: cur.A, AAAA: cur.AAAA}
		if merged.A == nil {
			merged.A = dirty.value.A
		}
		if merged.AAAA == nil {
			merged.AAAA = dirty.value.AAAA
		}
		c.ips[dirty.key] = merged
	}
}

func (c *CacheController) updateRecord(req *dnsRequest, rep *IPRecord) {
	rtt := time.Since(req.start)

	var selfSuffix, otherSuffix string
	var otherType dnsmessage.Type
	switch req.reqType {
	case dnsmessage.TypeA:
		selfSuffix, otherSuffix, otherType = "4", "6", dnsmessage.TypeAAAA
	case dnsmessage.TypeAAAA:
		selfSuffix, otherSuffix, otherType = "6", "4", dnsmessage.TypeA
	default:
		errors.LogWarning(context.Background(), c.name, " ignore answer with unsupported type: ", req.domain, " ", req.reqType)
		return
	}

	// 先广播本类型的结果,再落缓存
	c.pub.Publish(req.domain+selfSuffix, rep)

	if c.disableCache {
		errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt)
		return
	}

	c.mu.Lock()
	lockWait := time.Since(req.start) - rtt

	oldRec := c.ips[req.domain]
	var dirtyRec *record
	if c.dirtyips != nil {
		dirtyRec = c.dirtyips[req.domain]
	}

	// 另一类型:优先继承新 map 中的;迁移期间旧 map 中的只用于发布,
	// 不写入 newRec,稍后 flush 会负责合并。
	other := recordOf(oldRec, otherType)
	pubRecord := other
	if pubRecord == nil {
		pubRecord = recordOf(dirtyRec, otherType)
	}

	newRec := &record{}
	if req.reqType == dnsmessage.TypeA {
		newRec.A = rep
		newRec.AAAA = other
	} else {
		newRec.AAAA = rep
		newRec.A = other
	}

	c.ips[req.domain] = newRec
	if n := len(c.ips); n > c.highWatermark {
		c.highWatermark = n
	}
	c.mu.Unlock()

	// 另一类型的旧缓存仍有效,则顺便发布给正在等待它的订阅者
	if pubRecord != nil {
		_, ttl, err := pubRecord.getIPs()
		if ttl > 0 && !go_errors.Is(err, errRecordNotFound) {
			c.pub.Publish(req.domain+otherSuffix, pubRecord)
		}
	}

	errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt, ", lock: ", lockWait)

	if !c.serveStale || c.serveExpiredTTL != 0 {
		if err := c.cacheCleanup.Start(); err != nil {
			errors.LogDebugInner(context.Background(), err, c.name, " failed to start cache cleanup")
		}
	}
}

// findRecords 返回域名对应的记录快照。
// 返回的 record 不可变,调用方可在锁外安全读取。
// 迁移期间会合并 ips 与 dirtyips,避免只命中一半。
func (c *CacheController) findRecords(domain string) *record {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rec := c.ips[domain]
	if c.dirtyips == nil {
		return rec
	}

	dirty := c.dirtyips[domain]
	switch {
	case dirty == nil:
		return rec
	case rec == nil:
		return dirty
	case rec.A != nil && rec.AAAA != nil:
		return rec
	}

	merged := &record{A: rec.A, AAAA: rec.AAAA}
	if merged.A == nil {
		merged.A = dirty.A
	}
	if merged.AAAA == nil {
		merged.AAAA = dirty.AAAA
	}
	return merged
}

// beginRefresh 尝试登记一个后台刷新;已有同 key 刷新在进行时返回 false。
func (c *CacheController) beginRefresh(key string) bool {
	_, loaded := c.refreshing.LoadOrStore(key, struct{}{})
	return !loaded
}

func (c *CacheController) endRefresh(key string) {
	c.refreshing.Delete(key)
}

func (c *CacheController) registerSubscribers(domain string, option dns_feature.IPOption) (sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	// ipv4 and ipv6 belong to different subscription groups
	if option.IPv4Enable {
		sub4 = c.pub.Subscribe(domain + "4")
	}
	if option.IPv6Enable {
		sub6 = c.pub.Subscribe(domain + "6")
	}
	return
}

func closeSubscribers(sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	if sub4 != nil {
		sub4.Close()
	}
	if sub6 != nil {
		sub6.Close()
	}
}
