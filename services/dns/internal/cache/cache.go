package cache

import (
	"strings"
	"sync"
	"time"
)

// Record 表示用户态 DNS baseline 里缓存的结构化记录。
// 这里不直接缓存原始 DNS 报文，而是缓存足够用于回包的最小信息。
type Record struct {
	QName string
	QType string
	Value string
	TTL   time.Duration
}

// Stats 记录缓存层的运行状态和命中情况。
type Stats struct {
	Capacity  int
	Size      int
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

type entry struct {
	record     Record
	expiresAt  time.Time
	hits       uint64
	lastAccess time.Time
}

// Cache 是一个并发安全的用户态 DNS 缓存。
//
// 设计目标很简单：
//   - 先命中用户态缓存，减少重复查 Zone Store 的次数
//   - 通过 TTL 让过期记录自动失效
//   - 通过简单容量淘汰维持缓存大小
type Cache struct {
	mu       sync.RWMutex
	data     map[string]*entry
	capacity int
	now      func() time.Time
	hits     uint64
	misses   uint64
	evicted  uint64
}

// New 创建一个缓存实例。
// capacity <= 0 表示不设置硬容量上限。
func New(capacity int) *Cache {
	if capacity < 0 {
		capacity = 0
	}
	return &Cache{
		data:     make(map[string]*entry),
		capacity: capacity,
		now:      time.Now,
	}
}

// Key 将 DNS 查询规范化为缓存 key。
//
// 第一版约定：
//   - 域名统一转小写并去掉尾部的 "."
//   - 类型统一转大写
//   - key 格式为 "qname:qtype"
func Key(qname, qtype string) string {
	name := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(qname)), ".")
	typ := strings.ToUpper(strings.TrimSpace(qtype))
	return name + ":" + typ
}

// Get 返回缓存记录。
//
// 行为约定：
//   - 不存在时返回 miss
//   - 过期时先清理再返回 miss
//   - 命中时更新访问统计和最近访问时间
func (c *Cache) Get(key string) (Record, bool) {
	now := c.nowTime()

	c.mu.RLock()
	e, ok := c.data[key]
	// key 不存在，直接记 miss。
	if !ok {
		c.mu.RUnlock()
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return Record{}, false
	}
	// 记录存在但已经过期，删除后返回 miss。
	if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
		c.mu.RUnlock()
		c.mu.Lock()
		if cur, ok := c.data[key]; ok {
			if !cur.expiresAt.IsZero() && !now.Before(cur.expiresAt) {
				delete(c.data, key)
			}
		}
		c.misses++
		c.mu.Unlock()
		return Record{}, false
	}

	record := e.record
	c.mu.RUnlock()

	c.mu.Lock()
	if cur, ok := c.data[key]; ok {
		// 命中时更新该项的命中次数和最近访问时间。
		cur.hits++
		cur.lastAccess = now
		record = cur.record
		c.hits++
		c.mu.Unlock()
		return record, true
	}
	c.misses++
	c.mu.Unlock()
	return Record{}, false
}

// Set 写入或更新一条缓存记录。
func (c *Cache) Set(key string, record Record, ttl time.Duration) {
	now := c.nowTime()
	record.TTL = ttl

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.data[key]; ok {
		existing.record = record
		existing.expiresAt = expirationAt(now, ttl)
		existing.lastAccess = now
		return
	}

	// 写入新项前，先清理一轮已过期的记录，避免无效数据占用容量。
	c.evicted += uint64(c.pruneExpiredLocked(now))
	if c.capacity > 0 && len(c.data) >= c.capacity {
		// 这里不做复杂 LRU，第一版只保留“最旧/最少近期访问”的简单淘汰。
		c.evictOneLocked()
	}

	c.data[key] = &entry{
		record:     record,
		expiresAt:  expirationAt(now, ttl),
		lastAccess: now,
	}
}

// Delete 删除一条缓存记录。
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()
}

// CleanupExpired 扫描并删除所有已经过期的记录。
func (c *Cache) CleanupExpired() int {
	now := c.nowTime()

	c.mu.Lock()
	defer c.mu.Unlock()

	removed := c.pruneExpiredLocked(now)
	c.evicted += uint64(removed)
	return removed
}

// Stats 返回当前缓存的统计快照。
func (c *Cache) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Stats{
		Capacity:  c.capacity,
		Size:      len(c.data),
		Hits:      c.hits,
		Misses:    c.misses,
		Evictions: c.evicted,
	}
}

// nowTime 方便测试里替换时间源。
func (c *Cache) nowTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// expirationAt 计算某条记录的过期时间。
func expirationAt(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return now
	}
	return now.Add(ttl)
}

// pruneExpiredLocked 删除所有过期项。
// 调用者必须持有写锁。
func (c *Cache) pruneExpiredLocked(now time.Time) int {
	removed := 0
	for key, e := range c.data {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(c.data, key)
			removed++
		}
	}
	return removed
}

// evictOneLocked 执行一次简单淘汰。
// 第一版不引入完整 LRU，而是淘汰最早最近访问的项。
func (c *Cache) evictOneLocked() {
	if len(c.data) == 0 {
		return
	}

	var (
		oldestKey string
		oldest    *entry
	)

	for key, e := range c.data {
		if oldest == nil {
			oldestKey = key
			oldest = e
			continue
		}
		if e.lastAccess.Before(oldest.lastAccess) {
			oldestKey = key
			oldest = e
			continue
		}
		if e.lastAccess.Equal(oldest.lastAccess) && e.expiresAt.Before(oldest.expiresAt) {
			oldestKey = key
			oldest = e
		}
	}

	if oldestKey != "" {
		delete(c.data, oldestKey)
		c.evicted++
	}
}
