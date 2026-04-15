package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Registry 是 DNS baseline 的最小运行指标收集器。
//
// 第一版只记录少量关键计数和总耗时，输出为可读的文本格式，便于
// 本地调试和后续脚本抓取。
type Registry struct {
	mu             sync.RWMutex
	requests       uint64
	cacheHits      uint64
	cacheMisses    uint64
	storeHits      uint64
	storeMisses    uint64
	parseErrors    uint64
	droppedPackets uint64
	totalLatency   time.Duration
	rcodeCounters  map[string]uint64
}

// Snapshot 提供一份当前指标快照，方便测试和导出。
type Snapshot struct {
	Requests       uint64
	CacheHits      uint64
	CacheMisses    uint64
	StoreHits      uint64
	StoreMisses    uint64
	ParseErrors    uint64
	DroppedPackets uint64
	TotalLatency   time.Duration
	RCodes         map[string]uint64
}

// NewRegistry 创建一个空的指标注册表。
func NewRegistry() *Registry {
	return &Registry{
		rcodeCounters: make(map[string]uint64),
	}
}

// IncRequest 记录一次成功进入 resolver 的请求。
func (r *Registry) IncRequest() {
	r.mu.Lock()
	r.requests++
	r.mu.Unlock()
}

// IncCacheHit 记录一次缓存命中。
func (r *Registry) IncCacheHit() {
	r.mu.Lock()
	r.cacheHits++
	r.mu.Unlock()
}

// IncCacheMiss 记录一次缓存未命中。
func (r *Registry) IncCacheMiss() {
	r.mu.Lock()
	r.cacheMisses++
	r.mu.Unlock()
}

// IncStoreHit 记录一次权威记录库命中。
func (r *Registry) IncStoreHit() {
	r.mu.Lock()
	r.storeHits++
	r.mu.Unlock()
}

// IncStoreMiss 记录一次权威记录库未命中。
func (r *Registry) IncStoreMiss() {
	r.mu.Lock()
	r.storeMisses++
	r.mu.Unlock()
}

// IncParseError 记录一次报文解析失败。
func (r *Registry) IncParseError() {
	r.mu.Lock()
	r.parseErrors++
	r.mu.Unlock()
}

// IncDroppedPacket 记录一次被丢弃的请求包。
func (r *Registry) IncDroppedPacket() {
	r.mu.Lock()
	r.droppedPackets++
	r.mu.Unlock()
}

// ObserveLatency 累加一次请求处理耗时。
func (r *Registry) ObserveLatency(d time.Duration) {
	if d < 0 {
		return
	}
	r.mu.Lock()
	r.totalLatency += d
	r.mu.Unlock()
}

// RecordRCode 记录一次响应码出现次数。
func (r *Registry) RecordRCode(code string) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return
	}

	r.mu.Lock()
	r.rcodeCounters[code]++
	r.mu.Unlock()
}

// Snapshot 返回当前指标快照。
func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{RCodes: map[string]uint64{}}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	rcodes := make(map[string]uint64, len(r.rcodeCounters))
	for k, v := range r.rcodeCounters {
		rcodes[k] = v
	}

	return Snapshot{
		Requests:       r.requests,
		CacheHits:      r.cacheHits,
		CacheMisses:    r.cacheMisses,
		StoreHits:      r.storeHits,
		StoreMisses:    r.storeMisses,
		ParseErrors:    r.parseErrors,
		DroppedPackets: r.droppedPackets,
		TotalLatency:   r.totalLatency,
		RCodes:         rcodes,
	}
}

// Handler 返回一个稳定的文本 metrics 处理器。
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, r.RenderText())
	})
}

// RenderText 按固定顺序渲染当前指标快照。
func (r *Registry) RenderText() string {
	snap := r.Snapshot()

	var b strings.Builder
	fmt.Fprintf(&b, "dns_requests_total %d\n", snap.Requests)
	fmt.Fprintf(&b, "dns_cache_hits_total %d\n", snap.CacheHits)
	fmt.Fprintf(&b, "dns_cache_misses_total %d\n", snap.CacheMisses)
	fmt.Fprintf(&b, "dns_store_hits_total %d\n", snap.StoreHits)
	fmt.Fprintf(&b, "dns_store_misses_total %d\n", snap.StoreMisses)
	fmt.Fprintf(&b, "dns_parse_errors_total %d\n", snap.ParseErrors)
	fmt.Fprintf(&b, "dns_dropped_packets_total %d\n", snap.DroppedPackets)
	fmt.Fprintf(&b, "dns_request_duration_seconds_sum %.6f\n", snap.TotalLatency.Seconds())

	rcodes := make([]string, 0, len(snap.RCodes))
	for code := range snap.RCodes {
		rcodes = append(rcodes, code)
	}
	sort.Strings(rcodes)
	for _, code := range rcodes {
		fmt.Fprintf(&b, "dns_response_rcode_total{rcode=%q} %d\n", code, snap.RCodes[code])
	}

	return b.String()
}
