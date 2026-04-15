package metrics

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"

	"ebpf-multi-protocol-network-monitor/user/cache_manager"
	"ebpf-multi-protocol-network-monitor/user/loader"
)

// Snapshot 是 DNS XDP 程序的运行时统计快照。
type Snapshot struct {
	Packets     uint64  `json:"packets"`
	DNSQueries  uint64  `json:"dns_queries"`
	ParseErrors uint64  `json:"parse_errors"`
	Unsupported uint64  `json:"unsupported"`
	HotHits     uint64  `json:"hot_hits"`
	HotMisses   uint64  `json:"hot_misses"`
	PassThrough uint64  `json:"pass_through"`
	Responses   uint64  `json:"responses"`
	Truncated   uint64  `json:"truncated"`
	HotEntries  int     `json:"hot_entries"`
	HitRate     float64 `json:"hit_rate"`
}

// Reader 从 loader 中读取 stats / hot map。
type Reader struct {
	loader *loader.Loader
}

// New creates a metrics reader.
func New(l *loader.Loader) *Reader {
	return &Reader{loader: l}
}

// Snapshot collects current counters and map sizes.
func (r *Reader) Snapshot() (Snapshot, error) {
	if r == nil || r.loader == nil {
		return Snapshot{}, fmt.Errorf("metrics: loader is nil")
	}

	statsMap, err := r.loader.Map("dns_stats_map")
	if err != nil {
		return Snapshot{}, err
	}
	hotMap, err := r.loader.Map("dns_hot_map")
	if err != nil {
		return Snapshot{}, err
	}

	var key uint32
	var stats bpfStats
	if err := statsMap.Lookup(&key, &stats); err != nil && !isNotExist(err) {
		return Snapshot{}, fmt.Errorf("metrics: lookup stats: %w", err)
	}

	entries, err := countHotEntries(hotMap)
	if err != nil {
		return Snapshot{}, err
	}

	snap := Snapshot{
		Packets:     stats.Packets,
		DNSQueries:  stats.DNSQueries,
		ParseErrors: stats.ParseErrors,
		Unsupported: stats.Unsupported,
		HotHits:     stats.HotHits,
		HotMisses:   stats.HotMisses,
		PassThrough: stats.PassThrough,
		Responses:   stats.Responses,
		Truncated:   stats.Truncated,
		HotEntries:  entries,
	}
	total := snap.HotHits + snap.HotMisses
	if total > 0 {
		snap.HitRate = float64(snap.HotHits) / float64(total)
	}
	return snap, nil
}

// RenderText returns a stable text representation.
func (s Snapshot) RenderText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "dns_xdp_packets_total %d\n", s.Packets)
	fmt.Fprintf(&b, "dns_xdp_dns_queries_total %d\n", s.DNSQueries)
	fmt.Fprintf(&b, "dns_xdp_parse_errors_total %d\n", s.ParseErrors)
	fmt.Fprintf(&b, "dns_xdp_unsupported_total %d\n", s.Unsupported)
	fmt.Fprintf(&b, "dns_xdp_hot_hits_total %d\n", s.HotHits)
	fmt.Fprintf(&b, "dns_xdp_hot_misses_total %d\n", s.HotMisses)
	fmt.Fprintf(&b, "dns_xdp_pass_through_total %d\n", s.PassThrough)
	fmt.Fprintf(&b, "dns_xdp_responses_total %d\n", s.Responses)
	fmt.Fprintf(&b, "dns_xdp_truncated_total %d\n", s.Truncated)
	fmt.Fprintf(&b, "dns_xdp_hot_entries %d\n", s.HotEntries)
	fmt.Fprintf(&b, "dns_xdp_hot_hit_rate %.6f\n", s.HitRate)
	return b.String()
}

// MarshalJSON returns the canonical JSON payload.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type alias Snapshot
	return json.Marshal(alias(s))
}

type bpfStats struct {
	Packets     uint64
	DNSQueries  uint64
	ParseErrors uint64
	Unsupported uint64
	HotHits     uint64
	HotMisses   uint64
	PassThrough uint64
	Responses   uint64
	Truncated   uint64
}

func countHotEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("metrics: hot map is nil")
	}
	iter := m.Iterate()
	var key cache_manager.HotKey
	var val cache_manager.HotVal
	count := 0
	for iter.Next(&key, &val) {
		count++
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("metrics: iterate hot map: %w", err)
	}
	return count, nil
}

func isNotExist(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "key does not exist")
}
