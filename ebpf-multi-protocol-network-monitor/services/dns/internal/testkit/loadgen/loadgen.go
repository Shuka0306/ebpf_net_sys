package loadgen

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
)

// Transport 表示一次 DNS 请求的传输会话。
type Transport interface {
	Exchange(context.Context, []byte) ([]byte, error)
	Close() error
}

// TransportFactory 为每个 worker 创建一个独立的 Transport。
type TransportFactory func(workerID int) (Transport, error)

// Runner 是一个可复用的 DNS 压测执行器。
type Runner struct {
	cfg     config.LoadGenConfig
	target  string
	queries []string
	factory TransportFactory
}

// Result 是一次压测的统计结果。
type Result struct {
	Target          string        `json:"target"`
	Concurrency     int           `json:"concurrency"`
	Duration        time.Duration `json:"duration"`
	Elapsed         time.Duration `json:"elapsed"`
	TotalRequests   uint64        `json:"total_requests"`
	Successes       uint64        `json:"successes"`
	Timeouts        uint64        `json:"timeouts"`
	TransportErrors uint64        `json:"transport_errors"`
	ProtocolErrors  uint64        `json:"protocol_errors"`
	SuccessRate     float64       `json:"success_rate"`
	ActualQPS       float64       `json:"actual_qps"`
	AvgLatency      time.Duration `json:"avg_latency"`
	P50Latency      time.Duration `json:"p50_latency"`
	P95Latency      time.Duration `json:"p95_latency"`
	P99Latency      time.Duration `json:"p99_latency"`
}

type workerStats struct {
	totalRequests   uint64
	successes       uint64
	timeouts        uint64
	transportErrors uint64
	protocolErrors  uint64
	latencies       []time.Duration
}

// New 创建一个 loadgen runner。
//
// factory 会为每个 worker 创建一个独立 transport 会话。
func New(cfg config.LoadGenConfig, factory TransportFactory) (*Runner, error) {
	if factory == nil {
		return nil, errors.New("loadgen: transport factory is nil")
	}
	if cfg.Target == "" {
		return nil, errors.New("loadgen: target is required")
	}
	if cfg.Concurrency <= 0 {
		return nil, errors.New("loadgen: concurrency must be > 0")
	}
	if cfg.QPS < 0 {
		return nil, errors.New("loadgen: qps must be >= 0")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Second
	}
	queries := normalizeQueries(cfg.Queries)
	if len(queries) == 0 {
		return nil, errors.New("loadgen: at least one query is required")
	}

	return &Runner{
		cfg:     cfg,
		target:  cfg.Target,
		queries: queries,
		factory: factory,
	}, nil
}

// Run 执行一次压测。
//
// 所有单请求错误都计入结果，不会因为个别失败中断整轮压测。
func (r *Runner) Run(ctx context.Context) (Result, error) {
	if r == nil {
		return Result{}, errors.New("loadgen: nil runner")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runCtx := ctx
	var cancel context.CancelFunc = func() {}
	if r.cfg.Duration > 0 {
		runCtx, cancel = context.WithTimeout(ctx, r.cfg.Duration)
	}
	defer cancel()

	transports, err := r.createTransports()
	if err != nil {
		return Result{}, err
	}
	defer closeTransports(transports)

	start := time.Now()
	limiter := newRateLimiter(r.cfg.QPS)
	defer limiter.Close()
	var seq uint64

	statsCh := make(chan workerStats, len(transports))
	var wg sync.WaitGroup
	for workerID, transport := range transports {
		wg.Add(1)
		go func(id int, tr Transport) {
			defer wg.Done()
			statsCh <- r.runWorker(runCtx, limiter, tr, &seq)
		}(workerID, transport)
	}

	go func() {
		wg.Wait()
		close(statsCh)
	}()

	merged := workerStats{}
	for ws := range statsCh {
		merged = merged.merge(ws)
	}

	elapsed := time.Since(start)
	result := merged.toResult(r.target, r.cfg.Concurrency, r.cfg.Duration, elapsed)
	return result, nil
}

func (r *Runner) createTransports() ([]Transport, error) {
	transports := make([]Transport, 0, r.cfg.Concurrency)
	for i := 0; i < r.cfg.Concurrency; i++ {
		tr, err := r.factory(i)
		if err != nil {
			closeTransports(transports)
			return nil, err
		}
		if tr == nil {
			closeTransports(transports)
			return nil, fmt.Errorf("loadgen: transport factory returned nil for worker %d", i)
		}
		transports = append(transports, tr)
	}
	return transports, nil
}

func (r *Runner) runWorker(ctx context.Context, limiter *rateLimiter, tr Transport, seq *uint64) workerStats {
	defer tr.Close()

	stats := workerStats{}
	for {
		if err := ctx.Err(); err != nil {
			return stats
		}
		if err := limiter.Wait(ctx); err != nil {
			return stats
		}

		n := atomic.AddUint64(seq, 1) - 1
		query := r.queries[int(n%uint64(len(r.queries)))]
		packetID := uint16(n + 1)
		req := buildQueryPacket(packetID, query)
		start := time.Now()
		resp, err := tr.Exchange(ctx, req)
		stats.totalRequests++
		if err != nil {
			switch {
			case isTimeoutErr(err):
				stats.timeouts++
			default:
				stats.transportErrors++
			}
			continue
		}
		if err := validateResponse(packetID, resp); err != nil {
			stats.protocolErrors++
			continue
		}

		stats.successes++
		stats.latencies = append(stats.latencies, time.Since(start))
	}
}

func (w workerStats) merge(other workerStats) workerStats {
	w.totalRequests += other.totalRequests
	w.successes += other.successes
	w.timeouts += other.timeouts
	w.transportErrors += other.transportErrors
	w.protocolErrors += other.protocolErrors
	w.latencies = append(w.latencies, other.latencies...)
	return w
}

func (w workerStats) toResult(target string, concurrency int, duration time.Duration, elapsed time.Duration) Result {
	var sum time.Duration
	for _, latency := range w.latencies {
		sum += latency
	}

	sort.Slice(w.latencies, func(i, j int) bool { return w.latencies[i] < w.latencies[j] })

	result := Result{
		Target:          target,
		Concurrency:     concurrency,
		Duration:        duration,
		Elapsed:         elapsed,
		TotalRequests:   w.totalRequests,
		Successes:       w.successes,
		Timeouts:        w.timeouts,
		TransportErrors: w.transportErrors,
		ProtocolErrors:  w.protocolErrors,
	}
	if w.totalRequests > 0 && elapsed > 0 {
		result.SuccessRate = float64(w.successes) / float64(w.totalRequests)
		result.ActualQPS = float64(w.totalRequests) / elapsed.Seconds()
	}
	if len(w.latencies) > 0 {
		result.AvgLatency = sum / time.Duration(len(w.latencies))
		result.P50Latency = percentile(w.latencies, 0.50)
		result.P95Latency = percentile(w.latencies, 0.95)
		result.P99Latency = percentile(w.latencies, 0.99)
	}
	return result
}

func normalizeQueries(in []string) []string {
	out := make([]string, 0, len(in))
	for _, q := range in {
		q = strings.TrimSpace(q)
		if q != "" {
			out = append(out, q)
		}
	}
	return out
}

func buildQueryPacket(id uint16, name string) []byte {
	buf := make([]byte, 0, 256)
	buf = appendUint16(buf, id)
	buf = appendUint16(buf, 0x0100) // RD
	buf = appendUint16(buf, 1)
	buf = appendUint16(buf, 0)
	buf = appendUint16(buf, 0)
	buf = appendUint16(buf, 0)

	for _, label := range strings.Split(strings.TrimSuffix(strings.TrimSpace(name), "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)
	buf = appendUint16(buf, 1) // A
	buf = appendUint16(buf, 1) // IN
	return buf
}

func appendUint16(buf []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(buf, v)
}

func validateResponse(expectedID uint16, raw []byte) error {
	if len(raw) < 12 {
		return errors.New("loadgen: short response")
	}

	hdr := decodeHeader(raw[:12])
	if hdr.ID != expectedID {
		return fmt.Errorf("loadgen: unexpected response id %d", hdr.ID)
	}
	if !hdr.QR {
		return errors.New("loadgen: response missing QR flag")
	}
	if hdr.RCode != 0 {
		return fmt.Errorf("loadgen: unexpected rcode %d", hdr.RCode)
	}
	if hdr.QDCount == 0 || hdr.ANCount == 0 {
		return errors.New("loadgen: missing question or answer")
	}

	off := 12
	for i := 0; i < int(hdr.QDCount); i++ {
		_, next, err := readName(raw, off, 0)
		if err != nil {
			return err
		}
		off = next
		if off+4 > len(raw) {
			return errors.New("loadgen: short question section")
		}
		off += 4
	}

	_, next, err := readName(raw, off, 0)
	if err != nil {
		return err
	}
	off = next
	if off+10 > len(raw) {
		return errors.New("loadgen: short answer section")
	}

	typ := binary.BigEndian.Uint16(raw[off : off+2])
	class := binary.BigEndian.Uint16(raw[off+2 : off+4])
	rdlen := int(binary.BigEndian.Uint16(raw[off+8 : off+10]))
	off += 10
	if typ != 1 || class != 1 || rdlen != 4 {
		return errors.New("loadgen: unexpected answer shape")
	}
	if off+rdlen > len(raw) {
		return errors.New("loadgen: short answer data")
	}
	if net.IP(raw[off:off+rdlen]).To4() == nil {
		return errors.New("loadgen: invalid ipv4 answer")
	}

	return nil
}

func decodeHeader(raw []byte) header {
	flags := binary.BigEndian.Uint16(raw[2:4])
	return header{
		ID:      binary.BigEndian.Uint16(raw[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0F),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		Z:       uint8((flags >> 4) & 0x07),
		RCode:   uint8(flags & 0x0F),
		QDCount: binary.BigEndian.Uint16(raw[4:6]),
		ANCount: binary.BigEndian.Uint16(raw[6:8]),
		NSCount: binary.BigEndian.Uint16(raw[8:10]),
		ARCount: binary.BigEndian.Uint16(raw[10:12]),
	}
}

type header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func readName(raw []byte, off int, depth int) (string, int, error) {
	if depth > 10 {
		return "", 0, errors.New("loadgen: malformed name")
	}
	if off >= len(raw) {
		return "", 0, errors.New("loadgen: short packet")
	}

	var labels []string
	next := off
	jumped := false
	jumpOff := 0

	for {
		if next >= len(raw) {
			return "", 0, errors.New("loadgen: short packet")
		}
		l := int(raw[next])
		if l == 0 {
			next++
			break
		}
		if l&0xC0 == 0xC0 {
			if next+1 >= len(raw) {
				return "", 0, errors.New("loadgen: short packet")
			}
			ptr := int(binary.BigEndian.Uint16(raw[next:next+2]) & 0x3FFF)
			if !jumped {
				jumpOff = next + 2
				jumped = true
			}
			if ptr >= len(raw) {
				return "", 0, errors.New("loadgen: malformed name")
			}
			name, _, err := readName(raw, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if name != "" {
				labels = append(labels, strings.Split(name, ".")...)
			}
			next = jumpOff
			break
		}
		next++
		if next+l > len(raw) {
			return "", 0, errors.New("loadgen: short packet")
		}
		labels = append(labels, string(raw[next:next+l]))
		next += l
	}

	return strings.Join(labels, "."), next, nil
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int(math.Ceil(float64(len(sorted))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	type timeout interface {
		Timeout() bool
	}
	var te timeout
	if errors.As(err, &te) {
		return te.Timeout()
	}
	return false
}

func closeTransports(transports []Transport) {
	for _, tr := range transports {
		if tr != nil {
			_ = tr.Close()
		}
	}
}
