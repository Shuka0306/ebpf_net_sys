package loadgen

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/internal/metrics"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/cache"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/dnsmsg"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/server"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/store"
)

func TestRunCollectsSuccessTimeoutProtocolAndTransportErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu        sync.Mutex
		callCount int
		seenNames []string
	)

	runner := mustRunner(t, config.LoadGenConfig{
		Target:      "127.0.0.1:1053",
		Concurrency: 1,
		Timeout:     20 * time.Millisecond,
		Queries:     []string{"hot.example.com", "api.example.com"},
	}, func(_ int) (Transport, error) {
		return &fakeTransport{
			exchangeFn: func(req []byte) ([]byte, error) {
				mu.Lock()
				defer mu.Unlock()

				q := mustQuery(t, req)
				seenNames = append(seenNames, q.QName)
				callCount++
				switch callCount {
				case 1:
					return mustAResponse(t, req, "1.1.1.1"), nil
				case 2:
					resp := mustAResponse(t, req, "1.1.1.1")
					binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(resp[0:2])+1)
					return resp, nil
				case 3:
					return nil, timeoutError{}
				default:
					cancel()
					return nil, errors.New("boom")
				}
			},
		}, nil
	})

	result, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.TotalRequests != 4 {
		t.Fatalf("unexpected total requests: %+v", result)
	}
	if result.Successes != 1 || result.ProtocolErrors != 1 || result.Timeouts != 1 || result.TransportErrors != 1 {
		t.Fatalf("unexpected result counts: %+v", result)
	}
	if result.AvgLatency <= 0 || result.P95Latency <= 0 || result.P99Latency <= 0 {
		t.Fatalf("expected latency stats to be populated: %+v", result)
	}
	if got := strings.Join(seenNames, ","); got != "hot.example.com,api.example.com,hot.example.com,api.example.com" {
		t.Fatalf("unexpected query order: %q", got)
	}
}

func TestRoundRobinQueryOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu    sync.Mutex
		names []string
		calls int
	)

	runner := mustRunner(t, config.LoadGenConfig{
		Target:      "127.0.0.1:1053",
		Concurrency: 1,
		Timeout:     20 * time.Millisecond,
		Queries:     []string{"a.example.com", "b.example.com", "c.example.com"},
	}, func(_ int) (Transport, error) {
		return &fakeTransport{
			exchangeFn: func(req []byte) ([]byte, error) {
				q := mustQuery(t, req)
				mu.Lock()
				names = append(names, q.QName)
				calls++
				if calls == 5 {
					cancel()
				}
				mu.Unlock()
				return mustAResponse(t, req, "1.1.1.1"), nil
			},
		}, nil
	})

	result, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.TotalRequests != 5 {
		t.Fatalf("unexpected request count: %+v", result)
	}
	if got := strings.Join(names, ","); got != "a.example.com,b.example.com,c.example.com,a.example.com,b.example.com" {
		t.Fatalf("unexpected round robin order: %q", got)
	}
}

func TestQPSLimitAppliesSpacing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu    sync.Mutex
		times []time.Time
		calls int
	)

	runner := mustRunner(t, config.LoadGenConfig{
		Target:      "127.0.0.1:1053",
		Concurrency: 1,
		QPS:         20,
		Timeout:     20 * time.Millisecond,
		Queries:     []string{"hot.example.com"},
	}, func(_ int) (Transport, error) {
		return &fakeTransport{
			exchangeFn: func(req []byte) ([]byte, error) {
				mu.Lock()
				times = append(times, time.Now())
				calls++
				if calls == 3 {
					cancel()
				}
				mu.Unlock()
				return mustAResponse(t, req, "1.1.1.1"), nil
			},
		}, nil
	})

	start := time.Now()
	result, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.TotalRequests != 3 {
		t.Fatalf("unexpected request count: %+v", result)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(times) != 3 {
		t.Fatalf("unexpected timestamps: %d", len(times))
	}
	if d := times[1].Sub(times[0]); d < 40*time.Millisecond {
		t.Fatalf("QPS limiter did not space requests enough: %s", d)
	}
	if d := times[2].Sub(times[1]); d < 40*time.Millisecond {
		t.Fatalf("QPS limiter did not space requests enough: %s", d)
	}
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("run ended too quickly for QPS limit: %s", elapsed)
	}
}

func TestResultJSONMarshalsStableFields(t *testing.T) {
	raw, err := json.Marshal(Result{
		Target:          "127.0.0.1:1053",
		TotalRequests:   7,
		Successes:       6,
		Timeouts:        1,
		ProtocolErrors:  0,
		TransportErrors: 0,
	})
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	body := string(raw)
	for _, want := range []string{
		`"target":"127.0.0.1:1053"`,
		`"total_requests":7`,
		`"successes":6`,
		`"timeouts":1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("json output missing %q: %s", want, body)
		}
	}
}

func TestRunAgainstLocalDNSBaseline(t *testing.T) {
	addr, stop := startLocalDNSBaseline(t)
	defer stop()

	runner := mustRunner(t, config.LoadGenConfig{
		Target:      addr,
		Concurrency: 1,
		Duration:    300 * time.Millisecond,
		QPS:         20,
		Timeout:     500 * time.Millisecond,
		Queries:     []string{"hot.example.com"},
	}, mustUDPFactory(t, addr, 500*time.Millisecond))

	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.Successes == 0 {
		t.Fatalf("expected at least one successful request: %+v", result)
	}
	if result.ProtocolErrors != 0 {
		t.Fatalf("unexpected protocol errors in smoke test: %+v", result)
	}
}

func mustRunner(t *testing.T, cfg config.LoadGenConfig, factory TransportFactory) *Runner {
	t.Helper()

	runner, err := New(cfg, factory)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return runner
}

func mustUDPFactory(t *testing.T, addr string, timeout time.Duration) TransportFactory {
	t.Helper()

	factory, err := NewUDPTransportFactory(addr, timeout)
	if err != nil {
		t.Fatalf("NewUDPTransportFactory failed: %v", err)
	}
	return factory
}

func mustQuery(t *testing.T, raw []byte) dnsmsg.Question {
	t.Helper()

	msg, err := dnsmsg.ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("unexpected question count: %d", len(msg.Questions))
	}
	return msg.Questions[0]
}

func mustAResponse(t *testing.T, req []byte, ip string) []byte {
	t.Helper()

	msg, err := dnsmsg.ParseQuery(req)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	resp, err := dnsmsg.BuildAResponse(msg, ip, time.Second)
	if err != nil {
		t.Fatalf("BuildAResponse failed: %v", err)
	}
	return resp
}

func startLocalDNSBaseline(t *testing.T) (string, func()) {
	t.Helper()

	cfg := config.Default().DNS
	reg := metrics.NewRegistry()
	c := cache.New(cfg.CacheCapacity)
	srv := server.New(cfg, store.Default(), c, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.ServePacketConn(ctx, conn)
	}()

	stop := func() {
		cancel()
		_ = conn.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ServePacketConn returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("DNS baseline server did not stop")
		}
	}

	return conn.LocalAddr().String(), stop
}

type fakeTransport struct {
	mu         sync.Mutex
	exchangeFn func([]byte) ([]byte, error)
	closed     bool
}

func (f *fakeTransport) Exchange(_ context.Context, req []byte) ([]byte, error) {
	f.mu.Lock()
	fn := f.exchangeFn
	f.mu.Unlock()
	if fn == nil {
		return nil, nil
	}
	return fn(req)
}

func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
