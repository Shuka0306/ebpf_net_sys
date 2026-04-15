package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/services/dns/api"
	xmetrics "ebpf-multi-protocol-network-monitor/user/metrics"
)

func TestPrepareBenchmarkConfig(t *testing.T) {
	cfg := config.Default()

	base, err := prepareBenchmarkConfig(cfg, benchModeBaseline)
	if err != nil {
		t.Fatalf("prepareBenchmarkConfig baseline failed: %v", err)
	}
	if base.XDP.Enabled {
		t.Fatalf("baseline should disable XDP: %+v", base.XDP)
	}
	if base.XDP.PrewarmDemo {
		t.Fatalf("baseline should not prewarm XDP: %+v", base.XDP)
	}

	miss, err := prepareBenchmarkConfig(cfg, benchModeXDPMiss)
	if err != nil {
		t.Fatalf("prepareBenchmarkConfig xdp-miss failed: %v", err)
	}
	if !miss.XDP.Enabled {
		t.Fatalf("xdp-miss should enable XDP: %+v", miss.XDP)
	}
	if miss.XDP.PrewarmDemo {
		t.Fatalf("xdp-miss should not prewarm XDP: %+v", miss.XDP)
	}
	if miss.XDP.ListenPort != 1053 {
		t.Fatalf("xdp-miss should derive listen port from target: %+v", miss.XDP)
	}

	hit, err := prepareBenchmarkConfig(cfg, benchModeXDPHit)
	if err != nil {
		t.Fatalf("prepareBenchmarkConfig xdp-hit failed: %v", err)
	}
	if !hit.XDP.Enabled {
		t.Fatalf("xdp-hit should enable XDP: %+v", hit.XDP)
	}
	if !hit.XDP.PrewarmDemo {
		t.Fatalf("xdp-hit should prewarm XDP: %+v", hit.XDP)
	}
	if hit.XDP.ListenPort != 1053 {
		t.Fatalf("xdp-hit should derive listen port from target: %+v", hit.XDP)
	}
}

func TestRunBenchmarkBaselineSkipsXDP(t *testing.T) {
	cfg := config.Default()
	cfg.LoadGen.Target = "127.0.0.1:1053"
	cfg.LoadGen.Duration = time.Second
	cfg.LoadGen.Concurrency = 1
	cfg.XDP.Enabled = false

	controllerCalled := false
	runnerFactory := func(config.LoadGenConfig) (benchmarkRunner, error) {
		return &fakeBenchmarkRunner{
			result: benchmarkResult{
				Mode: benchModeBaseline,
				LoadGen: benchmarkLoadGenResult{
					Target:        cfg.LoadGen.Target,
					TotalRequests: 7,
					Successes:     7,
				},
			},
		}, nil
	}
	controllerFactory := func(config.XDPConfig, []api.Record) benchmarkController {
		controllerCalled = true
		return &fakeController{}
	}

	var buf bytes.Buffer
	if err := runBenchmark(context.Background(), cfg, benchModeBaseline, runnerFactory, controllerFactory, &buf); err != nil {
		t.Fatalf("runBenchmark baseline failed: %v", err)
	}
	if controllerCalled {
		t.Fatalf("baseline should not create controller")
	}
	if !strings.Contains(buf.String(), `"mode": "baseline"`) {
		t.Fatalf("missing baseline mode in output: %s", buf.String())
	}
}

func TestRunBenchmarkXDPHitIncludesSnapshot(t *testing.T) {
	cfg := config.Default()
	cfg.LoadGen.Target = "127.0.0.1:1053"
	cfg.LoadGen.Duration = time.Second
	cfg.LoadGen.Concurrency = 1
	cfg.XDP.Interface = "eth0"
	cfg.XDP.ObjectPath = "dist/dns_ingress.o"

	var gotCfg config.XDPConfig
	var gotRecords int
	runnerFactory := func(config.LoadGenConfig) (benchmarkRunner, error) {
		return &fakeBenchmarkRunner{
			result: benchmarkResult{
				Mode: benchModeXDPHit,
				LoadGen: benchmarkLoadGenResult{
					Target:        cfg.LoadGen.Target,
					TotalRequests: 5,
					Successes:     5,
				},
			},
		}, nil
	}
	controllerFactory := func(xcfg config.XDPConfig, records []api.Record) benchmarkController {
		gotCfg = xcfg
		gotRecords = len(records)
		return &fakeController{
			snapshot: xmetrics.Snapshot{
				Packets:    9,
				HotEntries: 3,
				HitRate:    0.75,
			},
		}
	}

	var buf bytes.Buffer
	if err := runBenchmark(context.Background(), cfg, benchModeXDPHit, runnerFactory, controllerFactory, &buf); err != nil {
		t.Fatalf("runBenchmark xdp-hit failed: %v", err)
	}
	if !gotCfg.Enabled || !gotCfg.PrewarmDemo {
		t.Fatalf("xdp-hit should enable prewarm controller: %+v", gotCfg)
	}
	if gotCfg.ListenPort != 1053 {
		t.Fatalf("xdp-hit should derive listen port into controller config: %+v", gotCfg)
	}
	if gotRecords != 3 {
		t.Fatalf("expected 3 prewarm records, got %d", gotRecords)
	}
	if !strings.Contains(buf.String(), `"mode": "xdp-hit"`) {
		t.Fatalf("missing xdp-hit mode in output: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"hot_entries": 3`) {
		t.Fatalf("missing xdp snapshot in output: %s", buf.String())
	}
}

func TestRunBenchmarkReturnsControllerErrorBeforeReady(t *testing.T) {
	cfg := config.Default()
	cfg.LoadGen.Target = "127.0.0.1:1053"
	cfg.LoadGen.Duration = time.Second
	cfg.LoadGen.Concurrency = 1
	cfg.XDP.Interface = "eth0"
	cfg.XDP.ObjectPath = "dist/dns_ingress.o"

	runnerFactory := func(config.LoadGenConfig) (benchmarkRunner, error) {
		return &fakeBenchmarkRunner{
			result: benchmarkResult{
				Mode: benchModeXDPHit,
				LoadGen: benchmarkLoadGenResult{
					Target:        cfg.LoadGen.Target,
					TotalRequests: 1,
					Successes:     1,
				},
			},
		}, nil
	}
	controllerFactory := func(config.XDPConfig, []api.Record) benchmarkController {
		return &fakeController{
			err:   errors.New("controller failed before ready"),
			ready: make(chan struct{}),
		}
	}

	done := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		done <- runBenchmark(context.Background(), cfg, benchModeXDPHit, runnerFactory, controllerFactory, &buf)
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "controller failed before ready") {
			t.Fatalf("expected controller error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runBenchmark timed out waiting for controller error")
	}
}

func TestBenchmarkOutputIsStableJSON(t *testing.T) {
	out := benchmarkOutput{
		Mode: benchModeXDPMiss,
		LoadGen: benchmarkLoadGenResult{
			Target:        "127.0.0.1:1053",
			TotalRequests: 11,
			Successes:     10,
		},
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		`"mode":"xdp-miss"`,
		`"total_requests":11`,
		`"successes":10`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("json output missing %q: %s", want, body)
		}
	}
}

type fakeBenchmarkRunner struct {
	result benchmarkResult
	err    error
}

func (f *fakeBenchmarkRunner) Run(context.Context) (benchmarkResult, error) {
	return f.result, f.err
}

type fakeController struct {
	snapshot xmetrics.Snapshot
	err      error
	ready    chan struct{}
}

func (f *fakeController) Run(context.Context) error { return f.err }

func (f *fakeController) Snapshot() (xmetrics.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeController) Ready() <-chan struct{} {
	if f.ready == nil {
		f.ready = make(chan struct{})
		close(f.ready)
	}
	return f.ready
}
