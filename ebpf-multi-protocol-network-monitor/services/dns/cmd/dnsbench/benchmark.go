package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/services/dns/api"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/store"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/testkit/loadgen"
	"ebpf-multi-protocol-network-monitor/user/controller"
	xmetrics "ebpf-multi-protocol-network-monitor/user/metrics"
)

type benchMode string

const (
	benchModeBaseline benchMode = "baseline"
	benchModeXDPMiss  benchMode = "xdp-miss"
	benchModeXDPHit   benchMode = "xdp-hit"
)

type benchmarkLoadGenResult = loadgen.Result

type benchmarkResult struct {
	Mode    benchMode              `json:"mode"`
	LoadGen benchmarkLoadGenResult `json:"loadgen"`
}

type benchmarkOutput struct {
	Mode    benchMode              `json:"mode"`
	LoadGen benchmarkLoadGenResult `json:"loadgen"`
	XDP     *xmetrics.Snapshot     `json:"xdp,omitempty"`
}

type benchmarkRunner interface {
	Run(context.Context) (benchmarkResult, error)
}

type benchmarkController interface {
	Run(context.Context) error
	Snapshot() (xmetrics.Snapshot, error)
	Ready() <-chan struct{}
}

type benchmarkRunnerFactory func(config.LoadGenConfig) (benchmarkRunner, error)
type benchmarkControllerFactory func(config.XDPConfig, []api.Record) benchmarkController

var (
	defaultBenchmarkRunnerFactory = func(cfg config.LoadGenConfig) (benchmarkRunner, error) {
		factory, err := loadgen.NewUDPTransportFactory(cfg.Target, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		runner, err := loadgen.New(cfg, factory)
		if err != nil {
			return nil, err
		}
		return &loadgenRunner{runner: runner}, nil
	}
	defaultBenchmarkControllerFactory = func(cfg config.XDPConfig, records []api.Record) benchmarkController {
		return controller.New(cfg, records)
	}
)

type loadgenRunner struct {
	runner *loadgen.Runner
}

func (r *loadgenRunner) Run(ctx context.Context) (benchmarkResult, error) {
	if r == nil || r.runner == nil {
		return benchmarkResult{}, errors.New("dnsbench: runner is nil")
	}
	result, err := r.runner.Run(ctx)
	if err != nil {
		return benchmarkResult{}, err
	}
	return benchmarkResult{LoadGen: result}, nil
}

func run() error {
	cfg := config.Default()
	cfg.ApplyEnv()

	mode := benchModeBaseline
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&mode, "bench.mode", "benchmark mode: baseline|xdp-miss|xdp-hit")
	config.BindFlags(fs, &cfg)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	prepared, err := prepareBenchmarkConfig(cfg, mode)
	if err != nil {
		return err
	}
	if err := prepared.Validate(); err != nil {
		return err
	}

	return runBenchmark(context.Background(), prepared, mode, defaultBenchmarkRunnerFactory, defaultBenchmarkControllerFactory, os.Stdout)
}

func prepareBenchmarkConfig(cfg config.Config, mode benchMode) (config.Config, error) {
	cfg.Normalize()

	switch mode {
	case "", benchModeBaseline:
		cfg.XDP.Enabled = false
		cfg.XDP.PrewarmDemo = false
	case benchModeXDPMiss:
		cfg.XDP.Enabled = true
		cfg.XDP.PrewarmDemo = false
	case benchModeXDPHit:
		cfg.XDP.Enabled = true
		cfg.XDP.PrewarmDemo = true
	default:
		return config.Config{}, fmt.Errorf("dnsbench: unsupported mode %q", mode)
	}

	if cfg.XDP.Enabled {
		port, err := config.PortFromAddr(cfg.LoadGen.Target)
		if err != nil {
			return config.Config{}, fmt.Errorf("dnsbench: derive xdp listen port: %w", err)
		}
		cfg.XDP.ListenPort = port
	}

	return cfg, nil
}

func runBenchmark(
	ctx context.Context,
	cfg config.Config,
	mode benchMode,
	runnerFactory benchmarkRunnerFactory,
	controllerFactory benchmarkControllerFactory,
	out io.Writer,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	prepared, err := prepareBenchmarkConfig(cfg, mode)
	if err != nil {
		return err
	}
	if runnerFactory == nil {
		return errors.New("dnsbench: runner factory is nil")
	}
	if out == nil {
		out = io.Discard
	}

	runner, err := runnerFactory(prepared.LoadGen)
	if err != nil {
		return err
	}

	output := benchmarkOutput{Mode: mode}
	var ctrl benchmarkController
	var runCtx context.Context = ctx
	var cancel context.CancelFunc = func() {}
	var ctrlErrCh chan error

	if prepared.XDP.Enabled {
		if controllerFactory == nil {
			return errors.New("dnsbench: controller factory is nil")
		}
		ctrl = controllerFactory(prepared.XDP, store.Default().Records())
		if ctrl == nil {
			return errors.New("dnsbench: controller factory returned nil")
		}

		runCtx, cancel = context.WithCancel(ctx)
		ctrlErrCh = make(chan error, 1)
		go func() {
			ctrlErrCh <- ctrl.Run(runCtx)
		}()

		if err := waitForControllerReady(runCtx, ctrl, ctrlErrCh); err != nil {
			cancel()
			return err
		}
		if prepared.XDP.AttachWait > 0 {
			timer := time.NewTimer(prepared.XDP.AttachWait)
			select {
			case <-runCtx.Done():
				timer.Stop()
				cancel()
				if ctrlErrCh != nil {
					<-ctrlErrCh
				}
				return runCtx.Err()
			case <-timer.C:
			}
		}
	}

	result, err := runner.Run(runCtx)
	if err != nil {
		cancel()
		if ctrlErrCh != nil {
			<-ctrlErrCh
		}
		return err
	}
	output.LoadGen = result.LoadGen
	if output.Mode == "" {
		output.Mode = result.Mode
	}

	if ctrl != nil {
		snap, snapErr := ctrl.Snapshot()
		if snapErr != nil {
			cancel()
			<-ctrlErrCh
			return snapErr
		}
		output.XDP = &snap
	}

	cancel()
	if ctrlErrCh != nil {
		if ctrlErr := <-ctrlErrCh; ctrlErr != nil && !errors.Is(ctrlErr, context.Canceled) {
			return ctrlErr
		}
	}

	raw, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(raw))
	return err
}

func waitForControllerReady(ctx context.Context, ctrl benchmarkController, errCh <-chan error) error {
	if ctrl == nil {
		return nil
	}
	ready := ctrl.Ready()
	if ready == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	case <-ready:
		return nil
	}
}

func (m *benchMode) Set(raw string) error {
	parsed, err := parseBenchMode(raw)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

func (m *benchMode) String() string {
	if m == nil || *m == "" {
		return string(benchModeBaseline)
	}
	return string(*m)
}

func parseBenchMode(raw string) (benchMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(benchModeBaseline):
		return benchModeBaseline, nil
	case string(benchModeXDPMiss):
		return benchModeXDPMiss, nil
	case string(benchModeXDPHit):
		return benchModeXDPHit, nil
	default:
		return "", fmt.Errorf("dnsbench: unsupported mode %q", raw)
	}
}

var _ flag.Value = (*benchMode)(nil)
