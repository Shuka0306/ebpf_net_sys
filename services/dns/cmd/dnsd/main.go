package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/internal/lifecycle"
	"ebpf-multi-protocol-network-monitor/internal/logging"
	"ebpf-multi-protocol-network-monitor/internal/metrics"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/cache"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/server"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/store"
	"ebpf-multi-protocol-network-monitor/user/controller"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dnsd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Default()
	cfg.ApplyEnv()
	config.BindFlags(flag.CommandLine, &cfg)
	flag.Parse()
	cfg.Normalize()
	if cfg.XDP.Enabled {
		port, err := config.PortFromAddr(cfg.DNS.ListenAddr)
		if err != nil {
			return err
		}
		cfg.XDP.ListenPort = port
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger, closer, err := logging.New(cfg.Logging)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}

	registry := metrics.NewRegistry()
	st := store.Default()
	var c *cache.Cache
	if cfg.DNS.EnableCache {
		c = cache.New(cfg.DNS.CacheCapacity)
	}

	srv := server.New(cfg.DNS, st, c, registry, logger)
	mgr := lifecycle.New(context.Background(), logger)
	mgr.Go("dns", func(ctx context.Context) error {
		return srv.ListenAndServe(ctx)
	})

	if cfg.XDP.Enabled {
		ctrl := controller.New(cfg.XDP, st.Records())
		mgr.Go("xdp", func(ctx context.Context) error {
			return ctrl.Run(ctx)
		})
	}

	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		var err error
		metricsSrv, err = startMetricsServer(logger, cfg.Metrics.ListenAddr, cfg.Metrics.Path, registry)
		if err != nil {
			return err
		}
		mgr.AddShutdown("metrics", func(context.Context) error {
			return shutdownMetricsServer(metricsSrv)
		})
	}

	logger.Info("dns baseline starting",
		"listen", cfg.DNS.ListenAddr,
		"cache_enabled", cfg.DNS.EnableCache,
		"metrics_enabled", cfg.Metrics.Enabled,
	)

	return mgr.Run()
}

func startMetricsServer(logger *slog.Logger, addr, path string, registry *metrics.Registry) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.Handle(path, registry.Handler())

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go func() {
		if logger != nil {
			logger.Info("metrics endpoint listening", "addr", addr, "path", path)
		}
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			if logger != nil {
				logger.Error("metrics server stopped", "error", err)
			}
		}
	}()

	return srv, nil
}

func shutdownMetricsServer(srv *http.Server) error {
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
