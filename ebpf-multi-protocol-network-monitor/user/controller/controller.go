package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/services/dns/api"
	"ebpf-multi-protocol-network-monitor/user/cache_manager"
	"ebpf-multi-protocol-network-monitor/user/loader"
	umetrics "ebpf-multi-protocol-network-monitor/user/metrics"
)

// Controller owns the DNS XDP runtime.
type Controller struct {
	cfg     config.XDPConfig
	records []api.Record

	loader  *loader.Loader
	manager *cache_manager.Manager
	reader  *umetrics.Reader
	ready   chan struct{}
	once    sync.Once
}

// New creates a controller from config and an optional warm record set.
func New(cfg config.XDPConfig, records []api.Record) *Controller {
	return &Controller{
		cfg:     cfg,
		records: append([]api.Record(nil), records...),
		ready:   make(chan struct{}),
	}
}

// Ready returns a channel that closes once the controller finished setup.
func (c *Controller) Ready() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.ready
}

// Run loads, optionally seeds, attaches, and blocks until ctx is done.
func (c *Controller) Run(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if !c.cfg.Enabled {
		c.signalReady()
		<-ctx.Done()
		return ctx.Err()
	}
	if c.cfg.ListenPort == 0 {
		return errors.New("controller: xdp listen port is required")
	}

	ldr, err := loader.Load(loader.Options{
		ObjectPath: c.cfg.ObjectPath,
		Interface:  c.cfg.Interface,
		PinPath:    c.cfg.PinPath,
		AttachMode: c.cfg.AttachMode,
	})
	if err != nil {
		return err
	}
	defer ldr.Close()

	c.loader = ldr
	c.reader = umetrics.New(ldr)

	if err := c.writeConfig(ldr); err != nil {
		return err
	}

	hotMap, err := ldr.Map("dns_hot_map")
	if err != nil {
		return err
	}
	c.manager = cache_manager.New(hotMap)

	if c.cfg.PrewarmDemo && len(c.records) > 0 {
		if err := c.manager.Seed(c.records); err != nil {
			return err
		}
	}

	if c.cfg.AutoAttach {
		if err := ldr.AttachXDP(); err != nil {
			return err
		}
	}

	if err := c.signalSetupReady(); err != nil {
		return err
	}

	<-ctx.Done()
	return ctx.Err()
}

// Snapshot returns the latest BPF-side metrics snapshot.
func (c *Controller) Snapshot() (umetrics.Snapshot, error) {
	if c == nil || c.reader == nil {
		return umetrics.Snapshot{}, errors.New("controller: metrics reader is not ready")
	}
	return c.reader.Snapshot()
}

// SweepExpired removes expired hot entries from the XDP map.
func (c *Controller) SweepExpired(now time.Time) (int, error) {
	if c == nil || c.manager == nil {
		return 0, errors.New("controller: cache manager is not ready")
	}
	return c.manager.SweepExpired(now)
}

// Promote inserts or refreshes one record in the XDP hot map.
func (c *Controller) Promote(record api.Record, now time.Time) error {
	if c == nil || c.manager == nil {
		return errors.New("controller: cache manager is not ready")
	}
	return c.manager.Promote(record, now)
}

func (c *Controller) String() string {
	return fmt.Sprintf("controller(enabled=%v iface=%s object=%s)", c.cfg.Enabled, c.cfg.Interface, c.cfg.ObjectPath)
}

func (c *Controller) writeConfig(ldr *loader.Loader) error {
	cfgMap, err := ldr.Map("dns_config_map")
	if err != nil {
		return err
	}

	val := dnsConfigValue{
		ListenPort:  uint16(c.cfg.ListenPort),
		MaxQNameLen: 128,
	}
	var key uint32
	if err := cfgMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("controller: update dns config map: %w", err)
	}
	return nil
}

func (c *Controller) signalSetupReady() error {
	if c == nil {
		return nil
	}
	if c.cfg.ReadyFile == "" {
		c.signalReady()
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(c.cfg.ReadyFile), 0o755); err != nil {
		return fmt.Errorf("controller: mkdir ready file dir: %w", err)
	}
	if err := os.WriteFile(c.cfg.ReadyFile, []byte("ready\n"), 0o644); err != nil {
		return fmt.Errorf("controller: write ready file: %w", err)
	}
	c.signalReady()
	return nil
}

func (c *Controller) signalReady() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		close(c.ready)
	})
}

type dnsConfigValue struct {
	ListenPort  uint16
	Pad0        uint16
	MaxQNameLen uint32
	Pad1        uint32
}
