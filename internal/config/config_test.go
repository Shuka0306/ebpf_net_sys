package config

import (
	"flag"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.App.Name != "dns-baseline" {
		t.Fatalf("unexpected app name: %q", cfg.App.Name)
	}
	if cfg.DNS.ListenAddr != "0.0.0.0:1053" {
		t.Fatalf("unexpected dns listen addr: %q", cfg.DNS.ListenAddr)
	}
	if cfg.DNS.TTL != 60*time.Second {
		t.Fatalf("unexpected dns ttl: %s", cfg.DNS.TTL)
	}
	if !cfg.Metrics.Enabled {
		t.Fatalf("metrics should be enabled by default")
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("APP_NAME", "dns-test")
	t.Setenv("DNS_LISTEN_ADDR", "127.0.0.1:2053")
	t.Setenv("DNS_CACHE_CAPACITY", "128")
	t.Setenv("DNS_TTL", "30s")
	t.Setenv("LOADGEN_QUERIES", "a.example.com,b.example.com")
	t.Setenv("METRICS_ENABLED", "false")
	cfg := Default()
	cfg.ApplyEnv()

	if cfg.App.Name != "dns-test" {
		t.Fatalf("unexpected app name: %q", cfg.App.Name)
	}
	if cfg.DNS.ListenAddr != "127.0.0.1:2053" {
		t.Fatalf("unexpected dns listen addr: %q", cfg.DNS.ListenAddr)
	}
	if cfg.DNS.CacheCapacity != 128 {
		t.Fatalf("unexpected cache capacity: %d", cfg.DNS.CacheCapacity)
	}
	if cfg.DNS.TTL != 30*time.Second {
		t.Fatalf("unexpected ttl: %s", cfg.DNS.TTL)
	}
	if len(cfg.LoadGen.Queries) != 2 {
		t.Fatalf("unexpected queries len: %d", len(cfg.LoadGen.Queries))
	}
	if cfg.Metrics.Enabled {
		t.Fatalf("metrics should be disabled by env override")
	}
}

func TestValidate(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}

	cfg.DNS.ListenAddr = "bad-addr"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid dns listen addr")
	}

	cfg = Default()
	cfg.XDP.Enabled = true
	cfg.XDP.Interface = "eth0"
	cfg.XDP.ObjectPath = "dist/dns_ingress.o"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for missing xdp listen port")
	}
	cfg.XDP.ListenPort = 1053
	if err := cfg.Validate(); err != nil {
		t.Fatalf("xdp config should validate once listen port is set: %v", err)
	}
}

func TestBindFlags(t *testing.T) {
	cfg := Default()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	BindFlags(fs, &cfg)

	args := []string{
		"-app.name=test-app",
		"-dns.listen=127.0.0.1:3053",
		"-dns.cache-capacity=256",
		"-dns.ttl=45s",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse flags failed: %v", err)
	}

	if cfg.App.Name != "test-app" {
		t.Fatalf("unexpected app name: %q", cfg.App.Name)
	}
	if cfg.DNS.ListenAddr != "127.0.0.1:3053" {
		t.Fatalf("unexpected dns listen addr: %q", cfg.DNS.ListenAddr)
	}
	if cfg.DNS.CacheCapacity != 256 {
		t.Fatalf("unexpected cache capacity: %d", cfg.DNS.CacheCapacity)
	}
	if cfg.DNS.TTL != 45*time.Second {
		t.Fatalf("unexpected ttl: %s", cfg.DNS.TTL)
	}
}

func TestPortFromAddr(t *testing.T) {
	port, err := PortFromAddr("127.0.0.1:3053")
	if err != nil {
		t.Fatalf("PortFromAddr failed: %v", err)
	}
	if port != 3053 {
		t.Fatalf("unexpected port: %d", port)
	}
}
