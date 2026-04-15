package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds project-wide configuration shared by the DNS baseline, testkit,
// and later eBPF control-plane components.
type Config struct {
	App      AppConfig
	Logging  LoggingConfig
	DNS      DNSConfig
	XDP      XDPConfig
	GRPC     GRPCConfig
	LoadGen  LoadGenConfig
	Profiler ProfilerConfig
	Metrics  MetricsConfig
}

type AppConfig struct {
	Name string
	Env  string
}

type LoggingConfig struct {
	Level     string
	Format    string
	Output    string
	AddCaller bool
}

type DNSConfig struct {
	Network       string
	ListenAddr    string
	ZoneFile      string
	CacheCapacity int
	TTL           time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	MaxUDPSize    int
	EnableCache   bool
}

type XDPConfig struct {
	Enabled     bool
	Interface   string
	ObjectPath  string
	PinPath     string
	AttachMode  string
	ListenPort  uint
	HotCapacity int
	PrewarmDemo bool
	AutoAttach  bool
	ReadyFile   string
	AttachWait  time.Duration
}

type GRPCConfig struct {
	Enabled     bool
	Network     string
	ListenAddr  string
	ReadTimeout time.Duration
}

type LoadGenConfig struct {
	Target      string
	Concurrency int
	Duration    time.Duration
	QPS         int
	Timeout     time.Duration
	Queries     []string
}

type ProfilerConfig struct {
	Enabled    bool
	ListenAddr string
	CPUProfile string
	MemProfile string
}

type MetricsConfig struct {
	Enabled    bool
	ListenAddr string
	Path       string
}

// Default returns a sane baseline configuration for local development.
func Default() Config {
	return Config{
		App: AppConfig{
			Name: "dns-baseline",
			Env:  "dev",
		},
		Logging: LoggingConfig{
			Level:     "info",
			Format:    "text",
			Output:    "stderr",
			AddCaller: false,
		},
		DNS: DNSConfig{
			Network:       "udp",
			ListenAddr:    "0.0.0.0:1053",
			ZoneFile:      "",
			CacheCapacity: 4096,
			TTL:           60 * time.Second,
			ReadTimeout:   2 * time.Second,
			WriteTimeout:  2 * time.Second,
			MaxUDPSize:    512,
			EnableCache:   true,
		},
		XDP: XDPConfig{
			Enabled:     false,
			Interface:   "",
			ObjectPath:  "dist/dns_ingress.o",
			PinPath:     "/sys/fs/bpf/dns-baseline",
			AttachMode:  "generic",
			ListenPort:  0,
			HotCapacity: 1024,
			PrewarmDemo: false,
			AutoAttach:  true,
			ReadyFile:   "",
			AttachWait:  0,
		},
		GRPC: GRPCConfig{
			Enabled:     false,
			Network:     "tcp",
			ListenAddr:  "0.0.0.0:50051",
			ReadTimeout: 2 * time.Second,
		},
		LoadGen: LoadGenConfig{
			Target:      "127.0.0.1:1053",
			Concurrency: 16,
			Duration:    30 * time.Second,
			QPS:         0,
			Timeout:     1 * time.Second,
			Queries: []string{
				"hot.example.com",
				"api.example.com",
				"www.example.com",
			},
		},
		Profiler: ProfilerConfig{
			Enabled:    false,
			ListenAddr: "127.0.0.1:6060",
			CPUProfile: "cpu.pprof",
			MemProfile: "mem.pprof",
		},
		Metrics: MetricsConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:9090",
			Path:       "/metrics",
		},
	}
}

// Load returns a defaulted configuration with environment variable overrides
// applied.
func Load() (*Config, error) {
	cfg := Default()
	cfg.ApplyEnv()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// BindFlags attaches commonly tuned configuration fields to a FlagSet.
func BindFlags(fs *flag.FlagSet, cfg *Config) {
	if fs == nil || cfg == nil {
		return
	}

	fs.StringVar(&cfg.App.Name, "app.name", cfg.App.Name, "application name")
	fs.StringVar(&cfg.App.Env, "app.env", cfg.App.Env, "runtime environment")

	fs.StringVar(&cfg.Logging.Level, "log.level", cfg.Logging.Level, "log level")
	fs.StringVar(&cfg.Logging.Format, "log.format", cfg.Logging.Format, "log format: text|json")
	fs.StringVar(&cfg.Logging.Output, "log.output", cfg.Logging.Output, "log output destination")
	fs.BoolVar(&cfg.Logging.AddCaller, "log.add-caller", cfg.Logging.AddCaller, "add caller info")

	fs.StringVar(&cfg.DNS.Network, "dns.network", cfg.DNS.Network, "dns network type")
	fs.StringVar(&cfg.DNS.ListenAddr, "dns.listen", cfg.DNS.ListenAddr, "dns listen address")
	fs.StringVar(&cfg.DNS.ZoneFile, "dns.zone-file", cfg.DNS.ZoneFile, "dns zone file")
	fs.IntVar(&cfg.DNS.CacheCapacity, "dns.cache-capacity", cfg.DNS.CacheCapacity, "dns cache capacity")
	fs.DurationVar(&cfg.DNS.TTL, "dns.ttl", cfg.DNS.TTL, "default dns ttl")
	fs.DurationVar(&cfg.DNS.ReadTimeout, "dns.read-timeout", cfg.DNS.ReadTimeout, "dns read timeout")
	fs.DurationVar(&cfg.DNS.WriteTimeout, "dns.write-timeout", cfg.DNS.WriteTimeout, "dns write timeout")
	fs.IntVar(&cfg.DNS.MaxUDPSize, "dns.max-udp-size", cfg.DNS.MaxUDPSize, "dns max udp payload size")
	fs.BoolVar(&cfg.DNS.EnableCache, "dns.enable-cache", cfg.DNS.EnableCache, "enable user-space cache")

	fs.BoolVar(&cfg.XDP.Enabled, "xdp.enabled", cfg.XDP.Enabled, "enable xdp dns fast path")
	fs.StringVar(&cfg.XDP.Interface, "xdp.iface", cfg.XDP.Interface, "xdp attach interface")
	fs.StringVar(&cfg.XDP.ObjectPath, "xdp.object", cfg.XDP.ObjectPath, "xdp object file path")
	fs.StringVar(&cfg.XDP.PinPath, "xdp.pin-path", cfg.XDP.PinPath, "xdp pin path")
	fs.StringVar(&cfg.XDP.AttachMode, "xdp.attach-mode", cfg.XDP.AttachMode, "xdp attach mode: generic|native|skb")
	fs.UintVar(&cfg.XDP.ListenPort, "xdp.listen-port", cfg.XDP.ListenPort, "dns listen port used by the xdp config map")
	fs.IntVar(&cfg.XDP.HotCapacity, "xdp.hot-capacity", cfg.XDP.HotCapacity, "xdp hot map capacity")
	fs.BoolVar(&cfg.XDP.PrewarmDemo, "xdp.prewarm-demo", cfg.XDP.PrewarmDemo, "prewarm xdp hot map with demo store records")
	fs.BoolVar(&cfg.XDP.AutoAttach, "xdp.auto-attach", cfg.XDP.AutoAttach, "attach xdp automatically in the controller")
	fs.StringVar(&cfg.XDP.ReadyFile, "xdp.ready-file", cfg.XDP.ReadyFile, "signal file written after xdp setup is ready")
	fs.DurationVar(&cfg.XDP.AttachWait, "xdp.attach-wait", cfg.XDP.AttachWait, "wait after xdp setup before loadgen starts")

	fs.BoolVar(&cfg.GRPC.Enabled, "grpc.enabled", cfg.GRPC.Enabled, "enable grpc service")
	fs.StringVar(&cfg.GRPC.Network, "grpc.network", cfg.GRPC.Network, "grpc network type")
	fs.StringVar(&cfg.GRPC.ListenAddr, "grpc.listen", cfg.GRPC.ListenAddr, "grpc listen address")
	fs.DurationVar(&cfg.GRPC.ReadTimeout, "grpc.read-timeout", cfg.GRPC.ReadTimeout, "grpc read timeout")

	fs.StringVar(&cfg.LoadGen.Target, "loadgen.target", cfg.LoadGen.Target, "benchmark target address")
	fs.IntVar(&cfg.LoadGen.Concurrency, "loadgen.concurrency", cfg.LoadGen.Concurrency, "benchmark concurrency")
	fs.DurationVar(&cfg.LoadGen.Duration, "loadgen.duration", cfg.LoadGen.Duration, "benchmark duration")
	fs.IntVar(&cfg.LoadGen.QPS, "loadgen.qps", cfg.LoadGen.QPS, "benchmark qps limit, 0 means unlimited")
	fs.DurationVar(&cfg.LoadGen.Timeout, "loadgen.timeout", cfg.LoadGen.Timeout, "benchmark request timeout")

	fs.BoolVar(&cfg.Profiler.Enabled, "profiler.enabled", cfg.Profiler.Enabled, "enable pprof endpoints")
	fs.StringVar(&cfg.Profiler.ListenAddr, "profiler.listen", cfg.Profiler.ListenAddr, "pprof listen address")
	fs.StringVar(&cfg.Profiler.CPUProfile, "profiler.cpu-profile", cfg.Profiler.CPUProfile, "cpu profile output")
	fs.StringVar(&cfg.Profiler.MemProfile, "profiler.mem-profile", cfg.Profiler.MemProfile, "mem profile output")

	fs.BoolVar(&cfg.Metrics.Enabled, "metrics.enabled", cfg.Metrics.Enabled, "enable metrics endpoint")
	fs.StringVar(&cfg.Metrics.ListenAddr, "metrics.listen", cfg.Metrics.ListenAddr, "metrics listen address")
	fs.StringVar(&cfg.Metrics.Path, "metrics.path", cfg.Metrics.Path, "metrics endpoint path")
}

// ApplyEnv applies environment overrides to the configuration.
// Prefixes follow the component name, e.g. DNS_LISTEN_ADDR, LOG_LEVEL.
func (c *Config) ApplyEnv() {
	if c == nil {
		return
	}

	c.App.Name = getenvString("APP_NAME", c.App.Name)
	c.App.Env = getenvString("APP_ENV", c.App.Env)

	c.Logging.Level = getenvString("LOG_LEVEL", c.Logging.Level)
	c.Logging.Format = getenvString("LOG_FORMAT", c.Logging.Format)
	c.Logging.Output = getenvString("LOG_OUTPUT", c.Logging.Output)
	c.Logging.AddCaller = getenvBool("LOG_ADD_CALLER", c.Logging.AddCaller)

	c.DNS.Network = getenvString("DNS_NETWORK", c.DNS.Network)
	c.DNS.ListenAddr = getenvString("DNS_LISTEN_ADDR", c.DNS.ListenAddr)
	c.DNS.ZoneFile = getenvString("DNS_ZONE_FILE", c.DNS.ZoneFile)
	c.DNS.CacheCapacity = getenvInt("DNS_CACHE_CAPACITY", c.DNS.CacheCapacity)
	c.DNS.TTL = getenvDuration("DNS_TTL", c.DNS.TTL)
	c.DNS.ReadTimeout = getenvDuration("DNS_READ_TIMEOUT", c.DNS.ReadTimeout)
	c.DNS.WriteTimeout = getenvDuration("DNS_WRITE_TIMEOUT", c.DNS.WriteTimeout)
	c.DNS.MaxUDPSize = getenvInt("DNS_MAX_UDP_SIZE", c.DNS.MaxUDPSize)
	c.DNS.EnableCache = getenvBool("DNS_ENABLE_CACHE", c.DNS.EnableCache)

	c.XDP.Enabled = getenvBool("XDP_ENABLED", c.XDP.Enabled)
	c.XDP.Interface = getenvString("XDP_INTERFACE", c.XDP.Interface)
	c.XDP.ObjectPath = getenvString("XDP_OBJECT_PATH", c.XDP.ObjectPath)
	c.XDP.PinPath = getenvString("XDP_PIN_PATH", c.XDP.PinPath)
	c.XDP.AttachMode = getenvString("XDP_ATTACH_MODE", c.XDP.AttachMode)
	c.XDP.ListenPort = uint(getenvInt("XDP_LISTEN_PORT", int(c.XDP.ListenPort)))
	c.XDP.HotCapacity = getenvInt("XDP_HOT_CAPACITY", c.XDP.HotCapacity)
	c.XDP.PrewarmDemo = getenvBool("XDP_PREWARM_DEMO", c.XDP.PrewarmDemo)
	c.XDP.AutoAttach = getenvBool("XDP_AUTO_ATTACH", c.XDP.AutoAttach)
	c.XDP.ReadyFile = getenvString("XDP_READY_FILE", c.XDP.ReadyFile)
	c.XDP.AttachWait = getenvDuration("XDP_ATTACH_WAIT", c.XDP.AttachWait)

	c.GRPC.Enabled = getenvBool("GRPC_ENABLED", c.GRPC.Enabled)
	c.GRPC.Network = getenvString("GRPC_NETWORK", c.GRPC.Network)
	c.GRPC.ListenAddr = getenvString("GRPC_LISTEN_ADDR", c.GRPC.ListenAddr)
	c.GRPC.ReadTimeout = getenvDuration("GRPC_READ_TIMEOUT", c.GRPC.ReadTimeout)

	c.LoadGen.Target = getenvString("LOADGEN_TARGET", c.LoadGen.Target)
	c.LoadGen.Concurrency = getenvInt("LOADGEN_CONCURRENCY", c.LoadGen.Concurrency)
	c.LoadGen.Duration = getenvDuration("LOADGEN_DURATION", c.LoadGen.Duration)
	c.LoadGen.QPS = getenvInt("LOADGEN_QPS", c.LoadGen.QPS)
	c.LoadGen.Timeout = getenvDuration("LOADGEN_TIMEOUT", c.LoadGen.Timeout)
	if v := getenvString("LOADGEN_QUERIES", ""); v != "" {
		c.LoadGen.Queries = splitCSV(v)
	}

	c.Profiler.Enabled = getenvBool("PROFILER_ENABLED", c.Profiler.Enabled)
	c.Profiler.ListenAddr = getenvString("PROFILER_LISTEN_ADDR", c.Profiler.ListenAddr)
	c.Profiler.CPUProfile = getenvString("PROFILER_CPU_PROFILE", c.Profiler.CPUProfile)
	c.Profiler.MemProfile = getenvString("PROFILER_MEM_PROFILE", c.Profiler.MemProfile)

	c.Metrics.Enabled = getenvBool("METRICS_ENABLED", c.Metrics.Enabled)
	c.Metrics.ListenAddr = getenvString("METRICS_LISTEN_ADDR", c.Metrics.ListenAddr)
	c.Metrics.Path = getenvString("METRICS_PATH", c.Metrics.Path)

	c.Normalize()
}

// Normalize adjusts empty or malformed values into a safe form.
func (c *Config) Normalize() {
	if c == nil {
		return
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stderr"
	}
	if c.DNS.Network == "" {
		c.DNS.Network = "udp"
	}
	if c.GRPC.Network == "" {
		c.GRPC.Network = "tcp"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.LoadGen.Timeout <= 0 {
		c.LoadGen.Timeout = time.Second
	}
	if c.DNS.TTL <= 0 {
		c.DNS.TTL = 60 * time.Second
	}
	if c.XDP.ObjectPath == "" {
		c.XDP.ObjectPath = "dist/dns_ingress.o"
	}
	if c.XDP.PinPath == "" {
		c.XDP.PinPath = "/sys/fs/bpf/dns-baseline"
	}
	if c.XDP.AttachMode == "" {
		c.XDP.AttachMode = "generic"
	}
	if c.XDP.HotCapacity <= 0 {
		c.XDP.HotCapacity = 1024
	}
}

// Validate checks for obviously invalid values.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.App.Name == "" {
		return fmt.Errorf("app name is required")
	}
	if err := validateListenAddr("dns.listen", c.DNS.ListenAddr); err != nil {
		return err
	}
	if c.DNS.CacheCapacity < 0 {
		return fmt.Errorf("dns.cache-capacity must be >= 0")
	}
	if c.DNS.MaxUDPSize <= 0 {
		return fmt.Errorf("dns.max-udp-size must be > 0")
	}
	if c.XDP.Enabled {
		if c.XDP.Interface == "" {
			return fmt.Errorf("xdp.iface is required when xdp.enabled=true")
		}
		if c.XDP.ObjectPath == "" {
			return fmt.Errorf("xdp.object is required when xdp.enabled=true")
		}
		if c.XDP.ListenPort == 0 {
			return fmt.Errorf("xdp.listen-port is required when xdp.enabled=true")
		}
	}
	if c.DNS.TTL <= 0 {
		return fmt.Errorf("dns.ttl must be > 0")
	}
	if c.LoadGen.Concurrency <= 0 {
		return fmt.Errorf("loadgen.concurrency must be > 0")
	}
	if c.LoadGen.Duration <= 0 {
		return fmt.Errorf("loadgen.duration must be > 0")
	}
	if c.GRPC.Enabled {
		if err := validateListenAddr("grpc.listen", c.GRPC.ListenAddr); err != nil {
			return err
		}
	}
	if c.Profiler.Enabled {
		if err := validateListenAddr("profiler.listen", c.Profiler.ListenAddr); err != nil {
			return err
		}
	}
	if c.Metrics.Enabled {
		if err := validateListenAddr("metrics.listen", c.Metrics.ListenAddr); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) DNSListen() string {
	return c.DNS.ListenAddr
}

func (c Config) GRPCListen() string {
	return c.GRPC.ListenAddr
}

func getenvString(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func getenvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return v
}

func splitCSV(raw string) []string {
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func validateListenAddr(field, addr string) error {
	if addr == "" {
		return fmt.Errorf("%s is required", field)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("%s must be host:port, got %q: %w", field, addr, err)
	}
	return nil
}
