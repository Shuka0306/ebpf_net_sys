package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/internal/metrics"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/cache"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/dnsmsg"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/store"
)

const defaultReadTimeout = 250 * time.Millisecond

// Server 负责 DNS baseline 的 UDP 请求处理。
type Server struct {
	cfg     config.DNSConfig
	store   *store.Store
	cache   *cache.Cache
	metrics *metrics.Registry
	logger  *slog.Logger
}

// New 创建一个 DNS baseline server。
func New(cfg config.DNSConfig, st *store.Store, c *cache.Cache, reg *metrics.Registry, logger *slog.Logger) *Server {
	if st == nil {
		st = store.Default()
	}
	if reg == nil {
		reg = metrics.NewRegistry()
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Server{
		cfg:     cfg,
		store:   st,
		cache:   c,
		metrics: reg,
		logger:  logger,
	}
}

// HandlePacket 处理一个 DNS UDP 请求包并返回响应。
//
// 返回值中的 bool 表示是否需要把响应写回网络：
//   - true: 成功生成了响应
//   - false: 报文非法、被丢弃或内部编码失败
func (s *Server) HandlePacket(raw []byte) ([]byte, bool) {
	start := time.Now()

	req, err := dnsmsg.ParseQuery(raw)
	if err != nil {
		s.recordParseDrop(time.Since(start))
		return nil, false
	}

	s.metrics.IncRequest()

	resp, rcode, err := s.resolve(req)
	s.metrics.ObserveLatency(time.Since(start))
	if err != nil {
		s.metrics.IncDroppedPacket()
		s.logger.Error("dns resolve failed", "error", err)
		return nil, false
	}
	s.metrics.RecordRCode(rcodeName(rcode))

	return resp, true
}

// ListenAndServe 绑定 UDP 监听并开始处理请求。
func (s *Server) ListenAndServe(ctx context.Context) error {
	conn, err := net.ListenPacket(s.cfg.Network, s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s.logger.Info("dns server listening", "network", s.cfg.Network, "addr", s.cfg.ListenAddr)
	return s.ServePacketConn(ctx, conn)
}

// ServePacketConn 在一个已经创建好的 PacketConn 上运行请求循环。
func (s *Server) ServePacketConn(ctx context.Context, conn net.PacketConn) error {
	if conn == nil {
		return errors.New("packet conn is nil")
	}

	bufSize := s.cfg.MaxUDPSize
	if bufSize < 512 {
		bufSize = 512
	}
	buf := make([]byte, bufSize)

	readTimeout := s.cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}

	for {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return err
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])

		resp, ok := s.HandlePacket(raw)
		if !ok || len(resp) == 0 {
			continue
		}
		if _, err := conn.WriteTo(resp, addr); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

func (s *Server) resolve(req *dnsmsg.Message) ([]byte, dnsmsg.RCode, error) {
	q := req.Questions[0]
	useCache := s.cfg.EnableCache && s.cache != nil

	if useCache {
		key := cache.Key(q.QName, "A")
		if cached, ok := s.cache.Get(key); ok {
			s.metrics.IncCacheHit()
			resp, err := dnsmsg.BuildAResponse(req, cached.Value, cached.TTL)
			return resp, dnsmsg.RCodeNoError, err
		}
		s.metrics.IncCacheMiss()
	}

	record, ok := s.store.Lookup(q.QName, q.QType)
	if !ok {
		s.metrics.IncStoreMiss()
		resp, err := dnsmsg.EncodeResponse(req, nil, dnsmsg.RCodeNameError)
		return resp, dnsmsg.RCodeNameError, err
	}

	s.metrics.IncStoreHit()
	if useCache {
		s.cache.Set(cache.Key(q.QName, "A"), cache.Record{
			QName: record.Name,
			QType: "A",
			Value: record.Value,
		}, record.TTL)
	}

	resp, err := dnsmsg.EncodeResponse(req, []dnsmsg.Record{record}, dnsmsg.RCodeNoError)
	return resp, dnsmsg.RCodeNoError, err
}

func (s *Server) recordParseDrop(d time.Duration) {
	s.metrics.IncParseError()
	s.metrics.IncDroppedPacket()
	s.metrics.ObserveLatency(d)
}

func rcodeName(code dnsmsg.RCode) string {
	switch code {
	case dnsmsg.RCodeNoError:
		return "NOERROR"
	case dnsmsg.RCodeFormatError:
		return "FORMERR"
	case dnsmsg.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmsg.RCodeNameError:
		return "NXDOMAIN"
	case dnsmsg.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmsg.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", code)
	}
}
