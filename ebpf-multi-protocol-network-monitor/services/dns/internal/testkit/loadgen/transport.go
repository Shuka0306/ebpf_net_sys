package loadgen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type udpTransport struct {
	conn    *net.UDPConn
	target  *net.UDPAddr
	timeout time.Duration
}

// NewUDPTransportFactory creates a transport factory that dials the target via UDP.
func NewUDPTransportFactory(target string, timeout time.Duration) (TransportFactory, error) {
	if target == "" {
		return nil, errors.New("loadgen: target is required")
	}
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("loadgen: resolve target: %w", err)
	}
	if timeout <= 0 {
		timeout = time.Second
	}

	return func(workerID int) (Transport, error) {
		_ = workerID
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return nil, fmt.Errorf("loadgen: dial udp: %w", err)
		}
		return &udpTransport{
			conn:    conn,
			target:  addr,
			timeout: timeout,
		}, nil
	}, nil
}

func (t *udpTransport) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	if t == nil || t.conn == nil {
		return nil, errors.New("loadgen: transport is closed")
	}

	deadline := time.Now().Add(t.timeout)
	if ctx != nil {
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	if err := t.conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("loadgen: set deadline: %w", err)
	}

	if _, err := t.conn.Write(req); err != nil {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("loadgen: write udp: %w", err)
	}

	buf := make([]byte, 4*1024)
	n, err := t.conn.Read(buf)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])
	return resp, nil
}

func (t *udpTransport) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}
