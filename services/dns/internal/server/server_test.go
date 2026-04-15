package server

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"ebpf-multi-protocol-network-monitor/internal/config"
	"ebpf-multi-protocol-network-monitor/internal/metrics"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/cache"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/dnsmsg"
	"ebpf-multi-protocol-network-monitor/services/dns/internal/store"
)

func TestHandlePacketStoreHitAndCacheFill(t *testing.T) {
	srv, c, reg := newTestServer(t, true)

	resp, ok := srv.HandlePacket(buildQueryPacket(t, 0x1234, "hot.example.com", dnsmsg.QTypeA, dnsmsg.ClassIN))
	if !ok {
		t.Fatalf("expected response")
	}

	msg := parseResponsePacket(t, resp)
	if msg.Header.ID != 0x1234 || !msg.Header.QR || msg.Header.RCode != dnsmsg.RCodeNoError {
		t.Fatalf("unexpected response header: %+v", msg.Header)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("unexpected answers count: %d", len(msg.Answers))
	}
	if msg.Answers[0].Value != "1.1.1.1" {
		t.Fatalf("unexpected answer value: %q", msg.Answers[0].Value)
	}

	if got, ok := c.Get(cache.Key("hot.example.com", "A")); !ok {
		t.Fatalf("expected cache to be populated")
	} else if got.Value != "1.1.1.1" {
		t.Fatalf("unexpected cached value: %q", got.Value)
	}

	snap := reg.Snapshot()
	if snap.Requests != 1 || snap.CacheMisses != 1 || snap.StoreHits != 1 {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}
	if snap.CacheHits != 0 || snap.StoreMisses != 0 || snap.ParseErrors != 0 {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}
	if snap.RCodes["NOERROR"] != 1 {
		t.Fatalf("unexpected rcode counts: %+v", snap.RCodes)
	}
}

func TestHandlePacketCacheHit(t *testing.T) {
	srv, c, reg := newTestServer(t, true)
	c.Set(cache.Key("hot.example.com", "A"), cache.Record{
		QName: "hot.example.com",
		QType: "A",
		Value: "9.9.9.9",
	}, time.Minute)

	resp, ok := srv.HandlePacket(buildQueryPacket(t, 0x2222, "HOT.EXAMPLE.COM.", dnsmsg.QTypeA, dnsmsg.ClassIN))
	if !ok {
		t.Fatalf("expected response")
	}

	msg := parseResponsePacket(t, resp)
	if len(msg.Answers) != 1 || msg.Answers[0].Value != "9.9.9.9" {
		t.Fatalf("unexpected answer: %+v", msg.Answers)
	}

	snap := reg.Snapshot()
	if snap.Requests != 1 || snap.CacheHits != 1 || snap.StoreHits != 0 {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}
}

func TestHandlePacketNXDomain(t *testing.T) {
	srv, _, reg := newTestServer(t, true)

	resp, ok := srv.HandlePacket(buildQueryPacket(t, 0x3333, "missing.example.com", dnsmsg.QTypeA, dnsmsg.ClassIN))
	if !ok {
		t.Fatalf("expected response")
	}

	msg := parseResponsePacket(t, resp)
	if msg.Header.RCode != dnsmsg.RCodeNameError {
		t.Fatalf("unexpected rcode: %d", msg.Header.RCode)
	}
	if len(msg.Answers) != 0 {
		t.Fatalf("unexpected answers count: %d", len(msg.Answers))
	}

	snap := reg.Snapshot()
	if snap.Requests != 1 || snap.StoreMisses != 1 {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}
	if snap.RCodes["NXDOMAIN"] != 1 {
		t.Fatalf("unexpected rcode counts: %+v", snap.RCodes)
	}
}

func TestHandlePacketMalformedDropsPacket(t *testing.T) {
	srv, _, reg := newTestServer(t, true)

	resp, ok := srv.HandlePacket([]byte{0x01, 0x02})
	if ok || resp != nil {
		t.Fatalf("expected packet to be dropped")
	}

	snap := reg.Snapshot()
	if snap.ParseErrors != 1 || snap.DroppedPackets != 1 || snap.Requests != 0 {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}
}

func TestHandlePacketCacheDisabled(t *testing.T) {
	srv, c, reg := newTestServer(t, false)

	resp, ok := srv.HandlePacket(buildQueryPacket(t, 0x4444, "api.example.com", dnsmsg.QTypeA, dnsmsg.ClassIN))
	if !ok {
		t.Fatalf("expected response")
	}

	msg := parseResponsePacket(t, resp)
	if len(msg.Answers) != 1 || msg.Answers[0].Value != "10.0.0.8" {
		t.Fatalf("unexpected answer: %+v", msg.Answers)
	}
	if _, ok := c.Get(cache.Key("api.example.com", "A")); ok {
		t.Fatalf("cache should remain disabled")
	}

	snap := reg.Snapshot()
	if snap.StoreHits != 1 || snap.CacheHits != 0 || snap.CacheMisses != 0 {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}
}

func TestServePacketConnIntegration(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- srv.ServePacketConn(ctx, conn)
	}()

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(buildQueryPacket(t, 0x5555, "www.example.com", dnsmsg.QTypeA, dnsmsg.ClassIN)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	msg := parseResponsePacket(t, buf[:n])
	if msg.Header.ID != 0x5555 || !msg.Header.QR || msg.Header.RCode != dnsmsg.RCodeNoError {
		t.Fatalf("unexpected response header: %+v", msg.Header)
	}
	if len(msg.Answers) != 1 || msg.Answers[0].Value != "93.184.216.34" {
		t.Fatalf("unexpected answer: %+v", msg.Answers)
	}

	cancel()
	_ = conn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServePacketConn returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("ServePacketConn did not stop")
	}
}

func newTestServer(t *testing.T, enableCache bool) (*Server, *cache.Cache, *metrics.Registry) {
	t.Helper()

	cfg := config.Default().DNS
	cfg.EnableCache = enableCache
	reg := metrics.NewRegistry()
	c := cache.New(cfg.CacheCapacity)

	srv := New(cfg, store.Default(), c, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return srv, c, reg
}

func buildQueryPacket(t *testing.T, id uint16, name string, qtype dnsmsg.QType, qclass dnsmsg.Class) []byte {
	t.Helper()

	var buf [12]byte
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	p := append([]byte{}, buf[:]...)
	for _, label := range strings.Split(strings.TrimSuffix(strings.TrimSpace(name), "."), ".") {
		if label == "" {
			t.Fatalf("invalid label in name %q", name)
		}
		if len(label) > 63 {
			t.Fatalf("label too long in name %q", name)
		}
		p = append(p, byte(len(label)))
		p = append(p, label...)
	}
	p = append(p, 0x00)
	p = appendUint16Local(p, uint16(qtype))
	p = appendUint16Local(p, uint16(qclass))
	return p
}

func appendUint16Local(dst []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(dst, b[:]...)
}

func parseResponsePacket(t *testing.T, raw []byte) *dnsmsg.Message {
	t.Helper()

	if len(raw) < 12 {
		t.Fatalf("short packet: %d", len(raw))
	}

	hdr := decodeHeader(raw[:12])
	msg := &dnsmsg.Message{Header: hdr}
	off := 12
	for i := 0; i < int(hdr.QDCount); i++ {
		name, next, err := readNameForTest(raw, off)
		if err != nil {
			t.Fatalf("read question name: %v", err)
		}
		off = next
		if off+4 > len(raw) {
			t.Fatalf("short question section")
		}
		msg.Questions = append(msg.Questions, dnsmsg.Question{
			QName:  name,
			QType:  dnsmsg.QType(binary.BigEndian.Uint16(raw[off : off+2])),
			QClass: dnsmsg.Class(binary.BigEndian.Uint16(raw[off+2 : off+4])),
		})
		off += 4
	}
	for i := 0; i < int(hdr.ANCount); i++ {
		name, next, err := readNameForTest(raw, off)
		if err != nil {
			t.Fatalf("read answer name: %v", err)
		}
		off = next
		if off+10 > len(raw) {
			t.Fatalf("short answer section")
		}
		ttl := time.Duration(binary.BigEndian.Uint32(raw[off+4:off+8])) * time.Second
		rdlen := int(binary.BigEndian.Uint16(raw[off+8 : off+10]))
		off += 10
		if off+rdlen > len(raw) {
			t.Fatalf("short rdata")
		}
		value := ""
		if rdlen == 4 {
			value = net.IP(raw[off : off+4]).String()
		}
		msg.Answers = append(msg.Answers, dnsmsg.Record{
			Name:  name,
			Type:  dnsmsg.QType(binary.BigEndian.Uint16(raw[off-10 : off-8])),
			Class: dnsmsg.Class(binary.BigEndian.Uint16(raw[off-8 : off-6])),
			TTL:   ttl,
			Value: value,
		})
		off += rdlen
	}
	return msg
}

func decodeHeader(raw []byte) dnsmsg.Header {
	flags := binary.BigEndian.Uint16(raw[2:4])
	return dnsmsg.Header{
		ID:      binary.BigEndian.Uint16(raw[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0F),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		Z:       uint8((flags >> 4) & 0x07),
		RCode:   dnsmsg.RCode(flags & 0x0F),
		QDCount: binary.BigEndian.Uint16(raw[4:6]),
		ANCount: binary.BigEndian.Uint16(raw[6:8]),
		NSCount: binary.BigEndian.Uint16(raw[8:10]),
		ARCount: binary.BigEndian.Uint16(raw[10:12]),
	}
}

func readNameForTest(raw []byte, off int) (string, int, error) {
	var labels []string
	next := off
	jumped := false
	var jumpOff int

	for {
		if next >= len(raw) {
			return "", 0, io.ErrUnexpectedEOF
		}
		l := int(raw[next])
		if l == 0 {
			next++
			break
		}
		if l&0xC0 == 0xC0 {
			if next+1 >= len(raw) {
				return "", 0, io.ErrUnexpectedEOF
			}
			ptr := int(binary.BigEndian.Uint16(raw[next:next+2]) & 0x3FFF)
			if !jumped {
				jumpOff = next + 2
				jumped = true
			}
			if ptr >= len(raw) {
				return "", 0, io.ErrUnexpectedEOF
			}
			next = ptr
			continue
		}
		next++
		if next+l > len(raw) {
			return "", 0, io.ErrUnexpectedEOF
		}
		labels = append(labels, string(raw[next:next+l]))
		next += l
	}

	if jumped {
		next = jumpOff
	}
	return strings.Join(labels, "."), next, nil
}
