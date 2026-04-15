package cache_manager

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"ebpf-multi-protocol-network-monitor/services/dns/api"
)

const hotQNameLen = 128

// HotKey matches the BPF dns_hot_key layout.
type HotKey struct {
	QName  [hotQNameLen]byte
	QType  uint16
	QClass uint16
}

// HotVal matches the BPF dns_hot_val layout.
type HotVal struct {
	IPv4      uint32
	TTL       uint32
	ExpiresNs uint64
	Hits      uint64
}

// Manager writes and prunes hot entries in the XDP hot map.
type Manager struct {
	hotMap *ebpf.Map
}

// New creates a hot map manager.
func New(hotMap *ebpf.Map) *Manager {
	return &Manager{hotMap: hotMap}
}

// Seed writes a batch of records into the hot map.
func (m *Manager) Seed(records []api.Record) error {
	if m == nil || m.hotMap == nil {
		return errors.New("cache_manager: hot map is nil")
	}

	now := time.Now()
	for _, record := range records {
		if err := m.Promote(record, now); err != nil {
			return err
		}
	}
	return nil
}

// Promote inserts or refreshes a single record in the hot map.
func (m *Manager) Promote(record api.Record, now time.Time) error {
	if m == nil || m.hotMap == nil {
		return errors.New("cache_manager: hot map is nil")
	}
	if record.Type != api.QTypeA {
		return nil
	}

	key, err := hotKeyFromRecord(record)
	if err != nil {
		return err
	}
	val, err := hotValFromRecord(record, now)
	if err != nil {
		return err
	}

	if err := m.hotMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("cache_manager: update hot map: %w", err)
	}
	return nil
}

// SweepExpired removes expired hot entries.
func (m *Manager) SweepExpired(now time.Time) (int, error) {
	if m == nil || m.hotMap == nil {
		return 0, errors.New("cache_manager: hot map is nil")
	}

	iter := m.hotMap.Iterate()
	var key HotKey
	var val HotVal
	removed := 0
	for iter.Next(&key, &val) {
		if val.ExpiresNs != 0 && now.UnixNano() >= int64(val.ExpiresNs) {
			if err := m.hotMap.Delete(&key); err != nil {
				return removed, fmt.Errorf("cache_manager: delete expired hot entry: %w", err)
			}
			removed++
		}
	}
	if err := iter.Err(); err != nil {
		return removed, fmt.Errorf("cache_manager: iterate hot map: %w", err)
	}
	return removed, nil
}

func hotKeyFromRecord(record api.Record) (HotKey, error) {
	name := normalizeQName(record.Name)
	if name == "" {
		return HotKey{}, errors.New("cache_manager: empty qname")
	}

	var key HotKey
	copy(key.QName[:], name)
	key.QType = uint16(record.Type)
	key.QClass = uint16(record.Class)
	return key, nil
}

func hotValFromRecord(record api.Record, now time.Time) (HotVal, error) {
	ip := net.ParseIP(record.Value)
	if ip == nil {
		return HotVal{}, fmt.Errorf("cache_manager: invalid ipv4 %q", record.Value)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return HotVal{}, fmt.Errorf("cache_manager: non-ipv4 value %q", record.Value)
	}

	ttl := uint32((record.TTL + time.Second - 1) / time.Second)
	if ttl == 0 {
		ttl = 1
	}

	return HotVal{
		IPv4:      binary.BigEndian.Uint32(ip4),
		TTL:       ttl,
		ExpiresNs: uint64(now.Add(record.TTL).UnixNano()),
		Hits:      0,
	}, nil
}

func normalizeQName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(name)), ".")
}
