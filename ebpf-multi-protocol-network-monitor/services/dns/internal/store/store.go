package store

import (
	"strings"
	"time"

	"ebpf-multi-protocol-network-monitor/services/dns/api"
)

const defaultTTL = 60 * time.Second

// Store 是一个只读的静态权威记录库。
//
// 第一版只把预置的 A 记录放在内存里，便于 DNS baseline 直接查到
// 可用于回包的结构化记录。
type Store struct {
	records map[string]api.Record
}

// New 基于输入记录创建一个只读 store。
//
// 这里会复制输入并做规范化，避免外部修改影响内部索引。
func New(records ...api.Record) *Store {
	data := make(map[string]api.Record, len(records))
	for _, record := range records {
		if record.Type != api.QTypeA {
			continue
		}

		canonical := canonicalRecord(record)
		data[key(canonical.Name, canonical.Type)] = canonical
	}

	return &Store{records: data}
}

// Default 返回一个带有 3 条 demo A 记录的默认 store。
//
// 这组记录用于本地联调和 baseline 测试。
func Default() *Store {
	return New(
		api.Record{
			Name:  "hot.example.com",
			Type:  api.QTypeA,
			Class: api.ClassIN,
			TTL:   defaultTTL,
			Value: "1.1.1.1",
		},
		api.Record{
			Name:  "api.example.com",
			Type:  api.QTypeA,
			Class: api.ClassIN,
			TTL:   defaultTTL,
			Value: "10.0.0.8",
		},
		api.Record{
			Name:  "www.example.com",
			Type:  api.QTypeA,
			Class: api.ClassIN,
			TTL:   defaultTTL,
			Value: "93.184.216.34",
		},
	)
}

// Lookup 按 QName + QType 查找一条记录。
//
// 第一版只支持 A 记录；对于未知域名、非 A 类型或空 store，返回 miss。
func (s *Store) Lookup(qname string, qtype api.QType) (api.Record, bool) {
	if s == nil || qtype != api.QTypeA {
		return api.Record{}, false
	}

	record, ok := s.records[key(qname, qtype)]
	if !ok {
		return api.Record{}, false
	}

	return canonicalRecord(record), true
}

// Records 返回 store 中当前保存的全部记录副本。
//
// 这只用于用户态控制面预热热点缓存，不暴露可写引用。
func (s *Store) Records() []api.Record {
	if s == nil || len(s.records) == 0 {
		return nil
	}

	out := make([]api.Record, 0, len(s.records))
	for _, record := range s.records {
		out = append(out, canonicalRecord(record))
	}
	return out
}

func key(qname string, qtype api.QType) string {
	return normalizeName(qname) + ":" + qtypeToken(qtype)
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(name)), ".")
}

func qtypeToken(qtype api.QType) string {
	switch qtype {
	case api.QTypeA:
		return "A"
	default:
		return ""
	}
}

func canonicalRecord(record api.Record) api.Record {
	record.Name = normalizeName(record.Name)
	if record.Type == 0 {
		record.Type = api.QTypeA
	}
	if record.Class == 0 {
		record.Class = api.ClassIN
	}
	return record
}
