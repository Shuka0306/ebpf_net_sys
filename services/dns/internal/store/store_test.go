package store

import (
	"testing"
	"time"

	"ebpf-multi-protocol-network-monitor/services/dns/internal/dnsmsg"
)

func TestLookupHit(t *testing.T) {
	s := New(
		dnsmsg.Record{Name: "hot.example.com", Type: dnsmsg.QTypeA, Class: dnsmsg.ClassIN, Value: "1.1.1.1", TTL: 60 * time.Second},
	)

	got, ok := s.Lookup("hot.example.com", dnsmsg.QTypeA)
	if !ok {
		t.Fatalf("expected cache hit")
	}
	if got.Name != "hot.example.com" {
		t.Fatalf("unexpected name: %q", got.Name)
	}
	if got.Value != "1.1.1.1" {
		t.Fatalf("unexpected value: %q", got.Value)
	}
	if got.Type != dnsmsg.QTypeA {
		t.Fatalf("unexpected type: %d", got.Type)
	}
	if got.Class != dnsmsg.ClassIN {
		t.Fatalf("unexpected class: %d", got.Class)
	}
}

func TestLookupNormalization(t *testing.T) {
	s := New(
		dnsmsg.Record{Name: "hot.example.com", Type: dnsmsg.QTypeA, Class: dnsmsg.ClassIN, Value: "1.1.1.1", TTL: 60 * time.Second},
	)

	got, ok := s.Lookup("Hot.Example.Com.", dnsmsg.QTypeA)
	if !ok {
		t.Fatalf("expected cache hit for normalized name")
	}
	if got.Name != "hot.example.com" {
		t.Fatalf("unexpected canonical name: %q", got.Name)
	}
}

func TestLookupMiss(t *testing.T) {
	s := Default()

	if _, ok := s.Lookup("missing.example.com", dnsmsg.QTypeA); ok {
		t.Fatalf("expected miss for unknown record")
	}
}

func TestUnsupportedTypeMiss(t *testing.T) {
	s := Default()

	if _, ok := s.Lookup("hot.example.com", dnsmsg.QType(28)); ok {
		t.Fatalf("expected miss for unsupported type")
	}
}

func TestDefaultSeedRecords(t *testing.T) {
	s := Default()

	cases := []string{
		"hot.example.com",
		"api.example.com",
		"www.example.com",
	}

	for _, name := range cases {
		if _, ok := s.Lookup(name, dnsmsg.QTypeA); !ok {
			t.Fatalf("expected default record to exist: %s", name)
		}
	}
}

func TestDefaultRecordShape(t *testing.T) {
	s := Default()

	got, ok := s.Lookup("hot.example.com", dnsmsg.QTypeA)
	if !ok {
		t.Fatalf("expected default record to exist")
	}
	if got.Name == "" || got.Value == "" || got.Type != dnsmsg.QTypeA || got.Class != dnsmsg.ClassIN {
		t.Fatalf("unexpected record shape: %+v", got)
	}
}

func TestLookupReturnsCanonicalRecord(t *testing.T) {
	s := Default()

	got, ok := s.Lookup("HOT.EXAMPLE.COM.", dnsmsg.QTypeA)
	if !ok {
		t.Fatalf("expected default record to exist")
	}

	req := &dnsmsg.Message{
		Header: dnsmsg.Header{
			ID: 1,
		},
		Questions: []dnsmsg.Question{
			{
				QName:  "hot.example.com",
				QType:  dnsmsg.QTypeA,
				QClass: dnsmsg.ClassIN,
			},
		},
	}

	if _, err := dnsmsg.EncodeResponse(req, []dnsmsg.Record{got}, dnsmsg.RCodeNoError); err != nil {
		t.Fatalf("expected canonical record to be encodable: %v", err)
	}
}
