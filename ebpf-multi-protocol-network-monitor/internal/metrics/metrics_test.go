package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistryCounts(t *testing.T) {
	r := NewRegistry()

	r.IncRequest()
	r.IncCacheHit()
	r.IncCacheMiss()
	r.IncStoreHit()
	r.IncStoreMiss()
	r.IncParseError()
	r.IncDroppedPacket()
	r.ObserveLatency(150 * time.Millisecond)
	r.RecordRCode("NOERROR")
	r.RecordRCode("NXDOMAIN")

	snap := r.Snapshot()
	if snap.Requests != 1 {
		t.Fatalf("unexpected requests: %d", snap.Requests)
	}
	if snap.CacheHits != 1 || snap.CacheMisses != 1 {
		t.Fatalf("unexpected cache counts: %+v", snap)
	}
	if snap.StoreHits != 1 || snap.StoreMisses != 1 {
		t.Fatalf("unexpected store counts: %+v", snap)
	}
	if snap.ParseErrors != 1 || snap.DroppedPackets != 1 {
		t.Fatalf("unexpected parse/drop counts: %+v", snap)
	}
	if snap.TotalLatency != 150*time.Millisecond {
		t.Fatalf("unexpected latency: %s", snap.TotalLatency)
	}
	if snap.RCodes["NOERROR"] != 1 || snap.RCodes["NXDOMAIN"] != 1 {
		t.Fatalf("unexpected rcode counts: %+v", snap.RCodes)
	}
}

func TestRegistryHandler(t *testing.T) {
	r := NewRegistry()
	r.IncRequest()
	r.IncCacheHit()
	r.RecordRCode("NOERROR")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{
		"dns_requests_total 1",
		"dns_cache_hits_total 1",
		"dns_response_rcode_total{rcode=\"NOERROR\"} 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, body)
		}
	}
}
