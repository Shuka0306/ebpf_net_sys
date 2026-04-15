package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSetGet(t *testing.T) {
	c := New(8)
	key := Key("hot.example.com", "a")

	c.Set(key, Record{QName: "hot.example.com", QType: "A", Value: "1.1.1.1"}, time.Minute)

	got, ok := c.Get(key)
	if !ok {
		t.Fatalf("expected cache hit")
	}
	if got.Value != "1.1.1.1" {
		t.Fatalf("unexpected cached value: %q", got.Value)
	}
	if got.QName != "hot.example.com" || got.QType != "A" {
		t.Fatalf("unexpected record: %+v", got)
	}
}

func TestGetMiss(t *testing.T) {
	c := New(8)

	if _, ok := c.Get(Key("missing.example.com", "A")); ok {
		t.Fatalf("expected miss for unknown key")
	}

	stats := c.Stats()
	if stats.Misses != 1 {
		t.Fatalf("unexpected misses: %d", stats.Misses)
	}
}

func TestDelete(t *testing.T) {
	c := New(8)
	key := Key("delete.example.com", "A")
	c.Set(key, Record{QName: "delete.example.com", QType: "A", Value: "2.2.2.2"}, time.Minute)

	c.Delete(key)

	if _, ok := c.Get(key); ok {
		t.Fatalf("expected cache miss after delete")
	}
}

func TestTTLExpiration(t *testing.T) {
	c := New(8)
	c.now = func() time.Time { return time.Unix(100, 0) }
	key := Key("ttl.example.com", "A")

	c.Set(key, Record{QName: "ttl.example.com", QType: "A", Value: "3.3.3.3"}, 10*time.Second)

	c.now = func() time.Time { return time.Unix(111, 0) }
	if _, ok := c.Get(key); ok {
		t.Fatalf("expected expired entry to miss")
	}
}

func TestCleanupExpired(t *testing.T) {
	base := time.Unix(100, 0)
	c := New(8)
	c.now = func() time.Time { return base }

	c.Set(Key("alive.example.com", "A"), Record{QName: "alive.example.com", QType: "A", Value: "4.4.4.4"}, 20*time.Second)
	c.Set(Key("dead.example.com", "A"), Record{QName: "dead.example.com", QType: "A", Value: "5.5.5.5"}, 5*time.Second)

	c.now = func() time.Time { return base.Add(6 * time.Second) }
	removed := c.CleanupExpired()
	if removed != 1 {
		t.Fatalf("expected 1 expired entry removed, got %d", removed)
	}

	if _, ok := c.Get(Key("dead.example.com", "A")); ok {
		t.Fatalf("expired entry should be gone")
	}
	if _, ok := c.Get(Key("alive.example.com", "A")); !ok {
		t.Fatalf("alive entry should still exist")
	}
}

func TestCapacityEviction(t *testing.T) {
	c := New(1)
	c.now = func() time.Time { return time.Unix(100, 0) }

	c.Set(Key("old.example.com", "A"), Record{QName: "old.example.com", QType: "A", Value: "6.6.6.6"}, time.Minute)
	c.now = func() time.Time { return time.Unix(101, 0) }
	c.Set(Key("new.example.com", "A"), Record{QName: "new.example.com", QType: "A", Value: "7.7.7.7"}, time.Minute)

	if _, ok := c.Get(Key("old.example.com", "A")); ok {
		t.Fatalf("old entry should have been evicted")
	}
	if _, ok := c.Get(Key("new.example.com", "A")); !ok {
		t.Fatalf("new entry should remain in cache")
	}
}

func TestKeyNormalization(t *testing.T) {
	got := Key(" Hot.Example.Com. ", " a ")
	want := "hot.example.com:A"
	if got != want {
		t.Fatalf("unexpected key: got %q want %q", got, want)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(4096)
	c.now = time.Now

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := Key(fmt.Sprintf("concurrent-%d-%d.example.com", id, j), "A")
				c.Set(key, Record{QName: "concurrent.example.com", QType: "A", Value: "8.8.8.8"}, time.Minute)
				c.Get(key)
			}
		}(i)
	}
	wg.Wait()
}
