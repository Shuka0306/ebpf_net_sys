package loadgen

import (
	"context"
	"sync"
	"time"
)

type rateLimiter struct {
	qps  int
	ch   chan struct{}
	stop chan struct{}
	once sync.Once
}

func newRateLimiter(qps int) *rateLimiter {
	rl := &rateLimiter{qps: qps}
	if qps <= 0 {
		return rl
	}

	rl.ch = make(chan struct{}, 1)
	rl.stop = make(chan struct{})
	rl.ch <- struct{}{}

	interval := time.Second / time.Duration(qps)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	go rl.run(interval)
	return rl
}

func (r *rateLimiter) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			select {
			case r.ch <- struct{}{}:
			default:
			}
		}
	}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.qps <= 0 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ch:
		return nil
	}
}

func (r *rateLimiter) Close() {
	if r == nil || r.qps <= 0 {
		return
	}
	r.once.Do(func() {
		close(r.stop)
	})
}
