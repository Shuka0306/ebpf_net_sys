package lifecycle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRunStopsOnCancelAndRunsHooksInReverse(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := New(parent, slog.New(slog.NewTextHandler(io.Discard, nil)))

	started := make(chan struct{})
	var (
		mu    sync.Mutex
		order []string
	)

	mgr.Go("dns", func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return nil
	})
	mgr.AddShutdown("metrics", func(context.Context) error {
		mu.Lock()
		order = append(order, "metrics")
		mu.Unlock()
		return nil
	})
	mgr.AddShutdown("cleanup", func(context.Context) error {
		mu.Lock()
		order = append(order, "cleanup")
		mu.Unlock()
		return nil
	})

	done := make(chan error, 1)
	go func() {
		done <- mgr.Run()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("task did not start")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit")
	}

	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(order, ","); got != "cleanup,metrics" {
		t.Fatalf("unexpected shutdown order: %q", got)
	}
}

func TestRunReturnsTaskErrorAndRunsHooks(t *testing.T) {
	mgr := New(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	hookCalled := false
	mgr.Go("dns", func(context.Context) error {
		return errors.New("boom")
	})
	mgr.AddShutdown("metrics", func(context.Context) error {
		hookCalled = true
		return nil
	})

	err := mgr.Run()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected task error, got %v", err)
	}
	if !hookCalled {
		t.Fatal("expected shutdown hook to run")
	}
}

func TestSignalStopsRun(t *testing.T) {
	mgr := New(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), syscall.SIGTERM)

	started := make(chan struct{})
	mgr.Go("dns", func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return nil
	})

	done := make(chan error, 1)
	go func() {
		done <- mgr.Run()
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("task did not start")
	}

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess failed: %v", err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal failed: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after signal")
	}
}

func TestShutdownHookClosesHTTPServer(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := New(parent, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(ln)
	}()

	mgr.Go("dns", func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})
	mgr.AddShutdown("metrics", func(context.Context) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	})

	done := make(chan error, 1)
	go func() {
		done <- mgr.Run()
	}()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit")
	}

	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP server did not stop")
	}
}
