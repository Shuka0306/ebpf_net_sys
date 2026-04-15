package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type task struct {
	name string
	fn   func(context.Context) error
}

type hook struct {
	name string
	fn   func(context.Context) error
}

// Manager 是一个最小的 signal-aware supervisor。
//
// 它只负责三件事：
//   - 启动并等待后台 goroutine
//   - 捕获 SIGINT / SIGTERM 并触发整体退出
//   - 按逆序执行 shutdown hooks
type Manager struct {
	mu      sync.Mutex
	parent  context.Context
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *slog.Logger
	signals []os.Signal
	tasks   []task
	hooks   []hook
	started bool
}

// New 创建一个生命周期管理器。
//
// 如果 parent 或 logger 为空，会退回到可用的默认值。
// signals 为空时默认监听 SIGINT 和 SIGTERM。
func New(parent context.Context, logger *slog.Logger, signals ...os.Signal) *Manager {
	if parent == nil {
		parent = context.Background()
	}
	if logger == nil {
		logger = slog.Default()
	}
	if len(signals) == 0 {
		signals = []os.Signal{os.Interrupt, syscall.SIGTERM}
	}

	ctx, cancel := context.WithCancel(parent)
	return &Manager{
		parent:  parent,
		ctx:     ctx,
		cancel:  cancel,
		logger:  logger,
		signals: append([]os.Signal(nil), signals...),
	}
}

// Context 返回 manager 管理的根 context。
func (m *Manager) Context() context.Context {
	if m == nil {
		return context.Background()
	}
	return m.ctx
}

// Go 注册一个后台任务。
//
// 任务会在 Run 里统一启动，收到退出信号时会得到同一个 context。
func (m *Manager) Go(name string, fn func(context.Context) error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks = append(m.tasks, task{name: name, fn: fn})
}

// AddShutdown 注册一个 shutdown hook。
//
// hooks 会在退出阶段按逆序执行。
func (m *Manager) AddShutdown(name string, fn func(context.Context) error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, hook{name: name, fn: fn})
}

// Run 启动所有任务并阻塞直到收到退出信号、parent 被取消或某个任务返回错误。
//
// 正常关闭时返回 nil；任务错误或 hook 错误会被返回。
func (m *Manager) Run() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("lifecycle: manager already running")
	}
	m.started = true
	tasks := append([]task(nil), m.tasks...)
	hooks := append([]hook(nil), m.hooks...)
	ctx := m.ctx
	cancel := m.cancel
	signals := append([]os.Signal(nil), m.signals...)
	m.mu.Unlock()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, signals...)
	defer signal.Stop(sigCh)

	signalDone := make(chan struct{})
	go func() {
		defer close(signalDone)
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	errCh := make(chan error, len(tasks))
	var wg sync.WaitGroup
	for _, tsk := range tasks {
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			if t.fn == nil {
				return
			}
			if err := t.fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case errCh <- fmt.Errorf("%s: %w", t.name, err):
				default:
				}
				cancel()
			}
		}(tsk)
	}

	var runErr error
	select {
	case runErr = <-errCh:
		cancel()
	case <-ctx.Done():
		select {
		case runErr = <-errCh:
		default:
		}
	}

	cancel()
	wg.Wait()

	for i := len(hooks) - 1; i >= 0; i-- {
		if hooks[i].fn == nil {
			continue
		}
		if err := hooks[i].fn(ctx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("%s: %w", hooks[i].name, err))
		}
	}

	<-signalDone

	if runErr != nil {
		m.logger.Error("lifecycle stopped with error", "error", runErr)
	}

	return runErr
}
