package logging

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"ebpf-multi-protocol-network-monitor/internal/config"
)

// New builds a slog logger from project logging config.
//
// Output accepts:
//   - "stderr"
//   - "stdout"
//   - a filesystem path for file output
func New(cfg config.LoggingConfig) (*slog.Logger, io.Closer, error) {
	writer, closer, err := openWriter(cfg.Output)
	if err != nil {
		return nil, nil, err
	}

	logger, err := NewWithWriter(cfg, writer)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, err
	}

	return logger, closer, nil
}

// NewWithWriter builds a logger against the supplied writer.
// It is intended for tests and controlled outputs.
func NewWithWriter(cfg config.LoggingConfig, w io.Writer) (*slog.Logger, error) {
	if w == nil {
		return nil, errors.New("writer is nil")
	}

	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddCaller,
	}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "", "text":
		handler = slog.NewTextHandler(w, opts)
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("unsupported log format %q", cfg.Format)
	}

	return slog.New(handler), nil
}

func openWriter(output string) (io.Writer, io.Closer, error) {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "", "stderr":
		return os.Stderr, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, nil, err
		}
		return f, f, nil
	}
}

func parseLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", raw)
	}
}
