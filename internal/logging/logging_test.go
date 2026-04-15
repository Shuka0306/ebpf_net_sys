package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebpf-multi-protocol-network-monitor/internal/config"
)

func TestNewWithWriterText(t *testing.T) {
	var buf bytes.Buffer
	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: "stderr",
	}
	logger, err := NewWithWriter(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithWriter failed: %v", err)
	}
	logger.Info("hello", "key", "value")
	got := buf.String()
	if !strings.Contains(got, "msg=hello") {
		t.Fatalf("text log missing message: %q", got)
	}
	if !strings.Contains(got, "key=value") {
		t.Fatalf("text log missing field: %q", got)
	}
}

func TestNewWithWriterJSON(t *testing.T) {
	var buf bytes.Buffer
	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: "stderr",
	}
	logger, err := NewWithWriter(cfg, &buf)
	if err != nil {
		t.Fatalf("NewWithWriter failed: %v", err)
	}
	logger.Info("hello", "key", "value")
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("failed to unmarshal json log: %v", err)
	}
	if entry["msg"] != "hello" {
		t.Fatalf("json log has wrong message: %q", entry["msg"])
	}
	if entry["key"] != "value" {
		t.Fatalf("json log missing field: %q", entry["key"])
	}
}

func TestNewRejectsInvalidFormat(t *testing.T) {
	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "xml",
		Output: "stderr",
	}

	if _, err := NewWithWriter(cfg, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected error for invalid format")
	}
}

func TestNewRejectsInvalidLevel(t *testing.T) {
	cfg := config.LoggingConfig{
		Level:  "trace",
		Format: "text",
		Output: "stderr",
	}

	if _, err := NewWithWriter(cfg, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected error for invalid level")
	}
}

func TestNewFileOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")

	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "text",
		Output: path,
	}

	logger, closer, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	logger.Info("file-log", "k", "v")

	if closer != nil {
		if err := closer.Close(); err != nil {
			t.Fatalf("failed to close log file: %v", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(data), "msg=file-log") {
		t.Fatalf("file log missing message: %q", string(data))
	}
}
