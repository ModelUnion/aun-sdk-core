package aun

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = orig
	}()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

func TestAUNLoggerIncludesContext(t *testing.T) {
	logger := &AUNLogger{
		debug:    false,
		minLevel: levelOrder["info"],
		logDir:   t.TempDir(),
		aunPath:  "/tmp/aun",
		deviceID: "-",
	}
	logger.BindDeviceID("device-1")

	out := captureStdout(t, func() {
		logger.For("aun_core.client").Info("hello")
	})

	if !strings.Contains(out, "[INFO][aun_core.client][aun_path=/tmp/aun][device_id=device-1] hello") {
		t.Fatalf("log line missing context: %q", out)
	}
}
