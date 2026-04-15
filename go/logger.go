package aun

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AUNLogger 多进程安全的调试日志记录器
type AUNLogger struct {
	mu  sync.Mutex
	aid string
}

func newAUNLogger() *AUNLogger {
	dir := logDir()
	_ = os.MkdirAll(dir, 0o700)
	cleanupOldLogs(dir, 3)
	return &AUNLogger{}
}

func (l *AUNLogger) setAID(aid string) {
	l.mu.Lock()
	if aid != "" {
		l.aid = fmt.Sprintf(" [%s]", aid)
	} else {
		l.aid = ""
	}
	l.mu.Unlock()
}

func (l *AUNLogger) log(message string) {
	now := time.Now().UTC()
	tsMs := now.UnixMilli()
	l.mu.Lock()
	aid := l.aid
	l.mu.Unlock()
	line := fmt.Sprintf("%d%s %s\n", tsMs, aid, message)
	path := logPath(now.Format("20060102"))
	writeLogLine(path, line)
}

// Write 实现 io.Writer 接口，使 AUNLogger 可作为 log.SetOutput 的目标
func (l *AUNLogger) Write(p []byte) (n int, err error) {
	now := time.Now().UTC()
	path := logPath(now.Format("20060102"))
	writeLogLine(path, string(p))
	return len(p), nil
}

func logDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aun", "logs")
}

func logPath(dateStr string) string {
	return filepath.Join(logDir(), fmt.Sprintf("go-sdk-%s.log", dateStr))
}

func writeLogLine(path, line string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AUNLogger] 打开日志文件失败: %v\n", err)
		return
	}
	defer f.Close()
	lockFile(f)
	defer unlockFile(f)
	if _, err := f.WriteString(line); err != nil {
		fmt.Fprintf(os.Stderr, "[AUNLogger] 写入日志失败: %v\n", err)
	}
}

func cleanupOldLogs(dir string, keepDays int) {
	cutoff := time.Now().AddDate(0, 0, -keepDays)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
