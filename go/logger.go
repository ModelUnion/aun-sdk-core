package aun

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// AUNLogger 统一日志记录器，格式：
//
//	[yyyy-mm-dd HH:mm:ss.SSS][LEVEL][module][aun_path=...][device_id=...] message
//
// 行为矩阵：
//
//	debug=OFF：ERROR/WARN/INFO 输出到控制台，DEBUG 不输出，无文件日志
//	debug=ON ：全部级别输出到控制台 + 写入文件日志
//
// 控制台分流：ERROR/WARN → stderr，INFO/DEBUG → stdout
// 文件路径：{aun_path}/logs/go-sdk-{yyyy-mm-dd}.log，按天切割，启动清理 7 天前旧文件
// 全局配置 ~/.aun/log.ini：debug / level 覆盖代码参数，日志目录强制 ~/.aun/logs/
type AUNLogger struct {
	mu            sync.Mutex
	debug         bool
	minLevel      int
	logDir        string
	aunPath       string
	deviceID      string
	aid           string
	cleanupTicker *time.Ticker
	cleanupStop   chan struct{}
	mkdirFailed   bool
	fileWriteFail bool
	cleanupFailed bool
	closed        bool
}

type logLevel int

const (
	levelDebug logLevel = 0
	levelInfo  logLevel = 1
	levelWarn  logLevel = 2
	levelError logLevel = 3
)

var levelOrder = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
}

var levelName = map[logLevel]string{
	levelDebug: "DEBUG",
	levelInfo:  "INFO",
	levelWarn:  "WARN",
	levelError: "ERROR",
}

const (
	logFilePrefix = "go-sdk-"
	logFileSuffix = ".log"
	retainDays    = 7
	cleanupPeriod = 24 * time.Hour
)

// NewAUNLogger 创建 Logger。debug 为代码层开关，aunPath 为 AUN 数据根目录（为空时取 ~/.aun）。
// 若 ~/.aun/log.ini 存在，ini 中的配置会覆盖传入值，日志目录强制为 ~/.aun/logs/。
func NewAUNLogger(debug bool, aunPath string) *AUNLogger {
	home, _ := os.UserHomeDir()
	ini := parseLogINI(filepath.Join(home, ".aun", "log.ini"))

	var (
		effectiveDebug bool
		levelStr       string
		logDir         string
	)
	base := strings.TrimSpace(aunPath)
	if base == "" {
		base = filepath.Join(home, ".aun")
	}
	if ini != nil {
		effectiveDebug = parseBool(ini["debug"])
		logDir = filepath.Join(home, ".aun", "logs")
		if v, ok := ini["level"]; ok && v != "" {
			levelStr = v
		} else if effectiveDebug {
			levelStr = "debug"
		} else {
			levelStr = "info"
		}
	} else {
		effectiveDebug = debug
		logDir = filepath.Join(base, "logs")
		if effectiveDebug {
			levelStr = "debug"
		} else {
			levelStr = "info"
		}
	}

	lvl, ok := levelOrder[levelStr]
	if !ok {
		lvl = levelOrder["info"]
	}

	l := &AUNLogger{
		debug:    effectiveDebug,
		minLevel: lvl,
		logDir:   logDir,
		aunPath:  base,
		deviceID: "-",
	}
	if effectiveDebug {
		l.ensureLogDir()
		l.cleanupOldLogs()
		l.startCleanupTicker()
	}
	registerPkgLogger(l)
	return l
}

// For 返回绑定了 module 名的子 logger。
func (l *AUNLogger) For(module string) *ModuleLogger {
	return &ModuleLogger{owner: l, module: module}
}

// Debug 返回 logger 的 debug 开关状态。
func (l *AUNLogger) Debug() bool {
	return l.debug
}

// BindAID 将 AID 附加到所有日志行末尾，便于多实例区分。
func (l *AUNLogger) BindAID(aid string) {
	l.mu.Lock()
	l.aid = aid
	l.mu.Unlock()
}

// BindDeviceID 将当前实例 device_id 附加到所有日志行。
func (l *AUNLogger) BindDeviceID(deviceID string) {
	l.mu.Lock()
	l.deviceID = strings.TrimSpace(deviceID)
	if l.deviceID == "" {
		l.deviceID = "-"
	}
	l.mu.Unlock()
}

// Close 停止定时清理任务。
func (l *AUNLogger) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	stop := l.cleanupStop
	ticker := l.cleanupTicker
	l.cleanupStop = nil
	l.cleanupTicker = nil
	l.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if ticker != nil {
		ticker.Stop()
	}
}

func (l *AUNLogger) emit(level logLevel, module, msg string, err error) {
	l.mu.Lock()
	if l.minLevel > int(level) {
		l.mu.Unlock()
		return
	}
	if level == levelDebug && !l.debug {
		l.mu.Unlock()
		return
	}
	debugOn := l.debug
	aid := l.aid
	dir := l.logDir
	aunPath := l.aunPath
	deviceID := l.deviceID
	l.mu.Unlock()

	now := time.Now()
	ts := formatTimestamp(now)
	aidSuffix := ""
	if aid != "" {
		aidSuffix = " [" + aid + "]"
	}
	if strings.TrimSpace(aunPath) == "" {
		aunPath = "-"
	}
	if strings.TrimSpace(deviceID) == "" {
		deviceID = "-"
	}
	line := fmt.Sprintf("[%s][%s][%s][aun_path=%s][device_id=%s] %s%s", ts, levelName[level], module, aunPath, deviceID, msg, aidSuffix)

	writeConsole(level, line)
	if debugOn {
		l.writeFile(dir, now, level, line, err)
	}
}

func writeConsole(level logLevel, line string) {
	target := os.Stdout
	if level == levelError || level == levelWarn {
		target = os.Stderr
	}
	fmt.Fprintln(target, line)
}

func (l *AUNLogger) writeFile(dir string, now time.Time, level logLevel, line string, err error) {
	path := filepath.Join(dir, logFilePrefix+now.Format("2006-01-02")+logFileSuffix)
	payload := line + "\n"
	if level == levelError && err != nil {
		payload += "  Traceback:\n" + indentStack(fmt.Sprintf("%+v", err), "    ") + "\n"
		if stack := stackIfPanic(); stack != "" {
			payload += indentStack(stack, "    ") + "\n"
		}
	}
	l.writeLineLocked(path, payload)
}

func (l *AUNLogger) writeLineLocked(path, payload string) {
	f, openErr := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if openErr != nil {
		l.reportFileFail("failed to open log file", openErr)
		return
	}
	defer f.Close()
	lockFile(f)
	defer unlockFile(f)
	if _, writeErr := f.WriteString(payload); writeErr != nil {
		l.reportFileFail("failed to write log", writeErr)
	}
}

func (l *AUNLogger) reportFileFail(msg string, err error) {
	l.mu.Lock()
	first := !l.fileWriteFail
	l.fileWriteFail = true
	l.mu.Unlock()
	if first {
		fmt.Fprintf(os.Stderr, "[AUNLogger] %s: %v\n", msg, err)
	}
}

func (l *AUNLogger) ensureLogDir() {
	if err := os.MkdirAll(l.logDir, 0o700); err != nil {
		l.mu.Lock()
		first := !l.mkdirFailed
		l.mkdirFailed = true
		l.mu.Unlock()
		if first {
			fmt.Fprintf(os.Stderr, "[AUNLogger] failed to create log directory: %v\n", err)
		}
	}
}

func (l *AUNLogger) cleanupOldLogs() {
	cutoff := time.Now().AddDate(0, 0, -retainDays)
	entries, err := os.ReadDir(l.logDir)
	if err != nil {
		l.reportCleanupFail("failed to scan log directory", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, logFilePrefix) || !strings.HasSuffix(name, logFileSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(l.logDir, name)); err != nil {
				l.reportCleanupFail("failed to delete old log", err)
			}
		}
	}
}

func (l *AUNLogger) reportCleanupFail(msg string, err error) {
	l.mu.Lock()
	first := !l.cleanupFailed
	l.cleanupFailed = true
	l.mu.Unlock()
	if first {
		fmt.Fprintf(os.Stderr, "[AUNLogger] %s: %v\n", msg, err)
	}
}

func (l *AUNLogger) startCleanupTicker() {
	l.cleanupTicker = time.NewTicker(cleanupPeriod)
	l.cleanupStop = make(chan struct{})
	ticker := l.cleanupTicker
	stop := l.cleanupStop
	go func() {
		for {
			select {
			case <-ticker.C:
				l.cleanupOldLogs()
			case <-stop:
				return
			}
		}
	}()
}

func formatTimestamp(t time.Time) string {
	return t.Format("2006-01-02 15:04:05") + fmt.Sprintf(".%03d", t.Nanosecond()/1_000_000)
}

func indentStack(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func stackIfPanic() string {
	// 仅在 recover 路径下调用方显式传入时启用；此处保留扩展点。
	_ = debug.Stack
	return ""
}

func parseLogINI(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.ToLower(strings.TrimSpace(line[idx+1:]))
		out[key] = val
	}
	return out
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// ModuleLogger 业务模块使用的 logger 句柄，绑定固定 module 名。
type ModuleLogger struct {
	owner  *AUNLogger
	module string
}

// Error 输出 ERROR 日志（仅消息）。
func (m *ModuleLogger) Error(format string, args ...any) {
	if m == nil || m.owner == nil {
		return
	}
	m.owner.emit(levelError, m.module, fmt.Sprintf(format, args...), nil)
}

// ErrorE 输出 ERROR 日志并在文件日志中追加异常详情。
func (m *ModuleLogger) ErrorE(err error, format string, args ...any) {
	if m == nil || m.owner == nil {
		return
	}
	m.owner.emit(levelError, m.module, fmt.Sprintf(format, args...), err)
}

// Warn 输出 WARN 日志。
func (m *ModuleLogger) Warn(format string, args ...any) {
	if m == nil || m.owner == nil {
		return
	}
	m.owner.emit(levelWarn, m.module, fmt.Sprintf(format, args...), nil)
}

// Info 输出 INFO 日志。
func (m *ModuleLogger) Info(format string, args ...any) {
	if m == nil || m.owner == nil {
		return
	}
	m.owner.emit(levelInfo, m.module, fmt.Sprintf(format, args...), nil)
}

// Debug 输出 DEBUG 日志（debug=OFF 时不输出到任何目标）。
func (m *ModuleLogger) Debug(format string, args ...any) {
	if m == nil || m.owner == nil {
		return
	}
	m.owner.emit(levelDebug, m.module, fmt.Sprintf(format, args...), nil)
}

// NullModuleLogger 返回一个静默 logger，用于不需要日志输出的场景（测试、可选字段）。
func NullModuleLogger() *ModuleLogger {
	return &ModuleLogger{}
}

// initAidOrDash 用于 banner 日志：空 AID 显示为 "-"。
func initAidOrDash(aid string) string {
	if aid == "" {
		return "-"
	}
	return aid
}

// 包级 fallback logger：某些无 client 接收器的辅助函数通过 pkgLogXxx() 获取 logger。
// 第一个 NewAUNLogger 调用会注册为包级默认；未注册时返回 NullModuleLogger。
var (
	pkgLoggerMu sync.Mutex
	pkgLogger   *AUNLogger
)

func registerPkgLogger(l *AUNLogger) {
	pkgLoggerMu.Lock()
	if pkgLogger == nil {
		pkgLogger = l
	}
	pkgLoggerMu.Unlock()
}

func pkgLogEG() *ModuleLogger {
	return pkgLogFor("aun_core.e2ee-group")
}

func pkgLogClient() *ModuleLogger {
	return pkgLogFor("aun_core.client")
}

func pkgLogTransport() *ModuleLogger {
	return pkgLogFor("aun_core.transport")
}

func pkgLogAuth() *ModuleLogger {
	return pkgLogFor("aun_core.auth")
}

func pkgLogE2EE() *ModuleLogger {
	return pkgLogFor("aun_core.e2ee")
}

func pkgLogKeystore() *ModuleLogger {
	return pkgLogFor("aun_core.keystore")
}

func pkgLogSecretStore() *ModuleLogger {
	return pkgLogFor("aun_core.secret-store")
}

func pkgLogDiscovery() *ModuleLogger {
	return pkgLogFor("aun_core.discovery")
}

func pkgLogFor(module string) *ModuleLogger {
	pkgLoggerMu.Lock()
	defer pkgLoggerMu.Unlock()
	if pkgLogger == nil {
		return NullModuleLogger()
	}
	return pkgLogger.For(module)
}
