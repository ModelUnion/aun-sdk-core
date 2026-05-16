package namespace

type ModuleLogger interface {
	Error(format string, args ...any)
	Warn(format string, args ...any)
	Info(format string, args ...any)
	Debug(format string, args ...any)
}

type nullLogger struct{}

func (nullLogger) Error(string, ...any) {}
func (nullLogger) Warn(string, ...any)  {}
func (nullLogger) Info(string, ...any)  {}
func (nullLogger) Debug(string, ...any) {}

var pkgLogger ModuleLogger = nullLogger{}

// SetLogger 由主包在初始化时注入 logger。传 nil 时恢复为静默 logger。
func SetLogger(l ModuleLogger) {
	if l == nil {
		pkgLogger = nullLogger{}
		return
	}
	pkgLogger = l
}

func pkgLogAuth() ModuleLogger {
	return pkgLogger
}
