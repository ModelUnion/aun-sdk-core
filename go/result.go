package aun

// Result 统一结果包装，与 Python/TS/JS SDK 对齐。
type Result[T any] struct {
	Ok    bool
	Data  T
	Error *ResultError
}

// ResultError 携带错误码、消息和可选原因。
type ResultError struct {
	Code    string
	Message string
	Cause   error
}

// ResultOk 构造成功结果。
func ResultOk[T any](data T) Result[T] {
	return Result[T]{Ok: true, Data: data}
}

// ResultErr 构造失败结果。
func ResultErr[T any](code, message string, cause ...error) Result[T] {
	var c error
	if len(cause) > 0 {
		c = cause[0]
	}
	return Result[T]{Ok: false, Error: &ResultError{Code: code, Message: message, Cause: c}}
}
