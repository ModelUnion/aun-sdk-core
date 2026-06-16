package aun

import (
	"fmt"
	"strings"
)

// StorageError 是所有存储操作错误的基类。
type StorageError struct {
	Message string
	Code    any
	Path    string
	Data    any
}

func (e *StorageError) Error() string {
	if e == nil {
		return ""
	}
	if e.Path != "" {
		return fmt.Sprintf("%s: %s", e.Path, e.Message)
	}
	return e.Message
}

// --- 子类型 ---

type StorageNotFoundError struct{ StorageError }
type StorageExistsError struct{ StorageError }
type StorageAccessDeniedError struct{ StorageError }
type StorageConflictError struct{ StorageError }
type StorageQuotaError struct{ StorageError }
type StorageSessionExpiredError struct{ StorageError }
type StorageLoopError struct{ StorageError }
type StorageDanglingSymlinkError struct{ StorageError }
type StorageNotADirectoryError struct{ StorageError }
type StorageIsADirectoryError struct{ StorageError }

// MapStorageError 将任意错误映射为对应的 Storage 子类型。
func MapStorageError(err error, path string) error {
	if err == nil {
		return nil
	}
	if se, ok := err.(*StorageError); ok {
		return se
	}

	msg := err.Error()
	lowered := strings.ToLower(msg)
	code := errorCode(err)
	base := StorageError{Message: msg, Path: path, Data: errorData(err)}

	switch {
	case code == -32008 || code == 404 || code == 4040:
		base.Code = "ENOENT"
		return &StorageNotFoundError{base}
	case code == -32009 || strings.Contains(lowered, "version conflict"):
		base.Code = "ECONFLICT"
		return &StorageConflictError{base}
	case code == -32004 || code == 403 || code == 4030:
		base.Code = "EACCES"
		return &StorageAccessDeniedError{base}
	case code == -32031 || strings.Contains(lowered, "eloop") || strings.Contains(msg, "循环"):
		base.Code = "ELOOP"
		return &StorageLoopError{base}
	case code == -32032 || strings.Contains(lowered, "dangling") || strings.Contains(msg, "软链目标不存在"):
		base.Code = "EDANGLING"
		return &StorageDanglingSymlinkError{base}
	case code == -32010 || code == -32011 || code == -32013 ||
		(strings.Contains(lowered, "session") && strings.Contains(lowered, "expired")):
		base.Code = "ESESSIONEXPIRED"
		return &StorageSessionExpiredError{base}
	case strings.Contains(lowered, "quota") || strings.Contains(msg, "配额"):
		base.Code = "EQUOTA"
		return &StorageQuotaError{base}
	case strings.Contains(lowered, "already exists") || strings.Contains(msg, "已存在"):
		base.Code = "EEXIST"
		return &StorageExistsError{base}
	case strings.Contains(lowered, "not a directory") || strings.Contains(msg, "不是目录"):
		base.Code = "ENOTDIR"
		return &StorageNotADirectoryError{base}
	case strings.Contains(lowered, "is a directory") || strings.Contains(msg, "是目录"):
		base.Code = "EISDIR"
		return &StorageIsADirectoryError{base}
	case code == -32602 && (strings.Contains(msg, "不存在") || strings.Contains(lowered, "not found") || strings.Contains(lowered, "no such")):
		base.Code = "ENOENT"
		return &StorageNotFoundError{base}
	}

	base.Code = "ESTORAGE"
	return &StorageError{Message: msg, Code: "ESTORAGE", Path: path, Data: errorData(err)}
}

// errorCode 从错误中提取 Code 字段（如果有的话）。
func errorCode(err error) int {
	type coder interface{ ErrorCode() int }
	if c, ok := err.(coder); ok {
		return c.ErrorCode()
	}
	// 尝试直接字段访问（通过接口）
	type fieldCoder interface{ GetCode() int }
	if c, ok := err.(fieldCoder); ok {
		return c.GetCode()
	}
	// 反射方式：检查 Code 字段
	type structCoder struct{ Code int }
	if c, ok := err.(interface{ Unwrap() error }); ok {
		return errorCode(c.Unwrap())
	}
	return 0
}

// errorData 从错误中提取 Data 字段。
func errorData(err error) any {
	type dataer interface{ ErrorData() any }
	if d, ok := err.(dataer); ok {
		return d.ErrorData()
	}
	return nil
}
