package aun

import "fmt"

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

func MapStorageError(err error, path string) error {
	if err == nil {
		return nil
	}
	if storageErr, ok := err.(*StorageError); ok {
		return storageErr
	}
	return &StorageError{Message: err.Error(), Code: "ESTORAGE", Path: path}
}
