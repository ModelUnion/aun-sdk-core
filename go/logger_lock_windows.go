//go:build windows

package aun

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32    = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = modkernel32.NewProc("LockFileEx")
	procUnlockFile = modkernel32.NewProc("UnlockFile")
)

const lockfileExclusiveLock = 0x00000002

func lockFile(f *os.File) {
	var overlapped syscall.Overlapped
	h := syscall.Handle(f.Fd())
	// LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped)
	procLockFileEx.Call(
		uintptr(h),
		lockfileExclusiveLock,
		0,
		1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
}

func unlockFile(f *os.File) {
	h := syscall.Handle(f.Fd())
	// UnlockFile(handle, 0, 0, 1, 0)
	procUnlockFile.Call(uintptr(h), 0, 0, 1, 0)
}
