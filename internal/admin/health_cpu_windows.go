//go:build windows

package admin

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	procGetProcessTimes   = modkernel32.NewProc("GetProcessTimes")
	procGetCurrentProcess = modkernel32.NewProc("GetCurrentProcess")
)

// processCPUTime 返回当前进程累计占用 CPU 的时间。
func processCPUTime() time.Duration {
	var creation, exit, kernel, user syscall.Filetime
	h, _, _ := procGetCurrentProcess.Call()
	ret, _, _ := procGetProcessTimes.Call(h,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)))
	if ret == 0 {
		return 0
	}
	k := time.Duration(kernel.HighDateTime)<<32 + time.Duration(kernel.LowDateTime)
	u := time.Duration(user.HighDateTime)<<32 + time.Duration(user.LowDateTime)
	// FILETIME 单位为 100ns
	return (k + u) * 100 * time.Nanosecond
}
