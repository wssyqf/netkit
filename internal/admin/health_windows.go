//go:build windows

package admin

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatus = modkernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func init() { sysMem = windowsMemPercent }

// windowsMemPercent 调用 GlobalMemoryStatusEx 取系统内存使用率。
func windowsMemPercent() float64 {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	ret, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return 0
	}
	return clampPct(float64(ms.MemoryLoad))
}
