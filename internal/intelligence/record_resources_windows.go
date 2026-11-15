//go:build windows

package intelligence

import (
	"errors"
	"syscall"
	"unsafe"
)

// The pointer is used only at the OS boundary, never for record storage.
func recordFreeSpace(path string) (uint64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var free uint64
	ok, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0)
	if ok == 0 {
		return 0, errors.New("cannot measure private state free space")
	}
	return free, nil
}
func recordPeakRSS() (uint64, error) {
	type counters struct {
		CB, PageFaultCount                                                                                                                                                     uint32
		PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage uintptr
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	c := counters{}
	c.CB = uint32(unsafe.Sizeof(c))
	ok, _, _ := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(uintptr(process), uintptr(unsafe.Pointer(&c)), uintptr(c.CB))
	if ok == 0 {
		return 0, errors.New("process RSS unavailable")
	}
	return uint64(c.PeakWorkingSetSize), nil
}
