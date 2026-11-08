//go:build windows

package pipeline

import (
	"errors"
	"syscall"
	"unsafe"
)

func processResources(path string) (rss, free uint64, measured bool, err error) {
	// These OS structures are used only for resource sampling, never serialized.
	type counters struct {
		CB, PageFaultCount                                 uint32
		PeakWorkingSetSize, WorkingSetSize                 uintptr
		QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage       uintptr
		QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage uintptr
		PagefileUsage, PeakPagefileUsage                   uintptr
	}
	kernel := syscall.NewLazyDLL("kernel32.dll")
	psapi := syscall.NewLazyDLL("psapi.dll")
	process, e := syscall.GetCurrentProcess()
	if e != nil {
		return 0, 0, false, e
	}
	c := counters{}
	c.CB = uint32(unsafe.Sizeof(c))
	ok, _, _ := psapi.NewProc("GetProcessMemoryInfo").Call(uintptr(process), uintptr(unsafe.Pointer(&c)), uintptr(c.CB))
	if ok == 0 {
		return 0, 0, false, errors.New("cannot sample compiler RSS")
	}
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return 0, 0, false, e
	}
	ok, _, _ = kernel.NewProc("GetDiskFreeSpaceExW").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0)
	if ok == 0 {
		return 0, 0, false, errors.New("cannot sample compiler physical free space")
	}
	return uint64(c.PeakWorkingSetSize), free, true, nil
}
