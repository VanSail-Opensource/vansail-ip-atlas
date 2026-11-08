package via3

import (
	"syscall"
	"unsafe"
)

func benchmarkPeakRSS() (uint64, bool) {
	// OS-only sampling structure, never part of a serialized VIA3 layout.
	type counters struct {
		Size, PageFaults                                                                                                 uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile uintptr
	}
	info := counters{}
	info.Size = uint32(unsafe.Sizeof(info))
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, false
	}
	ok, _, _ := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(uintptr(process), uintptr(unsafe.Pointer(&info)), uintptr(info.Size))
	return uint64(info.PeakWorkingSet), ok != 0
}
