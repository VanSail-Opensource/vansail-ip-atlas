package intelligence

import (
	"syscall"
	"time"
	"unsafe"
)

func latencyClock() func() int64 {
	dll := syscall.NewLazyDLL("kernel32.dll")
	counter := dll.NewProc("QueryPerformanceCounter")
	frequency := dll.NewProc("QueryPerformanceFrequency")
	var base, freq int64
	ok, _, _ := frequency.Call(uintptr(unsafe.Pointer(&freq)))
	if ok == 0 || freq <= 0 {
		start := time.Now()
		return func() int64 { return time.Since(start).Nanoseconds() }
	}
	counter.Call(uintptr(unsafe.Pointer(&base)))
	return func() int64 {
		var value int64
		counter.Call(uintptr(unsafe.Pointer(&value)))
		return int64(float64(value-base) * 1e9 / float64(freq))
	}
}

func peakRSS() (uint64, bool) {
	type processMemoryCounters struct {
		Size, PageFaults                                                                                                 uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile uintptr
	}
	info := processMemoryCounters{}
	info.Size = uint32(unsafe.Sizeof(info))
	getProcess := syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcess")
	process, _, _ := getProcess.Call()
	getMemory := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	ok, _, _ := getMemory.Call(process, uintptr(unsafe.Pointer(&info)), uintptr(info.Size))
	return uint64(info.PeakWorkingSet), ok != 0
}
