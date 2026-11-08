//go:build !windows

package intelligence

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func latencyClock() func() int64 {
	start := time.Now()
	return func() int64 { return time.Since(start).Nanoseconds() }
}

func peakRSS() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmHWM:" && fields[2] == "kB" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024, err == nil
		}
	}
	return 0, false
}
