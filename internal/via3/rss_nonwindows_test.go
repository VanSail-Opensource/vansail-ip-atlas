//go:build !windows

package via3

import (
	"os"
	"strconv"
	"strings"
)

func benchmarkPeakRSS() (uint64, bool) {
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
