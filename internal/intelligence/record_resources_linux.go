//go:build linux

package intelligence

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func recordFreeSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
func recordPeakRSS() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmHWM:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024, err
		}
	}
	return 0, errors.New("process RSS unavailable")
}
