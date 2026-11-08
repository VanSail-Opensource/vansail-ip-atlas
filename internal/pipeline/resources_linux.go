//go:build linux

package pipeline

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func processResources(path string) (rss, free uint64, measured bool, err error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, 0, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmHWM:" && fields[2] == "kB" {
			kb, e := strconv.ParseUint(fields[1], 10, 64)
			if e != nil {
				return 0, 0, false, e
			}
			rss = kb * 1024
			measured = true
		}
	}
	if !measured {
		return 0, 0, false, errors.New("cannot sample compiler RSS")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, false, err
	}
	return rss, stat.Bavail * uint64(stat.Bsize), true, nil
}
