//go:build !linux && !windows

package intelligence

import "errors"

func recordFreeSpace(string) (uint64, error) {
	return 0, errors.New("private state free-space measurement unsupported")
}
func recordPeakRSS() (uint64, error) { return 0, errors.New("process RSS measurement unsupported") }
