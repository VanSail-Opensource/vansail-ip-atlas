//go:build !windows && !linux

package pipeline

import "errors"

func processResources(string) (uint64, uint64, bool, error) {
	return 0, 0, false, errors.New("compiler resource enforcement requires Windows or Linux")
}
