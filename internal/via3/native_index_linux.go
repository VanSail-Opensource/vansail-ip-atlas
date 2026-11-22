package via3

import (
	"os"
	"syscall"
)

func checkIndexSpace(file *os.File, growth int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &stat); err != nil {
		return err
	}
	if uint64(stat.Bavail)*uint64(stat.Bsize) < uint64(growth)+(1<<30) {
		return fail("resource_limit")
	}
	return nil
}
