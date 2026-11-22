//go:build !linux

package via3

import "os"

func checkIndexSpace(*os.File, int64) error { return nil }
