package admission

import (
	"errors"
	"os"
	"path/filepath"
)

const engineLockName = "admission-engine-v1.lock"

func (e *Engine) acquireWorkspace() error {
	directory := filepath.Join(e.workspace, ".atlas-private")
	if os.MkdirAll(directory, 0700) != nil {
		return errors.New("admission workspace unavailable")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("admission workspace escaped root")
	}
	path := filepath.Join(directory, engineLockName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		// A stale lock also fails closed. Never erase it or reset clock history
		// merely because another owner/process is not currently observable.
		return errors.New("admission workspace already locked or unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return errors.New("admission workspace lock invalid")
	}
	e.lock, e.lockInfo, e.lockPath = file, info, path
	return nil
}

// Close waits for in-flight intake operations, then releases this engine's
// workspace-exclusive lifetime lock. It is idempotent. A failed or stale lock
// is never automatically stolen; a closed engine cannot perform further IO.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.lock == nil {
		return nil
	}
	info, statErr := os.Lstat(e.lockPath)
	owned := statErr == nil && info.Mode().IsRegular() && os.SameFile(e.lockInfo, info)
	closeErr := e.lock.Close()
	e.lock = nil
	if !owned || closeErr != nil {
		return errors.New("admission workspace lock ownership or close failed")
	}
	if os.Remove(e.lockPath) != nil {
		return errors.New("admission workspace lock release failed")
	}
	return nil
}
