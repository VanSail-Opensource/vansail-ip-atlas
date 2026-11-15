package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const allocationScope = "atlas-go-runtime-allocations-v1"

type processAllocationMetrics struct {
	AllocatedBytes  uint64 `json:"allocated_bytes"`
	AllocationCount uint64 `json:"allocation_count"`
	Command         string `json:"command"`
	ExitCode        int    `json:"exit_code"`
	Invocation      string `json:"invocation"`
	PID             int    `json:"pid"`
	SchemaVersion   uint16 `json:"schema_version"`
	Scope           string `json:"scope"`
}

// Instrument only the Atlas process, including its Go initialization and private
// measurement setup. Node/Python/toolchain allocations are not claimed. The
// counters are sampled before serializing the small measurement record itself.
func runWithProcessMetrics(ctx context.Context, args []string, execute func(context.Context, []string) error) error {
	directory, invocation := os.Getenv("ATLAS_GO_METRICS_DIR"), os.Getenv("ATLAS_GO_METRICS_INVOCATION")
	if directory == "" && invocation == "" {
		return execute(ctx, args)
	}
	if !allocationInvocation(invocation) || !filepath.IsAbs(directory) {
		return errors.New("private allocation measurement controls invalid")
	}
	root, err := os.Getwd()
	if err != nil {
		return errors.New("private allocation measurement workspace unavailable")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil || allocationDirectory(root, directory) != nil {
		return errors.New("private allocation measurement directory invalid")
	}
	err = execute(ctx, args)
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	command := "invalid"
	if len(args) > 0 {
		switch args[0] {
		case "synthetic", "compile-facts", "compile-state", "compile-production", "verify-production", "state-fingerprints", "intake", "lookup", "inspect", "benchmark-state", "corpus":
			command = args[0]
		}
	}
	metrics := processAllocationMetrics{AllocatedBytes: memory.TotalAlloc, AllocationCount: memory.Mallocs, Command: command,
		Invocation: invocation, PID: os.Getpid(), SchemaVersion: 1, Scope: allocationScope}
	if err != nil {
		metrics.ExitCode = 1
	}
	return errors.Join(err, writeProcessAllocationMetrics(root, directory, metrics))
}

func allocationInvocation(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func allocationDirectory(root, directory string) error {
	private := filepath.Join(root, ".atlas-private")
	relative, err := filepath.Rel(private, directory)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("allocation measurement must stay below the private workspace")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("allocation measurement cannot traverse links")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("allocation measurement directory unavailable")
	}
	return nil
}

func writeProcessAllocationMetrics(root, directory string, metrics processAllocationMetrics) error {
	if err := allocationDirectory(root, directory); err != nil {
		return err
	}
	data, err := json.Marshal(metrics)
	if err != nil || len(data) > 4096 {
		return errors.New("allocation measurement exceeds its bound")
	}
	file, err := os.CreateTemp(directory, "allocation-*.partial")
	if err != nil {
		return errors.New("allocation measurement cannot be created")
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	var suffix [8]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return err
	}
	name := metrics.Invocation + "-" + strconv.Itoa(metrics.PID) + "-" + hex.EncodeToString(suffix[:]) + ".json"
	// A complete record becomes visible atomically; an existing record cannot be
	// overwritten, even if a concurrent process happened to choose the same name.
	if err = allocationDirectory(root, directory); err != nil {
		return err
	}
	return os.Link(file.Name(), filepath.Join(directory, name))
}
