package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func processMetricsFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, ".atlas-private", "scenario", "invocation")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ATLAS_GO_METRICS_DIR", directory)
	t.Setenv("ATLAS_GO_METRICS_INVOCATION", strings.Repeat("a", 32))
	return root, directory
}

func TestProcessMetricsRecordsActualRuntimeAllocationsAndFailedExits(t *testing.T) {
	_, directory := processMetricsFixture(t)
	for _, fail := range []bool{false, true} {
		err := runWithProcessMetrics(context.Background(), []string{"intake", "-private-secret", "never-record-argv"}, func(context.Context, []string) error {
			data := make([]byte, 64<<10)
			runtime.KeepAlive(data)
			if fail {
				return context.Canceled
			}
			return nil
		})
		if fail && !errors.Is(err, context.Canceled) || !fail && err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 2 {
		t.Fatal("every completed process observation needs its own file", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(directory, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "never-record-argv") || strings.Contains(file.Name(), ".partial") {
			t.Fatal("private arguments or partial output survived")
		}
		var metric processAllocationMetrics
		if err = json.Unmarshal(data, &metric); err != nil {
			t.Fatal(err)
		}
		if metric.Scope != allocationScope || metric.SchemaVersion != 1 || metric.PID != os.Getpid() || metric.Command != "intake" || metric.AllocationCount == 0 || metric.AllocatedBytes < 64<<10 || metric.Invocation != strings.Repeat("a", 32) {
			t.Fatal("runtime measurement incomplete", metric)
		}
		if metric.ExitCode != 0 && metric.ExitCode != 1 {
			t.Fatal("invalid exit code")
		}
	}
}

func TestProcessMetricsRejectsEscapesAndMalformedControlsBeforeExecution(t *testing.T) {
	root, directory := processMetricsFixture(t)
	for _, scenario := range []string{"outside", "private-root", "relative", "bad-invocation"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("ATLAS_GO_METRICS_DIR", directory)
			t.Setenv("ATLAS_GO_METRICS_INVOCATION", strings.Repeat("a", 32))
			switch scenario {
			case "outside":
				t.Setenv("ATLAS_GO_METRICS_DIR", root)
			case "private-root":
				t.Setenv("ATLAS_GO_METRICS_DIR", filepath.Join(root, ".atlas-private"))
			case "relative":
				t.Setenv("ATLAS_GO_METRICS_DIR", "relative")
			case "bad-invocation":
				t.Setenv("ATLAS_GO_METRICS_INVOCATION", "private/value")
			}
			called := false
			if err := runWithProcessMetrics(context.Background(), nil, func(context.Context, []string) error { called = true; return nil }); err == nil || called {
				t.Fatal("invalid measurement controls reached command")
			}
		})
	}
}

func TestProcessMetricsDoesNotFollowReplacedDirectory(t *testing.T) {
	root, directory := processMetricsFixture(t)
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".atlas-private", "test-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	os.Remove(link)
	err := runWithProcessMetrics(context.Background(), []string{"intake"}, func(context.Context, []string) error {
		if err := os.Remove(directory); err != nil {
			return err
		}
		return os.Symlink(outside, directory)
	})
	if err == nil {
		t.Fatal("replaced measurement directory accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("metrics escaped private measurement directory", err)
	}
}
