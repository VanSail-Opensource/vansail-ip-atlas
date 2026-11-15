package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestBenchmarkMutationPreservesAuthenticatedSourceBytes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(ctx)
	for _, prefix := range []string{"8.8.8.0/24", "9.9.9.0/24", "1.1.1.0/24"} {
		if err := writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo,
			Geo: &intelligence.GeoEvidence{Prefix: netip.MustParsePrefix(prefix), PhysicalCountry: "US", City: "Original", Family: "fixture", Weight: 70, Current: true}}); err != nil {
			t.Fatal(err)
		}
	}
	parts, err := writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	baseline := intelligence.BuildState{Sources: []intelligence.StoredSource{{ID: "fixture", RecordPartitions: parts}}}
	before, _ := json.Marshal(baseline)
	isolated := filepath.Join(root, "build-private", "isolated")
	if err = cloneBenchmarkRecords(ctx, root, isolated, baseline); err != nil {
		t.Fatal(err)
	}
	changed := baseline
	changed.Sources = append([]intelligence.StoredSource(nil), baseline.Sources...)
	if err = mutateBenchmarkGeo(ctx, isolated, &changed, 2); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(baseline)
	if string(before) != string(after) {
		t.Fatal("baseline metadata mutated")
	}
	for _, population := range []struct {
		root     string
		state    intelligence.BuildState
		expected int
	}{{root, baseline, 0}, {isolated, changed, 2}} {
		mutations, total := 0, 0
		err = intelligence.WalkStoredSource(ctx, population.root, population.state.Sources[0], func(record intelligence.NormalizedRecord) error {
			total++
			if record.Geo.City != "Original" {
				mutations++
			}
			return nil
		})
		if err != nil || total != 3 || mutations != population.expected {
			t.Fatalf("records=%d changed=%d err=%v", total, mutations, err)
		}
	}
	if err = mutateBenchmarkGeo(ctx, isolated, &changed, 4); err == nil {
		t.Fatal("unavailable mutation population accepted")
	}
}

func TestBenchmarkDestinationRejectsEscapeAndLink(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"build-private", "../escape", ".atlas-private", "build-private/../../escape"} {
		if _, err := benchmarkDestination(root, path); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	if _, err := benchmarkDestination(root, "build-private/case/one"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// Windows paths are case insensitive. The ancestor walk must terminate
		// when an absolute caller path spells the workspace differently.
		if _, err := benchmarkDestination(root, filepath.Join(strings.ToUpper(root), "build-private", "case")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "build-private"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "build-private", "linked")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Log("symlink creation unavailable on this host")
		return
	}
	if _, err := benchmarkDestination(root, filepath.Join(link, "case")); err == nil {
		t.Fatal("followed external link")
	}
}
