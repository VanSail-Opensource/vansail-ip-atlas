package pipeline

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

type counterObservation struct {
	stage    Stage
	counters Counters
}

func TestBuildCountersMirrorWorkWithoutChangingRelease(t *testing.T) {
	options := testOptions(t)
	var seen []counterObservation
	options.ObserveCounters = func(_ context.Context, stage Stage, counters Counters) {
		seen = append(seen, counterObservation{stage, counters})
		counters.InputRecords = 0 // This independent copy cannot change Build.
		counters.ObjectsByKind[0] = ^uint64(0)
	}
	records := fusedFixture()
	records = append(records, records[5])
	candidate, err := Build(context.Background(), options, producer(records))
	if err != nil {
		t.Fatal(err)
	}
	wantStages := []Stage{StageSort, StageMerge, StageClassify, StagePartition, StagePublish}
	if len(seen) != len(wantStages) {
		t.Fatalf("unexpected diagnostic population: %d", len(seen))
	}
	for i, want := range wantStages {
		if seen[i].stage != want || seen[i].counters.InputRecords != uint64(len(records)) {
			t.Fatal("fixed boundary or cumulative input count changed")
		}
	}
	if seen[0].counters.SortRuns < 2 || seen[0].counters.UniqueRecords != 0 ||
		seen[2].counters.UniqueRecords != uint64(len(records)-1) ||
		seen[3].counters.Partitions == 0 || seen[3].counters.OutputBytes == 0 {
		t.Fatal("snapshot did not describe the work completed at its boundary")
	}
	stats := candidate.Stats
	var objectsByKind [14]uint64
	for _, object := range candidate.Manifest.Objects {
		objectsByKind[object.Kind-1]++
	}
	want := Counters{InputRecords: uint64(stats.InputRecords), UniqueRecords: uint64(stats.UniqueRecords),
		SortRuns: uint64(stats.SortRuns), Partitions: uint64(stats.Partitions),
		BinaryByteRepacks: uint64(stats.BinaryByteRepacks), SortBufferPeak: stats.SortBufferPeak,
		PartitionBufferPeak: stats.PartitionBufferPeak, OutputBytes: stats.OutputBytes,
		ScratchPeak: stats.ScratchPeak, ObjectsByKind: objectsByKind}
	if seen[len(seen)-1].counters != want {
		t.Fatal("final counters differ from the completed compiler statistics")
	}
	if seen[2].counters.ObjectsByKind != ([14]uint64{}) || objectsByKind[0] == 0 || objectsByKind[13] == 0 {
		t.Fatal("object kinds were not taken from the current registry at each boundary")
	}
	other, err := Build(context.Background(), testOptions(t), producer(records))
	if err != nil || !reflect.DeepEqual(candidate.Pointer, other.Pointer) {
		t.Fatalf("optional diagnostics changed the immutable release: %v", err)
	}
}

func TestBuildCountersReportCanceledWorkWithoutPublishing(t *testing.T) {
	options := testOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var seen []counterObservation
	options.ObserveCounters = func(observed context.Context, stage Stage, counters Counters) {
		if !errors.Is(observed.Err(), context.Canceled) {
			t.Fatal("canceled-stage regression did not reach a canceled context")
		}
		seen = append(seen, counterObservation{stage, counters})
	}
	candidate, err := Build(ctx, options, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		if err := emit(fusedFixture()[0]); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || candidate.Pointer.ReleaseID != "" || len(seen) != 1 ||
		seen[0].stage != StageSort || seen[0].counters.InputRecords != 1 {
		t.Fatalf("canceled work was omitted or became a candidate: %v, %+v", err, seen)
	}
	if _, err := os.Stat(options.Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed output was published")
	}
	assertClean(t, options.Workspace)
}

func TestBuildCountersDescribeObjectBudgetFailure(t *testing.T) {
	options := testOptions(t)
	options.Limits.MaxObjects = 2
	var final counterObservation
	options.ObserveCounters = func(_ context.Context, stage Stage, counters Counters) {
		final = counterObservation{stage, counters}
	}
	_, err := Build(context.Background(), options, producer(fusedFixture()))
	var objects uint64
	for _, count := range final.counters.ObjectsByKind {
		objects += count
	}
	if via3.ErrorCode(err) != "partition_budget" || final.stage != StagePartition || objects != 2 {
		t.Fatalf("object-cap failure did not retain its bounded kind distribution: %v, %+v", err, final)
	}
	if _, err := os.Stat(options.Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("object-budget diagnostics published failed output")
	}
	assertClean(t, options.Workspace)
}

func TestBuildCountersKeepTheFinalProductionGate(t *testing.T) {
	options := testOptions(t)
	options.Mode = "production"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	options.ProductionGate = func(context.Context) error {
		calls++
		if calls == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	var final counterObservation
	options.ObserveCounters = func(observed context.Context, stage Stage, counters Counters) {
		final = counterObservation{stage, counters}
		if stage == StagePublish && !errors.Is(observed.Err(), context.Canceled) {
			t.Fatal("final gate did not cancel the publication context")
		}
	}
	_, err := Build(ctx, options, producer(fusedFixture()))
	if !errors.Is(err, context.Canceled) || calls != 2 || final.stage != StagePublish ||
		final.counters.Partitions == 0 || final.counters.OutputBytes == 0 {
		t.Fatalf("final gate or failure counters changed: %v", err)
	}
	if _, err := os.Stat(options.Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("diagnostics made a rejected production build publishable")
	}
	assertClean(t, options.Workspace)
}
