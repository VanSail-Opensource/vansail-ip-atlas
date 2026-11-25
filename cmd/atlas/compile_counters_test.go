package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/pipeline"
)

func TestCompileCountersAreClosedAndSurviveCancellation(t *testing.T) {
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(withCompilePhases(context.Background(), &output))
	cancel()
	counters := pipeline.Counters{InputRecords: 1, UniqueRecords: 2, SortRuns: 3,
		Partitions: 4, BinaryByteRepacks: 5, SortBufferPeak: 6, PartitionBufferPeak: 7,
		OutputBytes: 8, ScratchPeak: 9, ObjectsByKind: [14]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}}
	stages := []pipeline.Stage{pipeline.StageSort, pipeline.StageMerge, pipeline.StageClassify, pipeline.StagePartition, pipeline.StagePublish}
	labels := []compilePhase{phaseSort, phaseMerge, phaseClassify, phasePartition, phasePublish}
	for _, stage := range stages {
		reportPipelineCounters(ctx, stage, counters)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != len(stages) {
		t.Fatal("canceled diagnostics omitted fixed stage snapshots")
	}
	for i, line := range lines {
		prefix := "ATLAS_COMPILE_COUNTERS "
		if !strings.HasPrefix(line, prefix) {
			t.Fatal("counter marker differs")
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &row); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"phase": string(labels[i]), "input_records": float64(1), "unique_records": float64(2),
			"sort_runs": float64(3), "partitions": float64(4), "binary_byte_repacks": float64(5),
			"sort_buffer_peak": float64(6), "partition_buffer_peak": float64(7), "output_bytes": float64(8), "scratch_peak": float64(9),
			"objects_by_kind": []any{float64(1), float64(2), float64(3), float64(4), float64(5), float64(6), float64(7), float64(8), float64(9), float64(10), float64(11), float64(12), float64(13), float64(14)}}
		if !reflect.DeepEqual(row, want) {
			t.Fatal("counter record contains nonfixed keys or values")
		}
	}
}

func TestCompileCountersAreOptionalBoundedAndIndependentOfPhases(t *testing.T) {
	reportPipelineCounters(context.Background(), pipeline.StageSort, pipeline.Counters{})
	var output bytes.Buffer
	ctx := withCompilePhases(context.Background(), &output)
	for _, stage := range []pipeline.Stage{0, 255, pipeline.StageSeed, pipeline.StageSpatial} {
		reportPipelineCounters(ctx, stage, pipeline.Counters{})
	}
	for field := 0; field < reflect.TypeFor[pipeline.Counters]().NumField(); field++ {
		var counters pipeline.Counters
		value := reflect.ValueOf(&counters).Elem().Field(field)
		if value.Kind() != reflect.Uint64 {
			continue
		}
		value.SetUint(9007199254740992)
		reportPipelineCounters(ctx, pipeline.StageSort, counters)
	}
	for _, counts := range [][14]uint64{{18499, 1}, {0, 18500}, {^uint64(0)}} {
		reportPipelineCounters(ctx, pipeline.StageSort, pipeline.Counters{ObjectsByKind: counts})
	}
	if output.Len() != 0 {
		t.Fatal("unknown stage or unsafe integer reached diagnostics")
	}
	reportPipelineCounters(ctx, pipeline.StageSort, pipeline.Counters{ObjectsByKind: [14]uint64{18499}})
	if !strings.Contains(output.String(), `"objects_by_kind":[18499,`) {
		t.Fatal("exact object limit was omitted")
	}
	for i := 0; i < 100; i++ {
		reportPipelineCounters(ctx, pipeline.StageSort, pipeline.Counters{})
	}
	if strings.Count(output.String(), "ATLAS_COMPILE_COUNTERS ") != 8 {
		t.Fatal("counter snapshot cap differs")
	}
	output.Reset()
	beginCompilePhase(ctx, phaseBuild)(false)
	if strings.Count(output.String(), "ATLAS_COMPILE_PHASE ") != 2 {
		t.Fatal("counter diagnostics exhausted the independent phase record budget")
	}

	// A failed diagnostic sink cannot turn a valid stage into a build error.
	reportPipelineCounters(withCompilePhases(context.Background(), rejectedDiagnosticWriter{}), pipeline.StageSort, pipeline.Counters{})
}

type rejectedDiagnosticWriter struct{}

func (rejectedDiagnosticWriter) Write([]byte) (int, error) {
	return 0, errors.New("private sink failure must never enter diagnostic output")
}
