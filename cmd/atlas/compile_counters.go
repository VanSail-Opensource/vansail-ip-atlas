package main

import (
	"context"
	"encoding/json"

	"vansail-ip-atlas/internal/pipeline"
)

// Keep this diagnostic schema separate from phase timing and acceptance data.
// Every string is fixed below; only bounded aggregate numbers come from Build.
type compileCounterRecord struct {
	Phase               compilePhase `json:"phase"`
	InputRecords        uint64       `json:"input_records"`
	UniqueRecords       uint64       `json:"unique_records"`
	SortRuns            uint64       `json:"sort_runs"`
	Partitions          uint64       `json:"partitions"`
	BinaryByteRepacks   uint64       `json:"binary_byte_repacks"`
	SortBufferPeak      uint64       `json:"sort_buffer_peak"`
	PartitionBufferPeak uint64       `json:"partition_buffer_peak"`
	OutputBytes         uint64       `json:"output_bytes"`
	ScratchPeak         uint64       `json:"scratch_peak"`
	ObjectsByKind       [14]uint64   `json:"objects_by_kind"`
}

func reportPipelineCounters(ctx context.Context, stage pipeline.Stage, counters pipeline.Counters) {
	logger, _ := ctx.Value(compilePhaseKey{}).(*compilePhases)
	if logger == nil {
		return
	}
	var phase compilePhase
	switch stage {
	case pipeline.StageSort:
		phase = phaseSort
	case pipeline.StageMerge:
		phase = phaseMerge
	case pipeline.StageClassify:
		phase = phaseClassify
	case pipeline.StagePartition:
		phase = phasePartition
	case pipeline.StagePublish:
		phase = phasePublish
	default:
		return
	}
	for _, value := range [...]uint64{counters.InputRecords, counters.UniqueRecords,
		counters.SortRuns, counters.Partitions, counters.BinaryByteRepacks,
		counters.SortBufferPeak, counters.PartitionBufferPeak, counters.OutputBytes,
		counters.ScratchPeak} {
		if value > 9007199254740991 {
			return
		}
	}
	var objects uint64
	for _, count := range counters.ObjectsByKind {
		if count > 18499-objects {
			return
		}
		objects += count
	}
	record := compileCounterRecord{
		Phase: phase, InputRecords: counters.InputRecords, UniqueRecords: counters.UniqueRecords,
		SortRuns: counters.SortRuns, Partitions: counters.Partitions, BinaryByteRepacks: counters.BinaryByteRepacks,
		SortBufferPeak: counters.SortBufferPeak, PartitionBufferPeak: counters.PartitionBufferPeak,
		OutputBytes: counters.OutputBytes, ScratchPeak: counters.ScratchPeak,
		ObjectsByKind: counters.ObjectsByKind,
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if logger.counters >= 8 || logger.output == nil {
		return
	}
	logger.counters++
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	// Do not consult ctx.Err: a deadline failure is precisely when the final
	// counters are needed. Failed writes never change compilation eligibility.
	_, _ = logger.output.Write(append(append([]byte("ATLAS_COMPILE_COUNTERS "), data...), '\n'))
}
