package pipeline

import "context"

// Stage identifies a fixed aggregate compiler phase. Observers report bounded
// diagnostics only; they cannot approve admission or materialization gates.
type Stage uint8

const (
	StageSeed Stage = iota + 1
	StagePaths
	StageASNRisk
	StageSpatial
	StageASN
	StageSort
	StageMerge
	StageClassify
	StagePartition
	StagePublish
)

// Counters is a source-free copy of aggregate work completed so far. A snapshot
// can describe a failed or incomplete build; it is never a candidate, receipt,
// resource waiver, or evidence that the output is eligible for publication.
type Counters struct {
	InputRecords, UniqueRecords, SortRuns, Partitions, BinaryByteRepacks uint64
	SortBufferPeak, PartitionBufferPeak, OutputBytes, ScratchPeak        uint64
}

func (c *compiler) observeBuildStage(stage Stage) func(bool) {
	finish := observeStage(c.ctx, c.options, stage)
	return func(ok bool) {
		finish(ok)
		if observe := c.options.ObserveCounters; observe != nil {
			// Build owns these counters and invokes observers synchronously. The
			// observer receives no mutable reference to compiler state or output.
			observe(c.ctx, stage, Counters{
				InputRecords:        uint64(c.stats.InputRecords),
				UniqueRecords:       uint64(c.stats.UniqueRecords),
				SortRuns:            uint64(c.stats.SortRuns),
				Partitions:          uint64(c.stats.Partitions),
				BinaryByteRepacks:   uint64(c.stats.BinaryByteRepacks),
				SortBufferPeak:      c.stats.SortBufferPeak,
				PartitionBufferPeak: c.stats.PartitionBufferPeak,
				OutputBytes:         c.stats.OutputBytes,
				ScratchPeak:         c.stats.ScratchPeak,
			})
		}
	}
}

func observeStage(ctx context.Context, options Options, stage Stage) func(bool) {
	if options.ObserveStage != nil {
		if finish := options.ObserveStage(ctx, stage); finish != nil {
			return finish
		}
	}
	return func(bool) {}
}
