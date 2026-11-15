package pipeline

import "context"

// Stage identifies a fixed aggregate compiler phase. Observers report timing
// only; they cannot alter admission, resource limits or materialization gates.
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

func observeStage(ctx context.Context, options Options, stage Stage) func(bool) {
	if options.ObserveStage != nil {
		if finish := options.ObserveStage(ctx, stage); finish != nil {
			return finish
		}
	}
	return func(bool) {}
}
