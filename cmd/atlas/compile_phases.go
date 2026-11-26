package main

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"vansail-ip-atlas/internal/pipeline"
)

// Diagnostics are fixed, source-free measurements, never acceptance evidence.
// Beginning a phase is flushed before its work so a killed process still shows
// the active phase. Only production compilation and its engineering replays
// activate the logger.
type compilePhase string

const (
	phaseStage            compilePhase = "stage"
	phaseBenchmarkPrepare compilePhase = "benchmark-prepare"
	phaseBenchmarkMeasure compilePhase = "benchmark-measure"
	phaseConfig           compilePhase = "config"
	phaseQualification    compilePhase = "qualification"
	phaseTier1            compilePhase = "tier1"
	phaseBuild            compilePhase = "build"
	phaseBoundary         compilePhase = "boundary"
	phaseObjects          compilePhase = "objects"
	phaseReceipt          compilePhase = "receipt"
	phaseRetention        compilePhase = "retention"
	phaseHistory          compilePhase = "history"
	phaseSeal             compilePhase = "seal"
	phaseSeed             compilePhase = "materialize-seed"
	phasePaths            compilePhase = "materialize-paths"
	phaseASNRisk          compilePhase = "materialize-asn-risk"
	phaseSpatial          compilePhase = "materialize-spatial"
	phaseASN              compilePhase = "materialize-asn"
	phaseSort             compilePhase = "pipeline-sort"
	phaseMerge            compilePhase = "pipeline-merge"
	phaseClassify         compilePhase = "pipeline-classify"
	phasePartition        compilePhase = "pipeline-partition"
	phasePublish          compilePhase = "pipeline-publish"
)

type compilePhaseKey struct{}
type compilePhases struct {
	mu       sync.Mutex
	output   io.Writer
	records  int
	counters int
}
type compilePhaseRecord struct {
	Phase     compilePhase `json:"phase"`
	Event     string       `json:"event"`
	ElapsedMS int64        `json:"elapsed_ms"`
	OK        bool         `json:"ok"`
}

func withCompilePhases(ctx context.Context, output io.Writer) context.Context {
	return context.WithValue(ctx, compilePhaseKey{}, &compilePhases{output: output})
}

func beginCompilePhase(ctx context.Context, phase compilePhase) func(bool) {
	logger, _ := ctx.Value(compilePhaseKey{}).(*compilePhases)
	if logger == nil {
		return func(bool) {}
	}
	switch phase {
	case phaseStage, phaseBenchmarkPrepare, phaseBenchmarkMeasure, phaseConfig, phaseQualification, phaseTier1, phaseBuild, phaseBoundary, phaseObjects, phaseReceipt, phaseRetention, phaseHistory, phaseSeal,
		phaseSeed, phasePaths, phaseASNRisk, phaseSpatial, phaseASN, phaseSort, phaseMerge, phaseClassify, phasePartition, phasePublish:
	default:
		return func(bool) {}
	}
	started := time.Now()
	logger.write(compilePhaseRecord{phase, "begin", 0, true})
	var once sync.Once
	return func(ok bool) {
		once.Do(func() { logger.write(compilePhaseRecord{phase, "end", max(0, time.Since(started).Milliseconds()), ok}) })
	}
}

func beginPipelinePhase(ctx context.Context, stage pipeline.Stage) func(bool) {
	var phase compilePhase
	switch stage {
	case pipeline.StageSeed:
		phase = phaseSeed
	case pipeline.StagePaths:
		phase = phasePaths
	case pipeline.StageASNRisk:
		phase = phaseASNRisk
	case pipeline.StageSpatial:
		phase = phaseSpatial
	case pipeline.StageASN:
		phase = phaseASN
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
		return func(bool) {}
	}
	return beginCompilePhase(ctx, phase)
}

func (p *compilePhases) write(record compilePhaseRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.records >= 64 || p.output == nil {
		return
	}
	p.records++
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	// A single bounded write avoids interleaving with other phase records.
	// Diagnostics must never turn an otherwise valid build into a failure.
	_, _ = p.output.Write(append(append([]byte("ATLAS_COMPILE_PHASE "), data...), '\n'))
}

func runCompilePhase(ctx context.Context, phase compilePhase, work func() error) (err error) {
	finish := beginCompilePhase(ctx, phase)
	defer func() { finish(err == nil) }()
	return work()
}
