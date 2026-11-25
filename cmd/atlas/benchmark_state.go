package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/pipeline"
)

const benchmarkScope = "authenticated-real-input-engineering-benchmark"

type benchmarkTransition struct {
	Before    uint64 `json:"before_records"`
	After     uint64 `json:"after_records"`
	Added     uint64 `json:"added_records"`
	Removed   uint64 `json:"removed_records"`
	Changed   uint64 `json:"changed_records"`
	Expired   uint64 `json:"expired_sources_retracted"`
	Withdrawn uint64 `json:"withdrawn_sources_retracted"`
}
type benchmarkReport struct {
	SchemaVersion   int                 `json:"schema_version"`
	Scope           string              `json:"scope"`
	Scenario        string              `json:"scenario"`
	Clock           int64               `json:"clock"`
	InputRecords    uint64              `json:"input_records"`
	InputBytes      uint64              `json:"normalized_input_bytes"`
	BeforeHash      string              `json:"before_state_sha256"`
	AfterHash       string              `json:"after_state_sha256"`
	ReleaseID       string              `json:"release_id"`
	CompileExitCode int                 `json:"compile_exit_code"`
	Transition      benchmarkTransition `json:"transition"`
}
type benchmarkMarker struct {
	Scope     string `json:"scope"`
	StateHash string `json:"state_sha256"`
	Clock     int64  `json:"clock"`
}

// The benchmark transforms an isolated copy, never the authenticated intake or
// its seals. Every output is engineering, including its unmodified warm-up.
func benchmarkState(ctx context.Context, args []string) (returnErr error) {
	ctx = withCompilePhases(ctx, os.Stderr)
	fs := flag.NewFlagSet("benchmark-state", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "authenticated source workspace")
	out := fs.String("out", "", "isolated directory beneath workspace/build-private")
	scenario := fs.String("scenario", "", "cold_full, warm_changed, warm_unchanged, clock_advance or withdrawal")
	clock := fs.Int64("clock", 0, "exact authenticated baseline clock")
	prepare := fs.Bool("prepare", false, "prime a warm scenario before its timed execution")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *clock <= 0 || *out == "" {
		return errors.New("invalid benchmark arguments")
	}
	switch *scenario {
	case "cold_full", "warm_changed", "warm_unchanged", "clock_advance", "withdrawal":
	default:
		return errors.New("invalid benchmark scenario")
	}
	root, err := resolveProductionRoot(*workspace)
	if err != nil {
		return err
	}
	engine, err := admission.New(root)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, engine.Close()) }()
	baseClock := time.Unix(*clock, 0).UTC()
	// Use the production compiler's exact process-local validation path. The
	// observed source epoch precedes unrelated capability failures, while the
	// opaque handle rechecks every object byte before source qualification.
	tierPhase := beginCompilePhase(ctx, phaseTier1)
	tier, verified, err := observeVerifiedCurrentTier1(ctx, root, baseClock)
	tierPhase(err == nil)
	if err != nil {
		return err
	}
	binding, err := loadVerifiedProductionBinding(ctx, root, baseClock, verified)
	if err != nil {
		return err
	}
	baseline := binding.qualification.State()
	if !baseline.EvaluatedAt.Equal(baseClock) {
		return errors.New("benchmark baseline clock mismatch")
	}
	if err = tier.ValidateObservation(baseline, baseClock); err != nil {
		return err
	}
	policyFile, err := openRegularInput(filepath.Join(root, "configs", "scoring.yaml"), 2<<20)
	if err != nil {
		return err
	}
	policy, err := intelligence.LoadPolicy(policyFile)
	_ = policyFile.Close()
	if err != nil {
		return err
	}
	destination, err := benchmarkDestination(root, *out)
	if err != nil {
		return err
	}
	markerPath := filepath.Join(destination, "benchmark-baseline.json")
	stateDigest := digestString(binding.stateHash)
	var marker benchmarkMarker
	if *prepare || *scenario == "cold_full" {
		if _, err = os.Lstat(destination); !os.IsNotExist(err) {
			return errors.New("benchmark destination must be new")
		}
		if err = os.MkdirAll(destination, 0700); err != nil {
			return err
		}
		if err = cloneBenchmarkRecords(ctx, root, destination, baseline); err != nil {
			return err
		}
	} else {
		data, readErr := readPrivateInput(ctx, markerPath, 16<<20)
		if readErr != nil || json.Unmarshal(data, &marker) != nil || marker.Scope != benchmarkScope || marker.StateHash != stateDigest || marker.Clock != *clock {
			return errors.New("warm benchmark requires matching prepared baseline")
		}
	}
	inputs := pipeline.ProductionInputs{Qualification: binding.qualification, Tier1: tier}
	validUntil := binding.qualification.ValidUntil()
	if tier.ValidUntil().Before(validUntil) {
		validUntil = tier.ValidUntil()
	}
	state := baseline
	state.Sources = append([]intelligence.StoredSource(nil), baseline.Sources...)
	report := benchmarkReport{SchemaVersion: 1, Scope: benchmarkScope, Scenario: *scenario, Clock: *clock, BeforeHash: stateDigest}
	for _, source := range baseline.Sources {
		for _, part := range source.RecordPartitions {
			report.InputRecords += part.Records
			report.InputBytes += uint64(part.DecodedBytes)
		}
	}
	if report.InputRecords == 0 {
		return errors.New("benchmark requires partitioned real inputs")
	}
	report.Transition.Before = report.InputRecords
	report.Transition.After = report.InputRecords
	if !*prepare {
		switch *scenario {
		case "cold_full":
			report.Transition.Before = 0
			report.Transition.Added = report.InputRecords
			report.Transition.Changed = report.InputRecords
		case "warm_changed":
			report.Transition.Changed = (report.InputRecords + 99) / 100
			if err = mutateBenchmarkGeo(ctx, destination, &state, report.Transition.Changed); err != nil {
				return err
			}
			report.Transition.Added = report.Transition.Changed
			report.Transition.Removed = report.Transition.Changed
		case "clock_advance", "withdrawal":
			remove := map[string]bool{}
			if *scenario == "clock_advance" {
				validUntil = state.Sources[0].ExpiresAt
				for _, source := range state.Sources {
					if validUntil.After(source.ExpiresAt) {
						validUntil = source.ExpiresAt
					}
				}
				state.EvaluatedAt = validUntil
				report.Clock = validUntil.Unix()
				for _, source := range state.Sources {
					if !state.EvaluatedAt.Before(source.ExpiresAt) {
						remove[source.ID] = true
					}
				}
				report.Transition.Expired = uint64(len(remove))
			} else {
				remove[state.Sources[0].ID] = true
				report.Transition.Withdrawn = 1
			}
			// Dependents cannot survive the removal of their required parent.
			for changed := true; changed; {
				changed = false
				for _, source := range binding.catalog {
					for _, dep := range source.Dependencies {
						if remove[dep] && !remove[source.ID] {
							remove[source.ID] = true
							changed = true
						}
					}
				}
			}
			kept := state.Sources[:0]
			for _, source := range state.Sources {
				if remove[source.ID] {
					for _, part := range source.RecordPartitions {
						report.Transition.Removed += part.Records
					}
					continue
				}
				kept = append(kept, source)
			}
			state.Sources = kept
			report.Transition.After -= report.Transition.Removed
			if report.Transition.Removed == 0 {
				return errors.New("benchmark transition did not retract records")
			}
			inputs = pipeline.ProductionInputs{}
			validUntil = state.EvaluatedAt.Add(720 * time.Hour)
			for _, source := range state.Sources {
				if source.ExpiresAt.Before(validUntil) {
					validUntil = source.ExpiresAt
				}
			}
		}
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	report.AfterHash = digestString(sha256.Sum256(encoded))
	// The marker is not a source seal. A transformed state is deliberately never
	// written under an authenticated intake filename or issued a release receipt.
	if err = writeJSON(filepath.Join(destination, "benchmark-state.json"), state); err != nil {
		return err
	}
	options := pipeline.Options{Workspace: destination, Output: filepath.Join(destination, "build-private", "result"), Mode: "engineering", Clock: report.Clock, ValidUntil: validUntil.Unix(), Limits: pipeline.DefaultLimits()}
	options.ObserveStage = beginPipelinePhase
	options.ObserveCounters = reportPipelineCounters
	options.InputGate = func(checkCtx context.Context) error {
		current, e := privateStateHash(checkCtx, root)
		if e != nil || current != binding.stateHash {
			return errors.New("benchmark source baseline changed")
		}
		config, _, e := intakeConfigHash(root)
		if e != nil || config != binding.configHash {
			return errors.New("benchmark source configuration changed")
		}
		certification, e := admission.CertificationFingerprint(checkCtx, root, binding.catalog)
		if e != nil || certification != binding.certificationHash {
			return errors.New("benchmark source certification changed")
		}
		return nil
	}
	if *prepare {
		options.Output = filepath.Join(destination, "build-private", "warm")
	}
	// All scenarios execute the same materializer. A warm measurement must not
	// substitute cached validation for work the production compiler performs.
	candidate, err := pipeline.BuildEngineeringBenchmark(ctx, options, baseline, state, policy, inputs)
	if err != nil {
		return err
	}
	if candidate.Manifest.Mode != "engineering" {
		return errors.New("benchmark attempted public output")
	}
	if err = options.InputGate(ctx); err != nil {
		return err
	}
	if *prepare {
		return writeJSON(markerPath, benchmarkMarker{benchmarkScope, stateDigest, *clock})
	}
	report.ReleaseID = candidate.Pointer.ReleaseID
	return json.NewEncoder(os.Stdout).Encode(report)
}

func benchmarkDestination(root, out string) (string, error) {
	destination, err := filepath.Abs(rooted(root, out))
	if err != nil {
		return "", err
	}
	base := filepath.Join(root, "build-private")
	rel, err := filepath.Rel(base, destination)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("benchmark must remain in isolated build-private subtree")
	}
	for path := destination; ; path = filepath.Dir(path) {
		if relative, e := filepath.Rel(root, path); e == nil && relative == "." {
			break
		}
		if filepath.Dir(path) == path {
			return "", errors.New("benchmark path does not reach its workspace")
		}
		if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("benchmark path cannot traverse links")
		} else if e != nil && !os.IsNotExist(e) {
			return "", e
		}
	}
	return destination, nil
}
func cloneBenchmarkRecords(ctx context.Context, sourceRoot, destination string, state intelligence.BuildState) error {
	target := filepath.Join(destination, ".atlas-private", "records-v2")
	if err := os.MkdirAll(target, 0700); err != nil {
		return err
	}
	for _, source := range state.Sources {
		if err := intelligence.WalkStoredSource(ctx, sourceRoot, source, func(intelligence.NormalizedRecord) error { return nil }); err != nil {
			return err
		}
		for _, part := range source.RecordPartitions {
			name := digestString(part.SHA256) + ".records"
			to := filepath.Join(target, name)
			if _, err := os.Lstat(to); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				return err
			}
			from := filepath.Join(sourceRoot, ".atlas-private", "records-v2", name)
			// Immutable same-volume objects share bytes; mutation writes new hashes.
			if err := os.Link(from, to); err != nil {
				input, e := openRegularInput(from, part.Bytes)
				if e != nil {
					return e
				}
				output, e := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					input.Close()
					return e
				}
				written, e := io.Copy(output, io.LimitReader(input, part.Bytes+1))
				e = errors.Join(e, input.Close(), output.Close())
				if e != nil {
					return e
				}
				if written != part.Bytes {
					return errors.New("benchmark partition length changed")
				}
			}
		}
	}
	return nil
}
func mutateBenchmarkGeo(ctx context.Context, root string, state *intelligence.BuildState, count uint64) error {
	store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		return err
	}
	remaining := count
	for i, source := range state.Sources {
		if remaining == 0 {
			break
		}
		// The baseline has already passed complete authentication and semantic
		// verification. Transform the same first N geographic records, but keep
		// immutable descriptors for every untouched partition. Full input checks
		// still run in the materializer; this only avoids rewriting unchanged
		// engineering-copy bytes after the requested mutation is complete.
		var replacement []intelligence.RecordPartition
		before := remaining
		units := source.RecordPartitions
		if len(units) == 0 {
			units = []intelligence.RecordPartition{{}}
		}
		for j, part := range units {
			if err := ctx.Err(); err != nil {
				return err
			}
			if remaining == 0 {
				replacement = append(replacement, units[j:]...)
				break
			}
			unit := source
			if len(source.RecordPartitions) > 0 {
				unit.RecordPartitions = []intelligence.RecordPartition{part}
			}
			writer := store.Writer(ctx)
			changed := uint64(0)
			err = intelligence.WalkStoredSource(ctx, root, unit, func(record intelligence.NormalizedRecord) error {
				if remaining > 0 && record.Geo != nil {
					geo := *record.Geo
					if geo.City == "Benchmark mutation A" {
						geo.City = "Benchmark mutation B"
					} else {
						geo.City = "Benchmark mutation A"
					}
					record.Geo = &geo
					remaining--
					changed++
				}
				return writer.Append(record)
			})
			if err != nil {
				_ = writer.Abort()
				return err
			}
			if changed == 0 && len(source.RecordPartitions) > 0 {
				if err = writer.Abort(); err != nil {
					return err
				}
				replacement = append(replacement, part)
				continue
			}
			parts, e := writer.Finish()
			if e != nil {
				_ = writer.Abort()
				return e
			}
			replacement = append(replacement, parts...)
		}
		if remaining < before {
			state.Sources[i].RecordPartitions = replacement
			state.Sources[i].Records = nil
		}
	}
	if remaining != 0 {
		return errors.New("real corpus lacks enough geographic records for rounded one-percent mutation")
	}
	return ctx.Err()
}
