package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
)

// intake validates the complete closed configuration before any acquisition.
// Its receipts/state are private; it neither materializes facts nor emits a
// public release, and unsupported real adapters remain quarantined.
func intakeSources(ctx context.Context, args []string) (returnErr error) {
	fs := flag.NewFlagSet("intake", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "workspace with reviewed configs and private state")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "UTC evaluation clock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *clock < 0 {
		return errors.New("invalid intake arguments")
	}
	root, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("intake workspace unavailable")
	}
	private := filepath.Join(root, ".atlas-private")
	if err := os.MkdirAll(private, 0700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(private)
	if err != nil || resolved != private {
		return errors.New("private intake directory escaped workspace")
	}
	configHash, sourceBytes, err := intakeConfigHash(root)
	if err != nil {
		return err
	}
	sources, err := admission.DecodeCatalog(bytes.NewReader(sourceBytes))
	if err != nil {
		return err
	}
	certificationHash, err := admission.CertificationFingerprint(ctx, root, sources)
	if err != nil {
		return err
	}
	policyHash := sha256.Sum256(append(append([]byte("intake-policy-v1\x00"), configHash[:]...), certificationHash[:]...))
	validation := exec.CommandContext(ctx, "python", filepath.Join(root, "tools", "validate_blueprint.py"))
	validation.Dir = root
	validation.Stdout, validation.Stderr = io.Discard, io.Discard
	if err := validation.Run(); err != nil {
		return errors.New("closed config validation failed; run python tools/validate_blueprint.py for details")
	}
	verifiedHash, _, err := intakeConfigHash(root)
	if err != nil || verifiedHash != configHash {
		return errors.New("configuration changed during validation")
	}
	verifiedCertification, err := admission.CertificationFingerprint(ctx, root, sources)
	if err != nil || verifiedCertification != certificationHash {
		return errors.New("certification changed during validation")
	}
	engine, err := admission.New(root)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, engine.Close()) }()
	var previous intelligence.BuildState
	if _, err := os.Lstat(filepath.Join(private, "state-v1.json")); err == nil {
		previous, err = intelligence.LoadPrivateState(root)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	committed := previous
	retained, err := intelligence.LoadRetainedPrivateState(ctx, root)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	before := previous
	if before.PolicyHash != policyHash {
		before = intelligence.BuildState{}
	}
	if err = intelligence.PruneRecordStore(ctx, root, before, retained, time.Unix(*clock, 0).UTC()); err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		returnErr = errors.Join(returnErr, intelligence.PruneRecordStore(cleanupCtx, root, committed, retained, time.Unix(*clock, 0).UTC()))
	}()
	policies := make([]intelligence.SourcePolicy, 0, len(sources))
	snapshots := make([]intelligence.SourceSnapshot, 0, len(sources))
	decisions := make([]intelligence.SourceDecision, 0, len(sources))
	var normalizedBytes int
	var mrtControls struct {
		Build struct {
			BGP struct {
				Enabled bool `yaml:"mrt_enabled"`
			} `yaml:"bgp"`
		} `yaml:"build"`
	}
	if err := yaml.Unmarshal(sourceBytes, &mrtControls); err != nil {
		return errors.New("MRT controls unavailable")
	}
	var mrtSources []admission.Source
	if mrtControls.Build.BGP.Enabled {
		for _, source := range sources {
			if source.Admission == "active" && source.Parser.ID == "mrt-table-dump-v2" {
				mrtSources = append(mrtSources, source)
			}
		}
		if len(mrtSources) != 2 {
			return errors.New("enabled MRT requires exactly two reviewed independent sources")
		}
	}
	intakeResults := make(map[string]admission.Result, len(mrtSources))
	if len(mrtSources) > 0 {
		group, err := engine.IngestMRT(ctx, mrtSources, time.Unix(*clock, 0).UTC(), policyHash, admission.MRTIntakeOptions{Enabled: true})
		if err != nil {
			return err
		}
		for _, result := range group.Results {
			intakeResults[result.Decision.ID] = result
		}
	}
	for _, source := range sources {
		result, ok := intakeResults[source.ID]
		var err error
		if !ok {
			result, err = engine.IngestPartitioned(ctx, source, time.Unix(*clock, 0).UTC(), policyHash)
		}
		if err != nil {
			return err
		}
		policies = append(policies, result.Policy)
		decisions = append(decisions, result.Decision)
		if result.Snapshot != nil {
			encoded, err := json.Marshal(result.Snapshot)
			if err != nil || len(encoded) > (64<<20)-normalizedBytes {
				return errors.New("intake partition metadata exceeds 64 MiB")
			}
			normalizedBytes += len(encoded)
			snapshots = append(snapshots, *result.Snapshot)
		}
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, root, previous, policies, snapshots, time.Unix(*clock, 0).UTC(), policyHash)
	if err != nil {
		return err
	}
	// Rights/catalog changes during a long acquisition invalidate the result.
	finalHash, _, err := intakeConfigHash(root)
	if err != nil || finalHash != configHash {
		return errors.New("configuration changed during intake")
	}
	finalCertification, err := admission.CertificationFingerprint(ctx, root, sources)
	if err != nil || finalCertification != certificationHash {
		return errors.New("certification changed during intake")
	}
	if err := intelligence.SavePartitionedState(ctx, root, plan.State, previous); err != nil {
		return err
	}
	committed = plan.State
	retained = previous
	if err := engine.SealPrivateState(ctx, policyHash); err != nil {
		return err
	}
	// Record every authenticated observation before later capability or output
	// failures can hide an intervening missing/failed Tier-1 epoch.
	if _, err := intelligence.ObserveTier1State(ctx, root, plan.State, policyHash, time.Unix(*clock, 0).UTC()); err != nil {
		return err
	}
	report := struct {
		SchemaVersion             uint16
		EvaluatedAt               time.Time
		PolicySHA256              [32]byte
		SourceCount, CurrentCount int
		ProductionEligible        bool
		IntakeDecisions           []intelligence.SourceDecision
		Reconciliation            []intelligence.SourceDecision
		FullRebuild               bool
		NextExpiry                time.Time
	}{1, time.Unix(*clock, 0).UTC(), policyHash, len(sources), len(plan.State.Sources), false,
		decisions, plan.Decisions, plan.FullRebuild, plan.NextExpiry}
	if err := writeJSON(filepath.Join(private, "intake-report-v1.json"), report); err != nil {
		return err
	}
	fmt.Printf("private intake: %d current of %d sources; production blocked\n", len(plan.State.Sources), len(sources))
	return nil
}

func intakeConfigHash(root string) ([32]byte, []byte, error) {
	hash := sha256.New()
	var sources []byte
	for _, name := range []string{"configs/sources.yaml", "configs/scoring.yaml", "configs/tier1.yaml", "configs/web.yaml", "configs/release-approval.yaml", "SOURCES_AUDIT.md"} {
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return [32]byte{}, nil, errors.New("intake config unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		_ = file.Close()
		if err != nil || len(data) > 4<<20 {
			return [32]byte{}, nil, errors.New("intake config size or read failure")
		}
		hash.Write([]byte(name + "\x00"))
		hash.Write(data)
		hash.Write([]byte{0})
		if name == "configs/sources.yaml" {
			sources = data
		}
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, sources, nil
}
