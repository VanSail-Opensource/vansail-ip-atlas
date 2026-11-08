package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/pipeline"
)

// compile-state consumes only the fixed private state saved by intake. A later
// clock needs a new intake/reconciliation; cached records cannot renew their own
// receipt, publication clock, rights, parser certification or scoring policy.
func compileState(ctx context.Context, args []string) (returnErr error) {
	fs := flag.NewFlagSet("compile-state", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "workspace containing reviewed configs and private state")
	out := fs.String("out", "build-private/compiled-state", "new private atlas destination")
	mode := fs.String("mode", "synthetic", "synthetic engineering materialization only")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "exact UTC evaluation clock used by intake")
	until := fs.Int64("valid-until", 0, "validity deadline; defaults to earliest surviving receipt")
	vrpComplete := fs.Bool("vrp-complete", false, "engineering assertion that the complete current VRP snapshot was retained")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode != "synthetic" {
		return errors.New("production_blocked: certified capabilities and source-qualified Tier-1/ASN identity are required")
	}
	if len(fs.Args()) != 0 || *clock < 0 {
		return errors.New("invalid state compilation arguments")
	}
	root, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("state compilation workspace unavailable")
	}
	engine, err := admission.New(root)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, engine.Close()) }()
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
	stateHash, err := privateStateHash(ctx, root)
	if err != nil {
		return err
	}
	state, err := intelligence.LoadPrivateState(root)
	if err != nil {
		return err
	}
	if state.PolicyHash != policyHash {
		return errors.New("private state policy/certification changed; rerun intake")
	}
	if !state.EvaluatedAt.Equal(time.Unix(*clock, 0).UTC()) {
		return errors.New("private state clock differs; rerun intake at the requested clock")
	}
	if len(state.Sources) == 0 {
		return errors.New("no surviving source receipts; no candidate materialized")
	}
	policyFile, err := openRegularInput(filepath.Join(root, "configs", "scoring.yaml"), 2<<20)
	if err != nil {
		return errors.New("scoring policy unavailable")
	}
	policy, err := intelligence.LoadPolicy(policyFile)
	_ = policyFile.Close()
	if err != nil {
		return err
	}
	deadline := *clock + 720*3600
	for _, source := range state.Sources {
		if source.ExpiresAt.Unix() < deadline {
			deadline = source.ExpiresAt.Unix()
		}
	}
	if *until != 0 {
		deadline = *until
	}
	gate := func(checkCtx context.Context) error {
		if err := checkCtx.Err(); err != nil {
			return err
		}
		currentConfig, _, err := intakeConfigHash(root)
		if err != nil || currentConfig != configHash {
			return errors.New("configuration changed during state compilation; rerun intake")
		}
		currentCertification, err := admission.CertificationFingerprint(checkCtx, root, sources)
		if err != nil || currentCertification != certificationHash {
			return errors.New("certification changed during state compilation; rerun intake")
		}
		currentState, err := privateStateHash(checkCtx, root)
		if err != nil || currentState != stateHash {
			return errors.New("private state changed during compilation")
		}
		return nil
	}
	destination := *out
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(root, destination)
	}
	candidate, err := pipeline.BuildIntelligence(ctx, pipeline.Options{Workspace: root, Output: destination, Mode: "synthetic", Clock: *clock, ValidUntil: deadline, Limits: pipeline.DefaultLimits(), InputGate: gate}, state, policy, pipeline.MaterializationInputs{VRPComplete: *vrpComplete})
	if err != nil {
		return err
	}
	fmt.Printf("synthetic compiled state %s: %d objects; %d records; production blocked\n", candidate.Pointer.ReleaseID, len(candidate.Manifest.Objects), candidate.Stats.UniqueRecords)
	return nil
}

func privateStateHash(ctx context.Context, root string) ([32]byte, error) {
	var value [32]byte
	file, err := openRegularInput(filepath.Join(root, ".atlas-private", "state-v1.json"), 64<<20)
	if err != nil {
		return value, errors.New("private state unavailable")
	}
	defer file.Close()
	reader := &io.LimitedReader{R: stateContextReader{ctx, file}, N: (64 << 20) + 1}
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return value, err
	}
	if reader.N == 0 {
		return value, errors.New("private state byte budget exceeded")
	}
	copy(value[:], hash.Sum(nil))
	return value, nil
}

type stateContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r stateContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
