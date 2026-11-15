package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/pipeline"
)

// Production consumes only authenticated source intake. compile-facts and the
// engineering compile-state entry point cannot manufacture this qualification.
func compileProduction(ctx context.Context, args []string) (returnErr error) {
	fs := flag.NewFlagSet("compile-production", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "reviewed source workspace")
	out := fs.String("out", "build-private/production-atlas", "new immutable production atlas")
	receipt := fs.String("receipt", ".atlas-private/production-receipt.json", "private qualification destination")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "exact intake evaluation clock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *clock < 0 {
		return errors.New("invalid production compilation arguments")
	}
	root, err := resolveProductionRoot(*workspace)
	if err != nil {
		return err
	}
	destination, err := privateReceiptDestination(root, *receipt)
	if err != nil {
		return err
	}
	engine, err := admission.New(root)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, engine.Close()) }()
	now := time.Unix(*clock, 0).UTC()
	tier1, err := observeCurrentTier1(ctx, root, now)
	if err != nil {
		return err
	}
	binding, err := loadProductionBinding(ctx, root, now)
	if err != nil {
		return err
	}
	q := binding.qualification
	state := q.State()
	if !state.EvaluatedAt.Equal(now) {
		return errors.New("production compilation requires the exact intake clock")
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
	if err := tier1.ValidateObservation(state, now); err != nil {
		return err
	}
	gate := func(checkCtx context.Context) error {
		current, err := loadProductionBinding(checkCtx, root, now)
		if err != nil {
			return err
		}
		if current.configHash != binding.configHash || current.stateHash != binding.stateHash || current.certificationHash != binding.certificationHash {
			return errors.New("production inputs changed during materialization")
		}
		return current.qualification.Validate(state, now)
	}
	output := rooted(root, *out)
	validUntil := q.ValidUntil()
	if tier1.ValidUntil().Before(validUntil) {
		validUntil = tier1.ValidUntil()
	}
	// This complete production gate also revalidates the source/config/state
	// binding at both boundaries. Installing it again as InputGate would repeat
	// the same full source scan without adding an independent predicate.
	candidate, err := pipeline.BuildProductionIntelligence(ctx, pipeline.Options{Workspace: root, Output: output, Mode: "production", Clock: *clock, ValidUntil: validUntil.Unix(), Limits: pipeline.DefaultLimits(), ProductionGate: gate}, state, policy, pipeline.ProductionInputs{Qualification: q, Tier1: tier1})
	if err != nil {
		return err
	}
	manifestBytes, err := readPrivateInput(ctx, filepath.Join(output, "releases", candidate.Pointer.ReleaseID, "manifest.json"), 4<<20)
	if err != nil {
		return err
	}
	if err = verifyProductionObjects(ctx, output, candidate.Manifest, manifestBytes, *clock); err != nil {
		return err
	}
	if err = gate(ctx); err != nil {
		return err
	}
	r, err := binding.receipt(candidate.Manifest, manifestBytes)
	if err != nil {
		return err
	}
	if err = writeJSON(destination, r); err != nil {
		return err
	}
	if err = engine.RetainPrivateStateSeal(ctx, binding.policyHash); err != nil {
		_ = os.Remove(destination)
		return err
	}
	// This checks the already persisted observation. Output success cannot
	// advance or suppress source-derived continuity.
	if err = intelligence.VerifyTier1ObservationHistory(ctx, root, tier1); err != nil {
		_ = os.Remove(destination)
		return err
	}
	receiptBytes, err := readPrivateInput(ctx, destination, 2<<20)
	canonical, canonicalErr := admission.CanonicalPrivateJSON(r)
	if err != nil || canonicalErr != nil || !bytes.Equal(receiptBytes, canonical) {
		_ = os.Remove(destination)
		return errors.New("written production receipt differs from compiler output")
	}
	if err = intelligence.SealProductionReceipt(ctx, root, binding.policyHash, receiptBytes, binding.stateHash, sha256.Sum256(manifestBytes), time.Unix(candidate.Manifest.ValidUntil, 0).UTC()); err != nil {
		_ = os.Remove(destination)
		return err
	}
	fmt.Printf("production candidate %s: %d objects; hosted acceptance required\n", candidate.Pointer.ReleaseID, len(candidate.Manifest.Objects))
	return nil
}

func observeCurrentTier1(ctx context.Context, root string, now time.Time) (*intelligence.QualifiedTier1, error) {
	configHash, sourceBytes, err := intakeConfigHash(root)
	if err != nil {
		return nil, err
	}
	catalog, err := admission.DecodeCatalog(bytes.NewReader(sourceBytes))
	if err != nil {
		return nil, err
	}
	certification, err := admission.CertificationFingerprint(ctx, root, catalog)
	if err != nil {
		return nil, err
	}
	binding := sha256.Sum256(append(append([]byte("intake-policy-v1\x00"), configHash[:]...), certification[:]...))
	state, err := intelligence.VerifyPrivateStateSeal(ctx, root, binding)
	if err != nil {
		return nil, err
	}
	if !state.EvaluatedAt.Equal(now) {
		return nil, errors.New("Tier-1 observation requires the exact intake clock")
	}
	return intelligence.ObserveTier1State(ctx, root, state, binding, now)
}
