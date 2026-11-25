package admission

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// sourceValidation retains only bounded, private statistics derived by the
// complete source verifier in this process. It never carries freshness forward:
// reuse requires the exact evaluation clock, controls, state and object bytes.
// Current-time verification and retained generations use the complete verifier.
type sourceValidation struct {
	self          *sourceValidation
	root          string
	clock         time.Time
	binding       [32]byte
	catalogHash   [32]byte
	certification [32]byte
	verified      *intelligence.VerifiedPrivateState
	statistics    map[string]SourceStatistics
	privateLabels []string
}

func sourceValidationIdentity(root string, catalog []Source) (string, [32]byte, error) {
	if len(catalog) == 0 || len(catalog) > 1000 {
		return "", [32]byte{}, errors.New("source validation catalog exceeds bounds")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", [32]byte{}, err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", [32]byte{}, err
	}
	data, err := json.Marshal(catalog)
	if err != nil || len(data) > 64<<20 {
		return "", [32]byte{}, errors.New("source validation catalog identity invalid")
	}
	return canonical, sha256.Sum256(data), nil
}

func validateSourceSet(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte) (intelligence.BuildState, CapabilityReport, *sourceValidation, error) {
	var state intelligence.BuildState
	var report CapabilityReport
	canonical, catalogHash, err := sourceValidationIdentity(root, catalog)
	if err != nil {
		return state, report, nil, err
	}
	certification, err := CertificationFingerprint(ctx, canonical, catalog)
	if err != nil {
		return state, report, nil, err
	}
	verified, state, err := intelligence.VerifyPrivateState(ctx, canonical, binding)
	if err != nil {
		return state, report, nil, err
	}
	return validateAuthenticatedSourceSet(ctx, canonical, catalog, state, now, binding, catalogHash, certification, verified, nil)
}

func validateVerifiedSourceSet(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte, verified *intelligence.VerifiedPrivateState, scan *VerifiedSourceRecords) (intelligence.BuildState, CapabilityReport, *sourceValidation, error) {
	var state intelligence.BuildState
	var report CapabilityReport
	canonical, catalogHash, err := sourceValidationIdentity(root, catalog)
	if err != nil {
		return state, report, nil, err
	}
	var records map[string]*sourceRecordScan
	if scan != nil {
		if scan.PrivateState() != verified || scan.catalogHash != catalogHash || !now.Equal(scan.now) {
			return state, report, nil, errors.New("verified source record controls differ")
		}
		records = scan.records
	}
	certification, err := CertificationFingerprint(ctx, canonical, catalog)
	if err != nil {
		return state, report, nil, err
	}
	state, err = verified.RevalidateFor(ctx, canonical, binding)
	if err != nil {
		return state, report, nil, err
	}
	return validateAuthenticatedSourceSet(ctx, canonical, catalog, state, now, binding, catalogHash, certification, verified, records)
}

func validateAuthenticatedSourceSet(ctx context.Context, canonical string, catalog []Source, state intelligence.BuildState, now time.Time, binding, catalogHash, certification [32]byte, verified *intelligence.VerifiedPrivateState, collected map[string]*sourceRecordScan) (intelligence.BuildState, CapabilityReport, *sourceValidation, error) {
	report, stats, err := revalidateStoredSources(ctx, canonical, catalog, state, now, binding, nil, collected)
	if err != nil {
		return state, report, nil, err
	}
	v := &sourceValidation{root: canonical, clock: now, binding: binding, catalogHash: catalogHash, certification: certification, verified: verified, privateLabels: PrivateLabelValues(catalog), statistics: make(map[string]SourceStatistics, len(stats))}
	for _, stat := range stats {
		// No statistics or their maps escape this handle. Capability reports
		// contain newly derived slices and cannot alter the retained predicates.
		v.statistics[stat.ID] = stat
	}
	v.self = v
	return state, report, v, nil
}

func (v *sourceValidation) revalidate(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte) (intelligence.BuildState, CapabilityReport, error) {
	var state intelligence.BuildState
	var report CapabilityReport
	if err := ctx.Err(); err != nil {
		return state, report, err
	}
	if v == nil || v.self != v || v.verified == nil || !now.Equal(v.clock) || binding != v.binding {
		return state, report, errors.New("source validation does not bind this boundary")
	}
	canonical, catalogHash, err := sourceValidationIdentity(root, catalog)
	if err != nil || canonical != v.root || catalogHash != v.catalogHash {
		return state, report, errors.New("source validation controls changed")
	}
	certification, err := CertificationFingerprint(ctx, canonical, catalog)
	if err != nil || certification != v.certification {
		return state, report, errors.New("source validation certification changed")
	}
	state, err = v.verified.Revalidate(ctx)
	if err != nil {
		return state, report, err
	}
	report, _, err = revalidateStoredSources(ctx, canonical, catalog, state, now, binding, v.statistics, nil)
	if err != nil {
		return state, report, err
	}
	return state, report, ctx.Err()
}

// RevalidateCurrent is a compile-boundary check for the exact source set that
// originally minted q. It rechecks every normalized object byte and every
// current admission control; only identical record semantics are reused.
// A different clock or generation must undergo full independent qualification.
func (q *ProductionQualification) RevalidateCurrent(ctx context.Context, root string, catalog []Source, now time.Time, binding [32]byte) error {
	if q == nil || q.validation == nil {
		return errors.New("source qualification has no current validation handle")
	}
	if err := q.Validate(q.state, now); err != nil {
		return err
	}
	state, report, err := q.validation.revalidate(ctx, root, catalog, now, binding)
	if err != nil {
		return err
	}
	if err = q.Validate(state, now); err != nil {
		return err
	}
	if err = report.RequireProduction(); err != nil {
		return err
	}
	current, err := json.Marshal(report)
	if err != nil {
		return err
	}
	original, err := json.Marshal(q.report)
	if err != nil || sha256.Sum256(current) != sha256.Sum256(original) {
		return errors.New("qualified capability report changed")
	}
	return nil
}
