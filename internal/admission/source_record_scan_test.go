package admission

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestSourceRecordScanMatchesFreshQualification(t *testing.T) {
	e, catalog, now, binding, want := preparedCoreQualification(t)
	ctx := context.Background()
	scan, state, err := VerifySourceRecordsForTier1(ctx, e.workspace, catalog, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, want.State()) {
		t.Fatal("sealed input differs")
	}
	q, err := scan.Qualify(ctx, e.workspace, catalog, now, binding)
	if err != nil || !reflect.DeepEqual(q.Report(), want.Report()) || !reflect.DeepEqual(q.validation.statistics, want.validation.statistics) {
		t.Fatal("qualified record statistics differ", err)
	}
	if err := q.RevalidateCurrent(ctx, e.workspace, catalog, now, binding); err != nil {
		t.Fatal(err)
	}
	// Returned state has no shared mutable receipt or descriptor with the scan.
	state.Sources[0].ExpiresAt = now
	state.Sources[0].Receipt.PublishedAt = now.Add(24 * time.Hour)
	if _, err = scan.Qualify(ctx, e.workspace, catalog, now, binding); err != nil {
		t.Fatal(err)
	}
}

func TestSourceRecordScanBindsInputs(t *testing.T) {
	e, catalog, now, binding, _ := preparedCoreQualification(t)
	ctx := context.Background()
	scan, state, err := VerifySourceRecordsForTier1(ctx, e.workspace, catalog, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"nil", "zero", "copied", "catalog", "signals", "fields", "policy", "workspace", "clock", "cancellation", "object"} {
		t.Run(kind, func(t *testing.T) {
			observed, root, at, policy, controls, current := scan, e.workspace, now, binding, append([]Source(nil), catalog...), ctx
			switch kind {
			case "nil":
				observed = nil
			case "zero":
				observed = new(VerifiedSourceRecords)
			case "copied":
				copy := *scan
				observed = &copy
			case "catalog":
				controls[0].Family = "changed"
			case "signals":
				controls[0].Signals = []string{"malware"}
			case "fields":
				controls[0].PublicFields = nil
			case "policy":
				policy[0] ^= 1
			case "workspace":
				root = t.TempDir()
			case "clock":
				at = now.Add(time.Second)
			case "cancellation":
				var cancel context.CancelFunc
				current, cancel = context.WithCancel(ctx)
				cancel()
			case "object":
				p := state.Sources[0].RecordPartitions[0]
				name := filepath.Join(root, ".atlas-private", "records-v2", hex.EncodeToString(p.SHA256[:])+".records")
				b, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-1] ^= 1
				if err = os.WriteFile(name, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := observed.Qualify(current, root, controls, at, policy); err == nil {
				t.Fatal("unbound source statistics accepted")
			}
		})
	}
}

func TestSourceRecordErrorsFollowTier1Observation(t *testing.T) {
	e, catalog, now, binding, _ := preparedCoreQualification(t)
	ctx := context.Background()
	// A structurally valid city row fails its source-specific field check.
	catalog[0].PublicFields = nil
	scan, _, err := VerifySourceRecordsForTier1(ctx, e.workspace, catalog, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if scan.records[catalog[0].ID].err == nil {
		t.Fatal("missing deferred predicate failure")
	}
	q, err := scan.PrivateState().ObserveTier1State(ctx, e.workspace, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scan.Qualify(ctx, e.workspace, catalog, now, binding); err == nil {
		t.Fatal("violating source qualified")
	}
	if err := scan.PrivateState().VerifyTier1ObservationHistory(ctx, e.workspace, q); err != nil {
		t.Fatal("source-specific failure affected history", err)
	}
}

func TestSourceRecordScanChecksCanonicalAliasedFamilies(t *testing.T) {
	e, catalog, now, binding, want := preparedCoreQualification(t)
	ctx := context.Background()
	// Distinct configured families with identical payload bytes collapse to
	// the lexical family. Existing rows declaring the other family must fail.
	state := want.State()
	state.Sources[1].Receipt.PayloadHash = state.Sources[0].Receipt.PayloadHash
	state.Sources[1].Receipt.ProofPayloadHash = state.Sources[0].Receipt.ProofPayloadHash
	if err := intelligence.SavePartitionedState(ctx, e.workspace, state, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err := e.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	scan, _, err := VerifySourceRecordsForTier1(ctx, e.workspace, catalog, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	_, freshErr := QualifyProductionState(ctx, e.workspace, catalog, now, binding)
	_, fusedErr := scan.Qualify(ctx, e.workspace, catalog, now, binding)
	if freshErr == nil || fusedErr == nil || freshErr.Error() != "production evidence independence changed" || freshErr.Error() != fusedErr.Error() {
		t.Fatal("canonical family predicate differs", freshErr, fusedErr)
	}
}
