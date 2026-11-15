package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func vrpObservationSnapshot() (SourcePolicy, SourceSnapshot, [32]byte) {
	policy, snapshot, binding := stateFixture()
	observed := clock().Add(-2 * time.Hour)
	snapshot.PublishedAt = observed.Add(-time.Hour) // The retained payload clock may be earlier.
	snapshot.Records = []NormalizedRecord{
		{Version: 3, Kind: RecordVRP, VRP: &VRP{Prefix: netip.MustParsePrefix("8.8.8.0/24"), MaxLength: 24, ASN: 13335, ValidUntil: observed.Add(time.Hour)}},
		{Version: 3, Kind: RecordVRP, VRP: &VRP{Prefix: netip.MustParsePrefix("9.9.9.0/24"), MaxLength: 24, ASN: 19281, ValidUntil: observed.Add(90 * time.Minute)}},
	}
	snapshot.VRPProof = &VRPSourceProof{Version: 2, Rows: 2, RetainedRows: 2, ObservedAt: observed, EvaluatedAt: clock(), CoverageValidUntil: snapshot.Records[0].VRP.ValidUntil}
	return policy, snapshot, binding
}

func TestVRPObservationProofRetainsExpiredSnapshotWithoutRenewingRows(t *testing.T) {
	for _, partitioned := range []bool{false, true} {
		t.Run(map[bool]string{false: "inline", true: "partitioned"}[partitioned], func(t *testing.T) {
			policy, snapshot, binding := vrpObservationSnapshot()
			root := t.TempDir()
			var plan ReconcilePlan
			var err error
			if partitioned {
				plan, err = ReconcilePartitioned(context.Background(), root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
			} else {
				plan, err = Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
			}
			if err != nil || len(plan.State.Sources) != 1 {
				t.Fatal("authenticated historical snapshot was not retained", err)
			}
			source := plan.State.Sources[0]
			if !source.ExpiresAt.Equal(snapshot.PublishedAt.Add(policy.MaxAge)) || !plan.NextExpiry.Equal(source.ExpiresAt) || !source.Receipt.ContentValidUntil.IsZero() {
				t.Fatal("observation retention changed source freshness or reused authorization expiry")
			}
			var actual []NormalizedRecord
			if err = WalkStoredSource(context.Background(), root, source, func(record NormalizedRecord) error {
				actual = append(actual, record)
				return nil
			}); err != nil || !reflect.DeepEqual(actual, snapshot.Records) {
				t.Fatal("original expired rows or authorization deadlines changed", err)
			}
			proof := *snapshot.VRPProof
			snapshot.VRPProof.ObservedAt = clock()
			snapshot.VRPProof.RetainedRows++
			if *source.Receipt.VRPProof != proof {
				t.Fatal("stored proof borrowed caller-mutable observation metadata")
			}
		})
	}
}

func TestVRPObservationProofRejectsUnboundMetadata(t *testing.T) {
	for _, kind := range []string{"zero_rows", "too_many_rows", "retained_count", "clock", "observation_missing", "future_observation", "publication_missing", "publication_after_observation", "coverage_missing", "coverage_at_observation", "legacy_accepted", "legacy_expired", "legacy_built", "legacy_until", "global_content_expiry", "unknown_version"} {
		t.Run(kind, func(t *testing.T) {
			policy, snapshot, binding := vrpObservationSnapshot()
			proof := snapshot.VRPProof
			switch kind {
			case "zero_rows":
				proof.Rows, proof.RetainedRows = 0, 0
			case "too_many_rows":
				proof.Rows, proof.RetainedRows = 100_000_001, 100_000_001
			case "retained_count":
				proof.RetainedRows--
			case "clock":
				proof.EvaluatedAt = clock().Add(time.Second)
			case "observation_missing":
				proof.ObservedAt = time.Time{}
			case "future_observation":
				proof.ObservedAt = clock().Add(25 * time.Hour)
				proof.CoverageValidUntil = proof.ObservedAt.Add(time.Hour)
			case "publication_missing":
				snapshot.PublishedAt = time.Time{}
			case "publication_after_observation":
				snapshot.PublishedAt = proof.ObservedAt.Add(time.Second)
			case "coverage_missing":
				proof.CoverageValidUntil = time.Time{}
			case "coverage_at_observation":
				proof.CoverageValidUntil = proof.ObservedAt
			case "legacy_accepted":
				proof.AcceptedRows = 2
			case "legacy_expired":
				proof.ExpiredRows = 2
			case "legacy_built":
				proof.BuiltAt = proof.ObservedAt
			case "legacy_until":
				proof.ValidUntil = proof.CoverageValidUntil
			case "global_content_expiry":
				snapshot.ContentValidUntil = proof.CoverageValidUntil
			case "unknown_version":
				proof.Version = 3
			}
			if proof.Validate(clock(), snapshot.PublishedAt, snapshot.ContentValidUntil) == nil {
				t.Fatal("invalid snapshot proof metadata accepted")
			}
			plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
			if err != nil || len(plan.State.Sources) != 0 {
				t.Fatal("invalid snapshot proof reached current state", err)
			}
		})
	}
}

func TestVRPObservationProofRequiresEveryOriginalRowAndExactMinimumExpiry(t *testing.T) {
	for _, kind := range []string{"missing_row", "extra_row", "other_kind", "expiry_missing", "expiry_before_observation", "expiry_at_observation", "minimum_extended", "minimum_reduced"} {
		t.Run(kind, func(t *testing.T) {
			policy, snapshot, binding := vrpObservationSnapshot()
			switch kind {
			case "missing_row":
				snapshot.Records = snapshot.Records[1:]
			case "extra_row":
				snapshot.Records = append(snapshot.Records, snapshot.Records[0])
			case "other_kind":
				snapshot.Records = append(snapshot.Records, NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &GeoEvidence{Prefix: netip.MustParsePrefix("1.1.1.0/24")}})
			case "expiry_missing":
				snapshot.Records[0].VRP.ValidUntil = time.Time{}
			case "expiry_before_observation":
				snapshot.Records[0].VRP.ValidUntil = snapshot.VRPProof.ObservedAt.Add(-time.Second)
			case "expiry_at_observation":
				snapshot.Records[0].VRP.ValidUntil = snapshot.VRPProof.ObservedAt
			case "minimum_extended":
				snapshot.VRPProof.CoverageValidUntil = snapshot.VRPProof.CoverageValidUntil.Add(time.Second)
			case "minimum_reduced":
				snapshot.VRPProof.CoverageValidUntil = snapshot.VRPProof.CoverageValidUntil.Add(-time.Second)
			}
			if _, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding); err == nil {
				t.Fatal("original snapshot rows did not match the authenticated proof")
			}
		})
	}
}

func TestVRPObservationProofPreservesSourceExpiryAndEvaluationBinding(t *testing.T) {
	policy, snapshot, binding := vrpObservationSnapshot()
	for _, now := range []time.Time{clock().Add(time.Second), snapshot.PublishedAt.Add(policy.MaxAge)} {
		if now.Equal(snapshot.PublishedAt.Add(policy.MaxAge)) {
			// A new complete-body assessment cannot renew the original publication.
			snapshot.VRPProof.EvaluatedAt = now
		}
		plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, now, binding)
		if err != nil || len(plan.State.Sources) != 0 {
			t.Fatal("snapshot observation renewed an intake or source freshness clock", err)
		}
	}
}

func TestVRPSourceProofPreservesLegacySerializationAndRejectsMixedVersions(t *testing.T) {
	_, snapshot, _ := vrpProofSnapshot()
	proof := snapshot.VRPProof
	legacy := struct {
		Version                          uint16
		Rows, AcceptedRows, ExpiredRows  uint64
		BuiltAt, EvaluatedAt, ValidUntil time.Time
	}{proof.Version, proof.Rows, proof.AcceptedRows, proof.ExpiredRows, proof.BuiltAt, proof.EvaluatedAt, proof.ValidUntil}
	want, _ := json.Marshal(legacy)
	actual, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatal("v1 state authentication bytes changed", err)
	}
	for _, kind := range []string{"retained", "observed", "coverage"} {
		mixed := *proof
		switch kind {
		case "retained":
			mixed.RetainedRows = mixed.Rows
		case "observed":
			mixed.ObservedAt = mixed.BuiltAt
		case "coverage":
			mixed.CoverageValidUntil = mixed.ValidUntil
		}
		if mixed.Validate(clock(), snapshot.PublishedAt, snapshot.ContentValidUntil) == nil {
			t.Fatal("legacy proof borrowed snapshot-observation semantics")
		}
	}
}
