package intelligence

import (
	"net/netip"
	"testing"
	"time"
)

func vrpProofSnapshot() (SourcePolicy, SourceSnapshot, [32]byte) {
	policy, snapshot, binding := stateFixture()
	snapshot.ContentValidUntil = clock().Add(time.Hour)
	snapshot.Records = []NormalizedRecord{{Version: 3, Kind: RecordVRP, VRP: &VRP{Prefix: netip.MustParsePrefix("8.8.8.0/24"), MaxLength: 24, ASN: 13335, ValidUntil: snapshot.ContentValidUntil}}}
	snapshot.VRPProof = &VRPSourceProof{Version: 1, Rows: 2, AcceptedRows: 1, ExpiredRows: 1, BuiltAt: snapshot.PublishedAt, EvaluatedAt: clock(), ValidUntil: snapshot.ContentValidUntil}
	return policy, snapshot, binding
}

func TestVRPSourceProofBindsRetainedCountAndCopiesReceipt(t *testing.T) {
	policy, snapshot, binding := vrpProofSnapshot()
	plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil || len(plan.State.Sources) != 1 || plan.State.Sources[0].Receipt == nil || plan.State.Sources[0].Receipt.VRPProof == nil {
		t.Fatal("complete-body proof was not retained", plan, err)
	}
	if !plan.State.Sources[0].ExpiresAt.Equal(snapshot.ContentValidUntil) {
		t.Fatal("source lifetime exceeded earliest cryptographic row expiry")
	}
	snapshot.VRPProof.AcceptedRows, snapshot.VRPProof.Rows = 2, 3
	if plan.State.Sources[0].Receipt.VRPProof.AcceptedRows != 1 {
		t.Fatal("stored proof borrowed caller-mutable metadata")
	}
	if _, err = Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding); err == nil {
		t.Fatal("complete-body proof accepted missing normalized rows")
	}
}

func TestVRPSourceProofRejectsWrongEvaluationAndExpiryBindings(t *testing.T) {
	for _, scenario := range []string{"evaluation_clock", "earliest_expiry", "expired", "future_build", "publication_after_build", "row_accounting"} {
		t.Run(scenario, func(t *testing.T) {
			policy, snapshot, binding := vrpProofSnapshot()
			now := clock()
			switch scenario {
			case "evaluation_clock":
				snapshot.VRPProof.EvaluatedAt = now.Add(-time.Second)
			case "earliest_expiry":
				snapshot.VRPProof.ValidUntil = snapshot.ContentValidUntil.Add(time.Hour)
			case "expired":
				snapshot.VRPProof.ValidUntil, snapshot.ContentValidUntil = now, now
			case "future_build":
				snapshot.VRPProof.BuiltAt = now.Add(25 * time.Hour)
			case "publication_after_build":
				snapshot.VRPProof.BuiltAt = snapshot.PublishedAt.Add(-time.Second)
			case "row_accounting":
				snapshot.VRPProof.ExpiredRows = 0
			}
			if snapshot.VRPProof.Validate(now, snapshot.PublishedAt, snapshot.ContentValidUntil) == nil {
				t.Fatal("unbound complete-body proof validated")
			}
			plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, now, binding)
			if err != nil || len(plan.State.Sources) != 0 {
				t.Fatal("unbound complete-body proof reached current state", plan, err)
			}
		})
	}
}

func TestVRPSourceProofCannotRenewAcrossEvaluationClocks(t *testing.T) {
	policy, snapshot, binding := vrpProofSnapshot()
	first, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil || len(first.State.Sources) != 1 {
		t.Fatal(err)
	}
	next, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(time.Second), binding)
	if err != nil || len(next.State.Sources) != 0 || !next.FullRebuild {
		t.Fatal("previous count/expiry assessment borrowed a new evaluation clock", next, err)
	}
}
