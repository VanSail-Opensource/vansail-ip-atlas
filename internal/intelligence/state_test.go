package intelligence

import (
	"crypto/sha256"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func stateFixture() (SourcePolicy, SourceSnapshot, [32]byte) {
	attribution := false
	policy := SourcePolicy{ID: "synthetic-private-fixture", Family: "synthetic-family", Admission: "active", ProofKind: "embedded", FixtureTested: true, RightsReviewed: true, AttributionRequired: &attribution, ParserVersion: 1, SchemaVersion: 3, MaxAge: 720 * time.Hour, Weight: 100}
	evidence := riskEvidence("192.0.2.1", "input-family-overwritten", "malware")
	hash := sha256.Sum256([]byte("synthetic observed bytes, no real source certification"))
	snapshot := SourceSnapshot{ID: policy.ID, PayloadHash: hash, ProofPayloadHash: hash, PublishedAt: clock(), ProofKind: "embedded", PayloadVerified: true, SchemaVerified: true, Records: []NormalizedRecord{{Version: 3, Kind: RecordEvidence, Evidence: &evidence}}}
	policyHash := sha256.Sum256([]byte("synthetic policy"))
	snapshot.NormalizationPolicyHash = policyHash
	snapshot.ParserVersion = policy.ParserVersion
	snapshot.SchemaVersion = policy.SchemaVersion
	return policy, snapshot, policyHash
}
func TestReconcileColdNoChangeClockAdvanceWithdrawalAndDeletion(t *testing.T) {
	policy, snapshot, hash := stateFixture()
	first, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !first.FullRebuild || len(first.State.Sources) != 1 || first.State.Sources[0].Records[0].Evidence.Family != policy.Family {
		t.Fatal("first build or private family binding incorrect")
	}
	same, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if same.FullRebuild {
		t.Fatal("identical inputs and clock missed no-change state")
	}
	aged, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(time.Hour), hash)
	if err != nil || !aged.FullRebuild {
		t.Fatal("decay change hidden behind unchanged payload")
	}
	expired, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(720*time.Hour), hash)
	if err != nil || !expired.FullRebuild || len(expired.State.Sources) != 0 {
		t.Fatal("expired input retained in current store")
	}
	policy.RightsReviewed = false
	withdrawn, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil || !withdrawn.FullRebuild || len(withdrawn.State.Sources) != 0 {
		t.Fatal("rights withdrawal did not retract all influence")
	}
	removed, err := Reconcile(first.State, nil, nil, clock(), hash)
	if err != nil || !removed.FullRebuild || len(removed.ChangedSources) != 1 || len(removed.State.Sources) != 0 {
		t.Fatal("source-list deletion cached old records")
	}
}
func TestReconcileProofFutureSchemaDependencyAndPolicyChanges(t *testing.T) {
	policy, snapshot, hash := stateFixture()
	for _, kind := range []string{"hash", "future", "schema", "commit", "dependency", "parser_version", "record_schema", "normalizer_policy"} {
		p, s := policy, snapshot
		switch kind {
		case "hash":
			s.ProofPayloadHash = sha256.Sum256([]byte("different payload"))
		case "future":
			s.PublishedAt = clock().Add(25 * time.Hour)
		case "schema":
			s.SchemaVerified = false
		case "commit":
			p.ProofKind = "github_commit"
			s.ProofKind = "github_commit"
		case "dependency":
			p.Dependencies = []string{"removed"}
		case "parser_version":
			s.ParserVersion++
		case "record_schema":
			s.SchemaVersion++
		case "normalizer_policy":
			s.NormalizationPolicyHash[0] ^= 1
		}
		plan, err := Reconcile(BuildState{}, []SourcePolicy{p}, []SourceSnapshot{s}, clock(), hash)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.State.Sources) != 0 {
			t.Fatalf("%s bypassed eligibility", kind)
		}
	}
	first, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		t.Fatal(err)
	}
	hash[0] ^= 1
	changed, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil || !changed.FullRebuild {
		t.Fatal("policy hash changed without recompilation")
	}
	policy.Dependencies = []string{policy.ID}
	if _, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash); err == nil {
		t.Fatal("dependency cycle accepted")
	}
}
func TestReconcileSubscriptionItemRetractionAndUnionValidation(t *testing.T) {
	policy, snapshot, hash := stateFixture()
	policy.Subscription = true
	snapshot.Records[0].Evidence.ItemPublishedAt = clock().Add(-167 * time.Hour)
	first, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !first.NextExpiry.Equal(clock().Add(time.Hour)) {
		t.Fatal("oldest item expiry did not bound next refresh")
	}
	expired, err := Reconcile(first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(time.Hour), hash)
	if err != nil || len(expired.State.Sources) != 1 || len(expired.State.Sources[0].Records) != 0 || !expired.FullRebuild {
		t.Fatal("unchanged source retained expired item")
	}
	snapshot.Records[0].Origins = &OriginMapping{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Origins: []uint32{100}}
	if _, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash); err == nil {
		t.Fatal("multiple tagged-union payloads accepted")
	}
}
func TestReconcileSubscriptionWrapperCannotSupplyMissingItemClock(t *testing.T) {
	policy, snapshot, hash := stateFixture()
	policy.Subscription = true
	// Even a new, payload-verified wrapper does not date the contained endpoint.
	snapshot.Records[0].Evidence.ItemPublishedAt = time.Time{}
	plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.State.Sources) != 1 || len(plan.State.Sources[0].Records) != 0 {
		t.Fatal("wrapper publication manufactured item freshness")
	}
}
func TestReconcileExactPayloadsCorrelateFamiliesTransitively(t *testing.T) {
	basePolicy, baseSnapshot, policyHash := stateFixture()
	var policies []SourcePolicy
	var snapshots []SourceSnapshot
	for i, family := range []string{"a", "b", "b", "c", "0-ineligible"} {
		p, s := basePolicy, baseSnapshot
		p.ID, p.Family = string(rune('A'+i)), family
		s.ID = p.ID
		if i >= 2 && i != 4 {
			s.PayloadHash = sha256.Sum256([]byte("second exact snapshot"))
			s.ProofPayloadHash = s.PayloadHash
		}
		if i == 4 {
			p.Admission = "retired"
		}
		policies, snapshots = append(policies, p), append(snapshots, s)
	}
	plan, err := Reconcile(BuildState{}, policies, snapshots, clock(), policyHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.State.Sources) != 4 {
		t.Fatal("source decisions lost during exact-snapshot correlation")
	}
	for _, source := range plan.State.Sources {
		if source.Records[0].Evidence.Family != "a" {
			t.Fatal("identical or transitively correlated snapshots manufactured independent votes")
		}
	}
	for i, j := 0, len(policies)-1; i < j; i, j = i+1, j-1 {
		policies[i], policies[j] = policies[j], policies[i]
		snapshots[i], snapshots[j] = snapshots[j], snapshots[i]
	}
	reversed, err := Reconcile(BuildState{}, policies, snapshots, clock(), policyHash)
	if err != nil || !reflect.DeepEqual(plan.State, reversed.State) {
		t.Fatal("source order changed canonical private evidence families", err)
	}
	for i := range policies {
		if policies[i].ID == "B" {
			policies[i].Admission = "retired"
		}
	}
	withdrawn, err := Reconcile(plan.State, policies, snapshots, clock(), policyHash)
	if err != nil || !withdrawn.FullRebuild {
		t.Fatal("correlation withdrawal did not rebuild dependent families", err)
	}
	for _, source := range withdrawn.State.Sources {
		want := "b"
		if source.ID == "A" {
			want = "a"
		}
		if source.Records[0].Evidence.Family != want {
			t.Fatal("withdrawn bridge retained correlation state")
		}
	}
}
func TestPrivateStateAtomicRoundTripAndCorruption(t *testing.T) {
	policy, snapshot, hash := stateFixture()
	plan, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), hash)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := SavePrivateState(root, plan.State); err != nil {
		t.Fatal(err)
	}
	if err := SavePrivateState(root, plan.State); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateState(root)
	if err != nil || len(loaded.Sources) != 1 || loaded.Sources[0].Fingerprint != plan.State.Sources[0].Fingerprint {
		t.Fatal("state round-trip failed")
	}
	files, err := os.ReadDir(filepath.Join(root, ".atlas-private"))
	if err != nil || len(files) != 1 {
		t.Fatal("partial files retained")
	}
	if err := os.WriteFile(filepath.Join(root, ".atlas-private", "state-v1.json"), []byte(`{"Version":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateState(root); err == nil {
		t.Fatal("corrupt or unknown state version accepted")
	}
}
