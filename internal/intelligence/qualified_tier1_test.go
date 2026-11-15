package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func qualifiedTier1Fixture(t *testing.T, root string, now time.Time, binding [32]byte, missingFamily bool) BuildState {
	t.Helper()
	basePolicy, baseSnapshot, _ := stateFixture()
	var policies []SourcePolicy
	var snapshots []SourceSnapshot
	for _, id := range []string{"relations", "ris", "views"} {
		if missingFamily && id == "views" {
			continue
		}
		policy, snapshot := basePolicy, baseSnapshot
		policy.ID, policy.Family = id, id
		snapshot.ID, snapshot.PublishedAt, snapshot.NormalizationPolicyHash = id, now, binding
		snapshot.PayloadHash = sha256.Sum256([]byte("synthetic-private-" + id + now.String()))
		snapshot.ProofPayloadHash = snapshot.PayloadHash
		snapshot.Records = nil
		if id == "relations" {
			for _, pair := range [][2]uint32{{100, 200}, {100, 300}, {200, 300}} {
				snapshot.Records = append(snapshot.Records, NormalizedRecord{Version: 3, Kind: RecordRelationship, Relationship: &RelationshipRecord{pair[0], pair[1], Peer}})
			}
			for _, asn := range []uint32{100, 200, 300} {
				snapshot.Records = append(snapshot.Records, NormalizedRecord{Version: 3, Kind: RecordRelationship, Relationship: &RelationshipRecord{asn, asn + 1, Customer}})
			}
		} else {
			for _, asn := range []uint32{100, 200, 300} {
				snapshot.Records = append(snapshot.Records, NormalizedRecord{Version: 3, Kind: RecordPath, Path: &ScopedPath{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Observation: PathObservation{Origin: asn, Current: true, Family: id, OriginOutward: true, Segments: []PathSegment{{ASSequence, []uint32{asn}}}}}})
			}
		}
		policies, snapshots = append(policies, policy), append(snapshots, snapshot)
	}
	plan, err := ReconcilePartitioned(context.Background(), root, BuildState{}, policies, snapshots, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = SavePrivateState(root, plan.State); err != nil {
		t.Fatal(err)
	}
	// Synthetic private protocol fixture only; this does not certify any real
	// source, rights review, publication clock or production capability.
	if err = SealPrivateState(context.Background(), root, binding); err != nil {
		t.Fatal(err)
	}
	return plan.State
}

func TestQualifiedTier1BindsWholeStateAndPreservesFirstSnapshotUnknown(t *testing.T) {
	root, now := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("synthetic-tier-policy"))
	state := qualifiedTier1Fixture(t, root, now, binding, false)
	q, err := QualifyTier1State(context.Background(), root, state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Validate(state, now.Add(time.Hour)); err != nil {
		t.Fatal("publication lifetime recheck failed", err)
	}
	for _, asn := range []uint32{100, 200, 300} {
		value := q.Result(asn)
		if value.Class != "unknown" || value.Stability != "pending" || !value.StatisticsKnown {
			t.Fatal("first snapshot invented stable Tier-1 membership", value)
		}
	}
	if q.Relation(100, 101) != Customer || q.Relation(101, 100) != TransitUpstream || q.Result(999).Class != "unknown" {
		t.Fatal("qualified context changed relationship perspective or unknowns")
	}
	encoded, _ := json.Marshal(state)
	for _, scenario := range []string{"source_fingerprint", "chunk_root", "policy", "clock"} {
		var edited BuildState
		if err = json.Unmarshal(encoded, &edited); err != nil {
			t.Fatal(err)
		}
		switch scenario {
		case "source_fingerprint":
			edited.Sources[0].Fingerprint[0] ^= 1
		case "chunk_root":
			edited.Sources[0].RecordPartitions[0].SHA256[0] ^= 1
		case "policy":
			edited.PolicyHash[0] ^= 1
		case "clock":
			edited.EvaluatedAt = edited.EvaluatedAt.Add(time.Second)
		}
		if err = q.Validate(edited, now); err == nil {
			t.Fatal("ordinary edited state borrowed an authenticated context", scenario)
		}
	}
	if err = q.Validate(state, now.Add(720*time.Hour)); err == nil {
		t.Fatal("expired context remained valid")
	}
}

func TestQualifiedTier1HistoryUsesRealSeparatedAuthenticatedEpochs(t *testing.T) {
	root, now := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("synthetic-tier-policy"))
	first := qualifiedTier1Fixture(t, root, now, binding, false)
	q, err := QualifyTier1State(context.Background(), root, first, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveQualifiedTier1History(context.Background(), root, q); err != nil {
		t.Fatal(err)
	}
	for _, hours := range []int{24} {
		later := now.Add(time.Duration(hours) * time.Hour)
		state := qualifiedTier1Fixture(t, root, later, binding, false)
		next, err := QualifyTier1State(context.Background(), root, state, binding, later)
		if err != nil {
			t.Fatal(err)
		}
		value := next.Result(100)
		if value.Class != "tier1_candidate" || value.Stability != "stable" {
			t.Fatal("history separation changed or manufactured membership", hours, value)
		}
		if err = SaveQualifiedTier1History(context.Background(), root, next); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, ".atlas-private", tier1HistoryName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var history tier1History
	if err = json.Unmarshal(data, &history); err != nil {
		t.Fatal(err)
	}
	history.Epochs[0].Candidates[0] = 101
	tampered, _ := json.Marshal(history)
	if err = os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadTier1History(context.Background(), root, binding); err == nil {
		t.Fatal("unauthenticated old membership was accepted")
	}
}

func TestUnavailableTier1ObservationRemainsAuthenticatedAndUnknown(t *testing.T) {
	root, now := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("synthetic-unavailable-tier-policy"))
	state := qualifiedTier1Fixture(t, root, now, binding, true)
	q, err := ObserveTier1State(context.Background(), root, state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.ValidateObservation(state, now); err != nil {
		t.Fatal("missing family invalidated authenticated observation", err)
	}
	if q.Validate(state, now) == nil || SaveQualifiedTier1History(context.Background(), root, q) == nil {
		t.Fatal("unavailable observation asserted positive qualification")
	}
	for _, asn := range []uint32{100, 101, 999} {
		result := q.Result(asn)
		if result.Class != "unknown" || result.Stability != "unavailable" || result.StatisticsKnown {
			t.Fatal("missing family invented Tier-1 information", result)
		}
	}
	before, err := os.ReadFile(filepath.Join(root, ".atlas-private", "tier1-history-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyTier1ObservationHistory(context.Background(), root, q); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, ".atlas-private", "tier1-history-v2.json"))
	if err != nil || string(after) != string(before) {
		t.Fatal("verification changed observed history", err)
	}
	changed := state
	changed.EvaluatedAt = now.Add(time.Second)
	if q.ValidateObservation(changed, now.Add(time.Second)) == nil || q.ValidateObservation(state, q.ValidUntil()) == nil || (*QualifiedTier1)(nil).ValidateObservation(state, now) == nil {
		t.Fatal("missing observations bypassed state or lifetime binding")
	}
}

func TestNonRoutingStatePreservesUnavailableTier1History(t *testing.T) {
	root := t.TempDir()
	policy, snapshot, binding := stateFixture()
	plan, err := ReconcilePartitioned(context.Background(), root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = SavePrivateState(root, plan.State); err != nil {
		t.Fatal(err)
	}
	if err = SealPrivateState(context.Background(), root, binding); err != nil {
		t.Fatal(err)
	}
	q, err := ObserveTier1State(context.Background(), root, plan.State, binding, clock())
	if err != nil {
		t.Fatal(err)
	}
	if err = q.ValidateObservation(plan.State, clock()); err != nil {
		t.Fatal(err)
	}
	if q.Validate(plan.State, clock()) == nil || q.Result(13335).Class != "unknown" || q.Relation(13335, 15169) != UnknownRelation {
		t.Fatal("nonrouting state invented classification or relationships")
	}
	if err = VerifyTier1ObservationHistory(context.Background(), root, q); err != nil {
		t.Fatal(err)
	}
}

func TestTier1MaterializationIdentityBindsDerivedHistoryOutcome(t *testing.T) {
	root, now := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("synthetic-materialization-policy"))
	state := qualifiedTier1Fixture(t, root, now, binding, false)
	q, err := ObserveTier1State(context.Background(), root, state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	want, err := q.MaterializationIdentity()
	if err != nil || want == ([32]byte{}) {
		t.Fatal("identity unavailable", err)
	}
	if again, err := q.MaterializationIdentity(); err != nil || again != want {
		t.Fatal("identity is not deterministic", err)
	}
	for _, mutate := range []func(*QualifiedTier1){
		func(v *QualifiedTier1) { v.expires = v.expires.Add(-time.Second) },
		func(v *QualifiedTier1) { v.observationHash[0] ^= 1 },
		func(v *QualifiedTier1) { v.snapshot.Eligible = false },
		func(v *QualifiedTier1) { v.snapshot.Results[0].Stability = "stable" },
		func(v *QualifiedTier1) { v.snapshot.Results[0].CustomerCone++ },
	} {
		changed := *q
		changed.snapshot.Results = append([]Tier1Result(nil), q.snapshot.Results...)
		mutate(&changed)
		got, err := changed.MaterializationIdentity()
		if err != nil || got == want {
			t.Fatal("different derived routing outcome reused materialization identity", err)
		}
	}
	for _, invalid := range []*QualifiedTier1{nil, {}} {
		if _, err = invalid.MaterializationIdentity(); err == nil {
			t.Fatal("ordinary zero context supplied an authenticated cache identity")
		}
	}
}

func TestQualifiedTier1HistoryNeverSkipsInterveningObservation(t *testing.T) {
	for _, disqualified := range []bool{false, true} {
		t.Run(map[bool]string{false: "recent_eligible", true: "disqualified"}[disqualified], func(t *testing.T) {
			root, now := t.TempDir(), clock()
			binding := sha256.Sum256([]byte("synthetic-tier-policy"))
			first := qualifiedTier1Fixture(t, root, now, binding, false)
			q, err := QualifyTier1State(context.Background(), root, first, binding, now)
			if err != nil {
				t.Fatal(err)
			}
			if err = SaveQualifiedTier1History(context.Background(), root, q); err != nil {
				t.Fatal(err)
			}
			interveningClock := now.Add(time.Hour)
			intervening := qualifiedTier1Fixture(t, root, interveningClock, binding, disqualified)
			next, err := QualifyTier1State(context.Background(), root, intervening, binding, interveningClock)
			if disqualified {
				if err == nil {
					t.Fatal("missing family qualified")
				}
			} else {
				if err != nil || next.Result(100).Class != "unknown" || next.Result(100).Stability != "pending" {
					t.Fatal("short separation qualified", err)
				}
				if err = SaveQualifiedTier1History(context.Background(), root, next); err != nil {
					t.Fatal(err)
				}
			}
			laterClock := now.Add(24 * time.Hour)
			later := qualifiedTier1Fixture(t, root, laterClock, binding, false)
			last, err := QualifyTier1State(context.Background(), root, later, binding, laterClock)
			if err != nil || last.Result(100).Class != "unknown" || last.Result(100).Stability != "pending" {
				t.Fatal("older success bypassed an intervening snapshot", last, err)
			}
		})
	}
}

func TestQualifiedTier1RejectsMissingIndependentFamily(t *testing.T) {
	root, now := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("synthetic-tier-policy"))
	state := qualifiedTier1Fixture(t, root, now, binding, true)
	if _, err := QualifyTier1State(context.Background(), root, state, binding, now); err == nil {
		t.Fatal("one MRT family qualified Tier-1 derivation")
	}
}

func TestTier1EvaluationPrecedesPublicationAndRepeatsAreIdempotent(t *testing.T) {
	for _, intervening := range []string{"none", "missing", "eligible_build_failed", "compute_failed"} {
		t.Run(intervening, func(t *testing.T) {
			root, at := t.TempDir(), clock()
			binding := sha256.Sum256([]byte("evaluation-ledger-policy"))
			first := qualifiedTier1Fixture(t, root, at, binding, false)
			if _, err := ObserveTier1State(context.Background(), root, first, binding, at); err != nil {
				t.Fatal(err)
			}
			if intervening != "none" {
				middleClock := at.Add(time.Hour)
				middle := qualifiedTier1Fixture(t, root, middleClock, binding, intervening == "missing")
				if intervening == "compute_failed" {
					if _, err := BuildQualifiedTier1(context.Background(), root, binding, middleClock, 1); err == nil {
						t.Fatal("work failure missing")
					}
				} else {
					q, err := ObserveTier1State(context.Background(), root, middle, binding, middleClock)
					if err != nil {
						t.Fatal(err)
					}
					if intervening == "missing" && q.Validate(middle, middleClock) == nil {
						t.Fatal("missing family qualified")
					}
				}
				// Deliberately no SaveQualifiedTier1History: capability/output failure
				// must not make the authenticated middle observation disappear.
			}
			laterClock := at.Add(24 * time.Hour)
			later := qualifiedTier1Fixture(t, root, laterClock, binding, false)
			q, err := ObserveTier1State(context.Background(), root, later, binding, laterClock)
			if err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if intervening == "none" {
				want = "stable"
			}
			if q.Result(100).Stability != want {
				t.Fatal("intervening evaluation skipped", intervening, q.Result(100))
			}
			if err := SaveQualifiedTier1History(context.Background(), root, q); err != nil {
				t.Fatal(err)
			}
			again, err := ObserveTier1State(context.Background(), root, later, binding, laterClock)
			if err != nil || !reflect.DeepEqual(q.snapshot, again.snapshot) {
				t.Fatal("same actual epoch changed its public result", err)
			}
		})
	}
}

func resealTier1Fixture(t *testing.T, root string, state BuildState, binding [32]byte) {
	t.Helper()
	if err := SavePrivateState(root, state); err != nil {
		t.Fatal(err)
	}
	if err := SealPrivateState(context.Background(), root, binding); err != nil {
		t.Fatal(err)
	}
}

func TestTier1SameSourceEpochIgnoresLocalClockAndUnrelatedGeo(t *testing.T) {
	root, at := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("relevant-tier-inputs"))
	first := qualifiedTier1Fixture(t, root, at, binding, false)
	if _, err := ObserveTier1State(context.Background(), root, first, binding, at); err != nil {
		t.Fatal(err)
	}
	later := at.Add(24 * time.Hour)
	state := qualifiedTier1Fixture(t, root, later, binding, false)
	stable, err := ObserveTier1State(context.Background(), root, state, binding, later)
	if err != nil || stable.Result(100).Stability != "stable" {
		t.Fatal(stable, err)
	}
	state.EvaluatedAt = later.Add(time.Hour)
	digest := sha256.Sum256([]byte("unrelated country source"))
	state.Sources = append(state.Sources, StoredSource{ID: "unrelated-geo", Fingerprint: digest, ExpiresAt: state.EvaluatedAt.Add(720 * time.Hour), Receipt: &SourceReceipt{PayloadHash: digest, ProofPayloadHash: digest, NormalizationPolicyHash: binding, PublishedAt: state.EvaluatedAt, PayloadVerified: true, SchemaVerified: true}, Records: []NormalizedRecord{{Version: 3, Kind: RecordGeo, Geo: &GeoEvidence{Prefix: netip.MustParsePrefix("8.8.8.0/24"), PhysicalCountry: "US", Family: "unrelated", Weight: 70, Current: true}}}})
	resealTier1Fixture(t, root, state, binding)
	same, err := ObserveTier1State(context.Background(), root, state, binding, state.EvaluatedAt)
	if err != nil || !reflect.DeepEqual(stable.snapshot, same.snapshot) || same.observationHash != stable.observationHash || same.stateHash == stable.stateHash {
		t.Fatal("local clock/Geo changes reset actual source-epoch stability", err)
	}
	if err := same.Validate(state, state.EvaluatedAt); err != nil {
		t.Fatal(err)
	}
}

func TestTier1EpochUsesVerifiedMRTCoverageWithoutRenewingBaseAge(t *testing.T) {
	root, at := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("MRT-observation-epoch"))
	first := qualifiedTier1Fixture(t, root, at, binding, false)
	for i := range first.Sources {
		s := &first.Sources[i]
		if s.ID != "relations" {
			s.Receipt.MRTProof = &MRTSourceProof{Version: 1, Collector: sha256.Sum256([]byte(s.ID)), BasePayloadHash: s.Receipt.PayloadHash, BaseBytes: 100, CapturedAt: at, Through: at}
		}
	}
	resealTier1Fixture(t, root, first, binding)
	if _, err := ObserveTier1State(context.Background(), root, first, binding, at); err != nil {
		t.Fatal(err)
	}
	unchanged := first
	unchanged.EvaluatedAt = at.Add(24 * time.Hour)
	resealTier1Fixture(t, root, unchanged, binding)
	same, err := ObserveTier1State(context.Background(), root, unchanged, binding, unchanged.EvaluatedAt)
	if err != nil || same.Result(100).Stability != "pending" || !same.snapshot.PublishedAt.Equal(at) {
		t.Fatal("local build clock became a source observation", err)
	}
	advanced := qualifiedTier1Fixture(t, root, unchanged.EvaluatedAt, binding, false)
	for i := range advanced.Sources {
		s := &advanced.Sources[i]
		if s.ID == "relations" {
			continue
		}
		base := first.Sources[i].Receipt
		peer := sha256.Sum256([]byte("peer" + s.ID))
		proof := &MRTSourceProof{Version: 1, Collector: sha256.Sum256([]byte(s.ID)), BasePayloadHash: base.PayloadHash, BaseBytes: 100, CapturedAt: at, Through: advanced.EvaluatedAt, Archives: []MRTArchiveProof{{PayloadHash: sha256.Sum256([]byte("complete UPDATE bytes" + s.ID)), From: at, Until: advanced.EvaluatedAt}}, Peers: []MRTPeerBinding{{PeerKey: peer, Session: sha256.Sum256([]byte("session" + s.ID)), PeerTable: 1, AFI: 1}}}
		content, err := proof.ContentHash()
		if err != nil {
			t.Fatal(err)
		}
		s.Receipt.MRTProof = proof
		s.Receipt.PayloadHash = content
		s.Receipt.ProofPayloadHash = content
		s.Receipt.PublishedAt = at
		s.ExpiresAt = at.Add(720 * time.Hour)
	}
	resealTier1Fixture(t, root, advanced, binding)
	q, err := ObserveTier1State(context.Background(), root, advanced, binding, advanced.EvaluatedAt)
	if err != nil || q.Result(100).Stability != "stable" || !q.snapshot.PublishedAt.Equal(advanced.EvaluatedAt) {
		t.Fatal("verified UPDATE observation epoch did not advance", err)
	}
	if !q.expires.Equal(at.Add(720 * time.Hour)) {
		t.Fatal("UPDATE coverage renewed old RIB expiry")
	}
}

func TestTier1LegacyHistoryDoesNotInventEvaluationOutcomes(t *testing.T) {
	root, at := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("legacy-history-policy"))
	state := qualifiedTier1Fixture(t, root, at, binding, false)
	legacy := []byte(`{"Version":1,"Epochs":[{"Candidates":[100,200,300]}]}`)
	path := filepath.Join(root, ".atlas-private", "tier1-history-v1.json")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	q, err := ObserveTier1State(context.Background(), root, state, binding, at)
	if err != nil || q.Result(100).Stability != "pending" {
		t.Fatal("legacy publication history became unobserved evaluation evidence", err)
	}
	kept, err := os.ReadFile(path)
	if err != nil || string(kept) != string(legacy) {
		t.Fatal("legacy audit bytes changed", err)
	}
	before, err := os.ReadFile(filepath.Join(root, ".atlas-private", tier1HistoryName))
	if err != nil {
		t.Fatal(err)
	}
	edited := state
	edited.PolicyHash[0] ^= 1
	if _, err := ObserveTier1State(context.Background(), root, edited, binding, at); err == nil {
		t.Fatal("edited supplied state authenticated")
	}
	after, err := os.ReadFile(filepath.Join(root, ".atlas-private", tier1HistoryName))
	if err != nil || string(before) != string(after) {
		t.Fatal("unauthenticated input rewrote evaluation history", err)
	}
}

func TestTier1CachedStableOutcomeCannotOutliveItsActualAnchor(t *testing.T) {
	root, at := t.TempDir(), clock()
	binding := sha256.Sum256([]byte("anchor-expiry-policy"))
	first := qualifiedTier1Fixture(t, root, at, binding, false)
	if _, err := ObserveTier1State(context.Background(), root, first, binding, at); err != nil {
		t.Fatal(err)
	}
	later := at.Add(24 * time.Hour)
	state := qualifiedTier1Fixture(t, root, later, binding, false)
	stable, err := ObserveTier1State(context.Background(), root, state, binding, later)
	if err != nil || stable.Result(100).Stability != "stable" {
		t.Fatal(err)
	}
	if !stable.expires.Equal(at.Add(720 * time.Hour)) {
		t.Fatal("stable result outlives actual previous sources")
	}
	state.EvaluatedAt = at.Add(721 * time.Hour)
	resealTier1Fixture(t, root, state, binding)
	q, err := ObserveTier1State(context.Background(), root, state, binding, state.EvaluatedAt)
	if err != nil || q.Result(100).Stability != "pending" {
		t.Fatal("expired previous snapshot extended stable membership", err)
	}
}
