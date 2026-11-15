package intelligence

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFusedTier1VerificationPreservesExactHistoryAndClassification(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "missing-path-family"}[missing], func(t *testing.T) {
			root, now := t.TempDir(), clock()
			binding := sha256.Sum256([]byte("fused-tier1-parity"))
			path := filepath.Join(root, ".atlas-private", tier1HistoryName)
			for _, elapsed := range []time.Duration{0, 24 * time.Hour} {
				at := now.Add(elapsed)
				state := qualifiedTier1Fixture(t, root, at, binding, missing)
				before, readErr := os.ReadFile(path)
				if readErr != nil && !os.IsNotExist(readErr) {
					t.Fatal(readErr)
				}
				full, err := ObserveTier1State(context.Background(), root, state, binding, at)
				if err != nil {
					t.Fatal(err)
				}
				fullHistory, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if os.IsNotExist(readErr) {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, before, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				verified, actual, err := VerifyPrivateStateForTier1(context.Background(), root, binding)
				if err != nil || !reflect.DeepEqual(state, actual) {
					t.Fatal("full verification changed the state", err)
				}
				afterConstructor, constructorErr := os.ReadFile(path)
				if !reflect.DeepEqual(before, afterConstructor) || os.IsNotExist(readErr) != os.IsNotExist(constructorErr) {
					t.Fatal("discovery constructor changed observation history")
				}
				if verified.tier1 == nil || verified.tier1.failed || len(verified.tier1.sources) != len(state.Sources) {
					t.Fatal("complete authenticated discovery unavailable")
				}
				for repeat := 0; repeat < 2; repeat++ {
					fused, err := verified.ObserveTier1State(context.Background(), root, binding, at)
					if err != nil {
						t.Fatal(err)
					}
					fusedHistory, err := os.ReadFile(path)
					if err != nil || !reflect.DeepEqual(fullHistory, fusedHistory) || !reflect.DeepEqual(full.snapshot, fused.snapshot) {
						t.Fatal("discovery changed exact history or classification", err)
					}
					fullID, e1 := full.MaterializationIdentity()
					fusedID, e2 := fused.MaterializationIdentity()
					if e1 != nil || e2 != nil || fullID != fusedID || full.Relation(100, 101) != fused.Relation(100, 101) || full.Relation(101, 100) != fused.Relation(101, 100) {
						t.Fatal("discovery changed materialization identity or direction", e1, e2)
					}
				}
			}
		})
	}
}

func TestFusedTier1VerificationKeepsGenericVerificationGraphFree(t *testing.T) {
	f := newReceiptSealFixture(t)
	plain, state, err := VerifyPrivateState(context.Background(), f.root, f.binding)
	if err != nil || plain.tier1 != nil {
		t.Fatal("generic verifier allocated Tier-1 discovery", err)
	}
	full, err := plain.ObserveTier1State(context.Background(), f.root, f.binding, state.EvaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	fused, actual, err := VerifyPrivateStateForTier1(context.Background(), f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(fused.tier1.relations.edges) != 0 || len(fused.tier1.relations.nodes) != 0 {
		t.Fatal("non-routing input manufactured a graph")
	}
	observed, err := fused.ObserveTier1State(context.Background(), f.root, f.binding, actual.EvaluatedAt)
	if err != nil || !reflect.DeepEqual(full.snapshot, observed.snapshot) || observed.Validate(actual, actual.EvaluatedAt) == nil {
		t.Fatal("non-routing discovery changed explicit unknown semantics", err)
	}
}

func TestFusedTier1SpecificFailureIsDeferredUntilPendingHistory(t *testing.T) {
	f := newReceiptSealFixture(t)
	f.state.Sources[0].RecordPartitions = nil
	f.state.Sources[0].Records = []NormalizedRecord{{Version: 3, Kind: RecordPath, Path: &ScopedPath{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"), Observation: PathObservation{
			Origin: 100, Current: false, Family: "synthetic", OriginOutward: true,
			Segments: []PathSegment{{ASSequence, []uint32{100}}}}}}}
	f.saveState(t)
	v, state, err := VerifyPrivateStateForTier1(context.Background(), f.root, f.binding)
	if err != nil {
		t.Fatal("Tier-1 predicate suppressed the complete semantic verification", err)
	}
	path := filepath.Join(f.root, ".atlas-private", tier1HistoryName)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("constructor wrote an observation attempt", err)
	}
	if _, err = v.ObserveTier1State(context.Background(), f.root, f.binding, state.EvaluatedAt); err == nil || err.Error() != "noncurrent Tier-1 path receipt" {
		t.Fatal("deferred source predicate did not fail during observation", err)
	}
	history, err := loadTier1History(context.Background(), f.root, f.binding)
	if err != nil || history.Pending != f.stateHash || len(history.Epochs) != 0 {
		t.Fatal("failed discovery disappeared from source history", err)
	}
}

func TestFusedTier1DiscoveryStopsAccumulatingAfterFirstDeferredFailure(t *testing.T) {
	discovery := &tier1Discovery{relations: NewRelationships(true), sources: make([]tier1SourceDiscovery, 2)}
	discovery.collect(0, NormalizedRecord{Version: 3, Kind: RecordRelationship,
		Relationship: &RelationshipRecord{100, 100, Peer}})
	first := discovery.sources[0].err
	if first == nil || !discovery.failed {
		t.Fatal("invalid directed relationship did not defer its error")
	}
	for i := uint32(0); i < 1000; i++ {
		discovery.collect(1, NormalizedRecord{Version: 3, Kind: RecordRelationship,
			Relationship: &RelationshipRecord{1000 + i, 3000 + i, Peer}})
	}
	if len(discovery.relations.edges) != 0 || len(discovery.relations.nodes) != 0 || discovery.sources[1].err != nil || !errors.Is(discovery.sources[0].err, first) {
		t.Fatal("discovery grew or lost the original error after failure")
	}
}

// Synthetic disk-backed normalized records measure only setup reuse. They are
// neither production inputs nor evidence that a hosted warm-runtime gate passed.
func BenchmarkTier1VerifiedSetup100kGeo(b *testing.B) {
	ctx, root, now := context.Background(), b.TempDir(), clock()
	policy, snapshot, binding := stateFixture()
	store, err := NewRecordStore(root, DefaultRecordStoreLimits())
	if err != nil {
		b.Fatal(err)
	}
	writer := store.Writer(ctx)
	defer writer.Abort()
	for i := uint32(0); i < 100_000; i++ {
		address := netip.AddrFrom4([4]byte{198, byte(i >> 16), byte(i >> 8), byte(i)})
		record := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &GeoEvidence{
			Family: policy.Family, Weight: policy.Weight, Prefix: netip.PrefixFrom(address, 32),
			PhysicalCountry: "US", Region: "Synthetic region", City: "Synthetic city", Current: true}}
		if err := writer.Append(record); err != nil {
			b.Fatal(err)
		}
	}
	snapshot.Records = nil
	snapshot.RecordPartitions, err = writer.Finish()
	if err != nil {
		b.Fatal(err)
	}
	plan, err := ReconcilePartitioned(ctx, root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, now, binding)
	if err != nil {
		b.Fatal(err)
	}
	if err := SavePrivateState(root, plan.State); err != nil {
		b.Fatal(err)
	}
	if err := SealPrivateState(ctx, root, binding); err != nil {
		b.Fatal(err)
	}
	var inputBytes int64
	var records uint64
	for _, source := range plan.State.Sources {
		for _, part := range source.RecordPartitions {
			inputBytes += part.DecodedBytes
			records += part.Records
		}
	}
	if records != 100_000 {
		b.Fatal("normalized benchmark population changed")
	}
	baseline, err := ObserveTier1State(ctx, root, plan.State, binding, now)
	if err != nil {
		b.Fatal(err)
	}
	expected, err := baseline.MaterializationIdentity()
	if err != nil {
		b.Fatal(err)
	}
	historyPath := filepath.Join(root, ".atlas-private", tier1HistoryName)
	expectedHistory, err := os.ReadFile(historyPath)
	if err != nil {
		b.Fatal(err)
	}
	for _, fused := range []bool{false, true} {
		b.Run(map[bool]string{false: "full", true: "fused"}[fused], func(b *testing.B) {
			verify := VerifyPrivateState
			if fused {
				verify = VerifyPrivateStateForTier1
			}
			b.SetBytes(inputBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v, _, err := verify(ctx, root, binding)
				if err != nil {
					b.Fatal(err)
				}
				q, err := v.ObserveTier1State(ctx, root, binding, now)
				if err != nil {
					b.Fatal(err)
				}
				identity, err := q.MaterializationIdentity()
				if err != nil || identity != expected {
					b.Fatal("optimized setup changed observation identity", err)
				}
			}
			b.StopTimer()
			actualHistory, err := os.ReadFile(historyPath)
			if err != nil || string(actualHistory) != string(expectedHistory) {
				b.Fatal("optimized setup changed history", err)
			}
			b.ReportMetric(float64(records), "records/op")
		})
	}
}
