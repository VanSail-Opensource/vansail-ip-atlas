package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Review fixtures deliberately authenticate alternate encodings or invalid
// record semantics. A valid local MAC alone must never authorize either reuse.
func reviewAuthenticateStateBytes(t *testing.T, root string, binding [32]byte, data []byte) {
	t.Helper()
	if err := atomicPrivateBytes(root, "state-v1.json", data); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(root, ".atlas-private", "state-seal.key"))
	if err != nil {
		t.Fatal(err)
	}
	seal := stateSeal{Version: 2, PolicyHash: binding, StateHash: sha256.Sum256(data)}
	seal.MAC = sealMAC(key, binding, seal.StateHash)
	encoded, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	if err = atomicPrivateBytes(root, "state-seal-v2.json", encoded); err != nil {
		t.Fatal(err)
	}
}

func TestFusedTier1ReviewPreservesOrderedFailures(t *testing.T) {
	for _, first := range []string{"receipt", "discovery"} {
		t.Run(first, func(t *testing.T) {
			ctx, root, now := context.Background(), t.TempDir(), clock()
			binding := sha256.Sum256([]byte("review-ordered-discovery"))
			state := qualifiedTier1Fixture(t, root, now, binding, false)
			if first == "receipt" {
				state.Sources[0].Receipt.PayloadVerified = false
				state.Sources[1].RecordPartitions = nil
				state.Sources[1].Records = []NormalizedRecord{{Version: 3, Kind: RecordPath, Path: &ScopedPath{Observation: PathObservation{Family: "ris", Current: false}}}}
			} else {
				state.Sources[0].RecordPartitions = nil
				state.Sources[0].Records = []NormalizedRecord{{Version: 3, Kind: RecordRelationship, Relationship: &RelationshipRecord{From: 0, To: 100, Relation: Peer}}}
				state.Sources[1].Receipt.PayloadVerified = false
			}
			resealTier1Fixture(t, root, state, binding)
			_, fullErr := ObserveTier1State(ctx, root, state, binding, now)
			if fullErr == nil {
				t.Fatal("review fixture did not fail")
			}
			path := filepath.Join(root, ".atlas-private", tier1HistoryName)
			fullHistory, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			v, _, err := VerifyPrivateStateForTier1(ctx, root, binding)
			if err != nil {
				t.Fatal("Tier-1-specific error escaped before its observation", err)
			}
			if _, err = os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("verification created history", err)
			}
			_, fusedErr := v.ObserveTier1State(ctx, root, binding, now)
			if fusedErr == nil || fusedErr.Error() != fullErr.Error() {
				t.Fatal("fused discovery reordered source failure", fullErr, fusedErr)
			}
			fusedHistory, err := os.ReadFile(path)
			if err != nil || string(fusedHistory) != string(fullHistory) {
				t.Fatal("failed observation did not preserve identical pending history", err)
			}
		})
	}
}

func TestFusedTier1ReviewFinishesStructuralValidationAfterDiscoveryFailure(t *testing.T) {
	ctx, root, now := context.Background(), t.TempDir(), clock()
	binding := sha256.Sum256([]byte("review-late-structural-failure"))
	state := qualifiedTier1Fixture(t, root, now, binding, false)
	state.Sources[0].RecordPartitions = nil
	state.Sources[0].Records = []NormalizedRecord{{Version: 3, Kind: RecordRelationship, Relationship: &RelationshipRecord{From: 0, To: 100, Relation: Peer}}}
	bad, err := json.Marshal(NormalizedRecord{Version: 3, Kind: RecordPath})
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(recordHeader), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(raw[len(recordHeader):], uint32(len(bad)))
	raw = append(raw, bad...)
	part := RecordPartition{SHA256: sha256.Sum256(raw), Bytes: int64(len(raw)), Records: 1}
	state.Sources[2].RecordPartitions = []RecordPartition{part}
	if err = os.WriteFile(filepath.Join(root, ".atlas-private", "records-v2", partitionName(part)), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyStoredSourceObjects(ctx, root, state.Sources[2]); err != nil {
		t.Fatal("fixture must pass exact-byte integrity", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	reviewAuthenticateStateBytes(t, root, binding, data)
	if _, _, err = VerifyPrivateStateForTier1(ctx, root, binding); err == nil {
		t.Fatal("deferred discovery error skipped a later invalid normalized union")
	}
	if _, err = os.Stat(filepath.Join(root, ".atlas-private", tier1HistoryName)); !os.IsNotExist(err) {
		t.Fatal("failed initial structural verification changed history", err)
	}
}

func TestFusedTier1ReviewAuthenticatesActualBytesAndCanonicalDiscoveryIdentity(t *testing.T) {
	ctx, root, now := context.Background(), t.TempDir(), clock()
	binding := sha256.Sum256([]byte("review-noncanonical-state"))
	state := qualifiedTier1Fixture(t, root, now, binding, false)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	reviewAuthenticateStateBytes(t, root, binding, data)
	full, err := ObserveTier1State(ctx, root, state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".atlas-private", tier1HistoryName)
	fullHistory, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	v, _, err := VerifyPrivateStateForTier1(ctx, root, binding)
	if err != nil {
		t.Fatal(err)
	}
	fused, err := v.ObserveTier1State(ctx, root, binding, now)
	if err != nil {
		t.Fatal("valid alternate state JSON spelling changed observation", err)
	}
	fullID, fullErr := full.MaterializationIdentity()
	fusedID, fusedErr := fused.MaterializationIdentity()
	if fullErr != nil || fusedErr != nil || fusedID != fullID {
		t.Fatal("observation identity changed", fullErr, fusedErr)
	}
	fusedHistory, err := os.ReadFile(path)
	if err != nil || string(fusedHistory) != string(fullHistory) {
		t.Fatal("alternate state spelling changed history", err)
	}
}

func TestFusedTier1ReviewRejectsMutationBeforeReuse(t *testing.T) {
	for _, mutation := range []string{"chunk", "state", "seal", "key", "resealed-state", "root", "copy", "nil", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			f := newReceiptSealFixture(t)
			ctx := context.Background()
			v, _, err := VerifyPrivateStateForTier1(ctx, f.root, f.binding)
			if err != nil {
				t.Fatal(err)
			}
			root, path := f.root, ""
			switch mutation {
			case "chunk":
				path = filepath.Join(root, ".atlas-private", "records-v2", partitionName(f.state.Sources[0].RecordPartitions[0]))
			case "state":
				path = filepath.Join(root, ".atlas-private", "state-v1.json")
			case "seal":
				path = filepath.Join(root, ".atlas-private", "state-seal-v2.json")
			case "key":
				path = filepath.Join(root, ".atlas-private", "state-seal.key")
			case "resealed-state":
				f.state.EvaluatedAt = f.state.EvaluatedAt.Add(1)
				f.saveState(t)
			case "root":
				root = t.TempDir()
			case "copy":
				copy := *v
				v = &copy
			case "nil":
				v = nil
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if path != "" {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[0] ^= 1
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = v.ObserveTier1State(ctx, root, f.binding, f.state.EvaluatedAt); err == nil {
				t.Fatal("fused discovery accepted mutated authentication")
			}
			if _, err = os.Stat(filepath.Join(f.root, ".atlas-private", tier1HistoryName)); !os.IsNotExist(err) {
				t.Fatal("rejected reuse created an observation", err)
			}
		})
	}
}

func TestFusedTier1ReviewCallerStateCannotRewriteDiscovery(t *testing.T) {
	ctx, root, now := context.Background(), t.TempDir(), clock()
	binding := sha256.Sum256([]byte("review-owned-discovery"))
	state := qualifiedTier1Fixture(t, root, now, binding, false)
	state.Sources[0].RecordPartitions = nil
	state.Sources[0].Records = []NormalizedRecord{{Version: 3, Kind: RecordRelationship, Relationship: &RelationshipRecord{From: 100, To: 101, Relation: Customer}}}
	resealTier1Fixture(t, root, state, binding)
	v, callerState, err := VerifyPrivateStateForTier1(ctx, root, binding)
	if err != nil {
		t.Fatal(err)
	}
	callerState.Sources[0].Records[0].Relationship.Relation = Peer
	callerState.Sources[0].Fingerprint[0] ^= 1
	q, err := v.ObserveTier1State(ctx, root, binding, now)
	if err != nil || q.Relation(100, 101) != Customer || q.ValidateObservation(state, now) != nil {
		t.Fatal("caller-owned state rewrote private discovery", err)
	}
}
