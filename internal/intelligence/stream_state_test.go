package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPartitionedReconcileMigratesBindsAndRetractsWithoutTTL(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	policy, snapshot, binding := stateFixture()
	legacy, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ReconcilePartitioned(ctx, root, legacy.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if first.State.Version != 2 || !first.FullRebuild || len(first.State.Sources) != 1 || len(first.State.Sources[0].Records) != 0 || len(first.State.Sources[0].RecordPartitions) != 1 || first.State.Sources[0].Receipt == nil {
		t.Fatal("migration or receipt missing")
	}
	var got []NormalizedRecord
	if err = WalkStoredSource(ctx, root, first.State.Sources[0], func(record NormalizedRecord) error { got = append(got, record); return nil }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, legacy.State.Sources[0].Records) {
		t.Fatal("streamed binding differs from v1 semantics")
	}
	same, err := ReconcilePartitioned(ctx, root, first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil || same.FullRebuild {
		t.Fatalf("no-change %v %v", same.FullRebuild, err)
	}
	if err = SavePartitionedState(ctx, root, first.State, legacy.State); err != nil {
		t.Fatal(err)
	}
	if err = SealPrivateState(ctx, root, binding); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyPrivateStateSeal(ctx, root, binding); err != nil {
		t.Fatal(err)
	}
	policy.RightsReviewed = false
	withdrawn, err := ReconcilePartitioned(ctx, root, first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(time.Hour), binding)
	if err != nil || len(withdrawn.State.Sources) != 0 {
		t.Fatalf("withdrawal %v", err)
	}
	if err = SavePartitionedState(ctx, root, withdrawn.State, first.State); err != nil {
		t.Fatal(err)
	}
	if err = PruneRecordStore(ctx, root, withdrawn.State, first.State, clock().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".atlas-private", "records-v2"))
	if err != nil || len(entries) != 0 {
		t.Fatal("withdrawn records retained for TTL", err)
	}
}

func TestRetainedSealUsesExactHistoricalStateAndWithdrawnChunksFail(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	policy, snapshot, binding := stateFixture()
	first, err := ReconcilePartitioned(ctx, root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = SavePartitionedState(ctx, root, first.State, BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err = SealPrivateState(ctx, root, binding); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(first.State)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := sha256.Sum256(data)
	snapshot.PayloadHash = sha256.Sum256([]byte("new observed fixture"))
	snapshot.ProofPayloadHash = snapshot.PayloadHash
	snapshot.Records[0].Evidence.Signal = "proxy"
	next, err := ReconcilePartitioned(ctx, root, first.State, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock().Add(time.Hour), binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = SavePartitionedState(ctx, root, next.State, first.State); err != nil {
		t.Fatal(err)
	}
	if err = SealPrivateState(ctx, root, binding); err != nil {
		t.Fatal(err)
	}
	old, err := VerifyRetainedPrivateStateSeal(ctx, root, binding, firstHash)
	if err != nil || old.EvaluatedAt != first.State.EvaluatedAt {
		t.Fatalf("retained exact state unavailable: %v", err)
	}
	if err = PruneRecordStore(ctx, root, BuildState{Version: 2, PolicyHash: binding}, next.State, clock().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyRetainedPrivateStateSeal(ctx, root, binding, firstHash); err == nil {
		t.Fatal("withdrawn historical record restored through retained seal")
	}
}

func TestPrivateStateSealRejectsStateBindingAndChunkEdits(t *testing.T) {
	for _, kind := range []string{"state", "binding", "chunk", "missing-key"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			ctx := context.Background()
			policy, snapshot, binding := stateFixture()
			plan, err := ReconcilePartitioned(ctx, root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
			if err != nil {
				t.Fatal(err)
			}
			if err = SavePartitionedState(ctx, root, plan.State, BuildState{}); err != nil {
				t.Fatal(err)
			}
			if err = SealPrivateState(ctx, root, binding); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "state":
				plan.State.Sources[0].ExpiresAt = clock().Add(999 * time.Hour)
				if err = SavePrivateState(root, plan.State); err != nil {
					t.Fatal(err)
				}
			case "binding":
				binding[0] ^= 1
			case "chunk":
				p := filepath.Join(root, ".atlas-private", "records-v2", partitionName(plan.State.Sources[0].RecordPartitions[0]))
				if err = os.WriteFile(p, []byte("edited"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err = os.Remove(filepath.Join(root, ".atlas-private", "state-seal.key")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = VerifyPrivateStateSeal(ctx, root, binding); err == nil {
				t.Fatal("edited or unsealed state admitted")
			}
		})
	}
}

func TestRecordRetentionDropsExpiredAndKeepsOnlyOneEligibleGeneration(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	policy, snapshot, binding := stateFixture()
	first, err := ReconcilePartitioned(ctx, root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = SavePartitionedState(ctx, root, first.State, BuildState{}); err != nil {
		t.Fatal(err)
	}
	expired := first.State
	expired.Sources = append([]StoredSource(nil), first.State.Sources...)
	expired.Sources[0].ExpiresAt = clock()
	if err = PruneRecordStore(ctx, root, expired, first.State, clock()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".atlas-private", "records-v2"))
	if err != nil || len(entries) != 0 {
		t.Fatal("expired current object retained", err)
	}
}
