package intelligence

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestVerifiedPrivateStateOperationsPreserveAuthenticatedArtifacts(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	v, state, err := VerifyPrivateState(ctx, f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.RevalidateFor(ctx, t.TempDir(), f.binding); err == nil {
		t.Fatal("handle accepted another root")
	}
	wrong := f.binding
	wrong[0] ^= 1
	if _, err := v.RevalidateFor(ctx, f.root, wrong); err == nil {
		t.Fatal("handle accepted another policy")
	}
	q, err := v.ObserveTier1State(ctx, f.root, f.binding, state.EvaluatedAt)
	if err != nil || q.ValidateObservation(state, state.EvaluatedAt) != nil || q.Validate(state, state.EvaluatedAt) == nil {
		t.Fatal("unavailable routing observation changed semantics", err)
	}
	if err := v.VerifyTier1ObservationHistory(ctx, f.root, q); err != nil {
		t.Fatal(err)
	}
	if err := v.RetainPrivateStateSeal(ctx, f.root, f.binding); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ current, retained string }{{"state-v1.json", ".json"}, {"state-seal-v2.json", ".seal"}} {
		current, err := os.ReadFile(filepath.Join(f.root, ".atlas-private", entry.current))
		if err != nil {
			t.Fatal(err)
		}
		retained, err := os.ReadFile(filepath.Join(f.root, ".atlas-private", "state-history-v2", hex.EncodeToString(f.stateHash[:])+entry.retained))
		if err != nil || string(current) != string(retained) {
			t.Fatal("retention did not archive the exact authenticated bytes", err)
		}
	}
	if err := v.SealProductionReceipt(ctx, f.root, f.binding, f.receipt, f.stateHash, f.manifestHash, f.validUntil); err != nil {
		t.Fatal(err)
	}
	before := privateReceiptTree(t, f.root)
	if err := f.verify(ctx); err != nil {
		t.Fatal("independent full verifier rejected optimized issuance", err)
	}
	if err := f.seal(ctx); err != nil {
		t.Fatal("full issuer disagreed with optimized attestation", err)
	}
	if err := v.SealProductionReceipt(ctx, f.root, f.binding, f.receipt, f.stateHash, f.manifestHash, f.validUntil); err != nil {
		t.Fatal("optimized identical attestation was not idempotent", err)
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("read-only/idempotent checks edited authenticated artifacts")
	}
	history, err := loadTier1History(ctx, f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	history.Pending = f.stateHash
	if err := writeTier1History(ctx, f.root, history); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyTier1ObservationHistory(ctx, f.root, q); err == nil {
		t.Fatal("optimized history check erased an intervening failure")
	}
}

func TestVerifiedPrivateStateOperationBoundariesRejectMutations(t *testing.T) {
	for _, operation := range []string{"observe", "history", "retain", "receipt"} {
		for _, mutation := range []string{"chunk", "state", "seal", "key", "workspace", "nil"} {
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				f := newReceiptSealFixture(t)
				ctx := context.Background()
				v, _, err := VerifyPrivateState(ctx, f.root, f.binding)
				if err != nil {
					t.Fatal(err)
				}
				q, err := v.ObserveTier1State(ctx, f.root, f.binding, f.state.EvaluatedAt)
				if err != nil {
					t.Fatal(err)
				}
				root := f.root
				var path string
				switch mutation {
				case "chunk":
					path = filepath.Join(root, ".atlas-private", "records-v2", partitionName(f.state.Sources[0].RecordPartitions[0]))
				case "state":
					path = filepath.Join(root, ".atlas-private", "state-v1.json")
				case "seal":
					path = filepath.Join(root, ".atlas-private", "state-seal-v2.json")
				case "key":
					path = filepath.Join(root, ".atlas-private", "state-seal.key")
				case "workspace":
					root = t.TempDir()
				case "nil":
					v = nil
				}
				if path != "" {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					data[0] ^= 1
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				switch operation {
				case "observe":
					_, err = v.ObserveTier1State(ctx, root, f.binding, f.state.EvaluatedAt)
				case "history":
					err = v.VerifyTier1ObservationHistory(ctx, root, q)
				case "retain":
					err = v.RetainPrivateStateSeal(ctx, root, f.binding)
				case "receipt":
					err = v.SealProductionReceipt(ctx, root, f.binding, f.receipt, f.stateHash, f.manifestHash, f.validUntil)
				}
				if err == nil {
					t.Fatal("operation reused changed or absent authentication")
				}
			})
		}
	}
}

func TestVerifiedPrivateStateTier1FinalFailureRetainsPendingEpoch(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	v, state, err := VerifyPrivateState(ctx, f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	_, err = observeTier1StateChecked(ctx, f.root, state, f.binding, state.EvaluatedAt, 100_000_000, func() error {
		if err := os.WriteFile(filepath.Join(f.root, ".atlas-private", "state-seal-v2.json"), []byte("changed"), 0600); err != nil {
			return err
		}
		return v.recheckAuthentication(ctx)
	})
	if err == nil {
		t.Fatal("changed final authentication completed an observed epoch")
	}
	history, err := loadTier1History(ctx, f.root, f.binding)
	if err != nil || history.Pending != f.stateHash {
		t.Fatal("failed final guard cleared pending source history", err)
	}
}

func TestVerifiedPrivateStateRetentionCannotArchiveAReplacementGeneration(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	v, state, err := VerifyPrivateState(ctx, f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the generation after the outer boundary check with a separately
	// valid sealed index. The shared retention body must bind its actual reads.
	f.state.EvaluatedAt = f.state.EvaluatedAt.Add(time.Second)
	f.saveState(t)
	if err := retainPrivateStateSeal(ctx, f.root, f.binding, state, v.identity); err == nil {
		t.Fatal("retention archived a different authenticated generation")
	}
	if _, err := os.Stat(filepath.Join(f.root, ".atlas-private", "state-history-v2")); !os.IsNotExist(err) {
		t.Fatal("rejected retention created an archived generation", err)
	}
}

// The context injects a mutation at an observable filesystem boundary, without
// sleep races or depending on the number of verification reads.
type mutateAttestationContext struct {
	context.Context
	trigger func() bool
	mutate  func() error
	fired   bool
	err     error
}

func (c *mutateAttestationContext) Err() error {
	if !c.fired && c.trigger() {
		c.fired = true
		c.err = c.mutate()
	}
	return c.Context.Err()
}

func TestVerifiedPrivateStateReceiptFinalGuardRejectsMidOperationKeyChange(t *testing.T) {
	for _, optimized := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "verified"}[optimized], func(t *testing.T) {
			f := newReceiptSealFixture(t)
			v, _, err := VerifyPrivateState(context.Background(), f.root, f.binding)
			if err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(f.root, ".atlas-private", "state-seal.key")
			key, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			key[0] ^= 1
			ctx := &mutateAttestationContext{Context: context.Background(), mutate: func() error { return os.WriteFile(keyPath, key, 0600) }}
			ctx.trigger = func() bool {
				entries, _ := os.ReadDir(filepath.Dir(f.path()))
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "receipt-attestation-") && strings.HasSuffix(entry.Name(), ".partial") {
						return true
					}
				}
				return false
			}
			if optimized {
				err = v.SealProductionReceipt(ctx, f.root, f.binding, f.receipt, f.stateHash, f.manifestHash, f.validUntil)
			} else {
				err = f.seal(ctx)
			}
			if err == nil || !ctx.fired || ctx.err != nil {
				t.Fatal("final authentication guard was bypassed", err, ctx.fired, ctx.err)
			}
			if _, err := os.Stat(f.path()); !os.IsNotExist(err) {
				t.Fatal("changed authentication published a receipt attestation", err)
			}
		})
	}
}
