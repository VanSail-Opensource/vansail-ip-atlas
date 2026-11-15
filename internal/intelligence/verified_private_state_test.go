package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestVerifiedPrivateStateReturnsIndependentSnapshots(t *testing.T) {
	f := newReceiptSealFixture(t)
	before := privateReceiptTree(t, f.root)
	verified, initial, err := VerifyPrivateState(context.Background(), f.root, f.binding)
	if err != nil || !reflect.DeepEqual(initial, f.state) {
		t.Fatal("full verification did not return the sealed state", err)
	}
	initial.Sources[0].ID = "caller edit"
	initial.Sources[0].Receipt.NormalizationPolicyHash[0] ^= 1
	initial.Sources[0].RecordPartitions[0].SHA256[0] ^= 1
	next, err := verified.Revalidate(context.Background())
	if err != nil || !reflect.DeepEqual(next, f.state) {
		t.Fatal("caller state mutated the verified identity", err)
	}
	next.Sources[0].Receipt.NormalizationPolicyHash[1] ^= 1
	next.Sources = nil
	again, err := verified.Revalidate(context.Background())
	if err != nil || !reflect.DeepEqual(again, f.state) {
		t.Fatal("revalidation returned shared mutable state", err)
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("process-local verification changed private files")
	}
}

func TestVerifiedPrivateStateRejectsChangedAuthenticatedInputs(t *testing.T) {
	for _, kind := range []string{"chunk", "state", "resealed-state", "seal", "key", "rotated-key", "receipt", "chunk-symlink", "state-symlink", "seal-symlink", "key-symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newReceiptSealFixture(t)
			verified, _, err := VerifyPrivateState(context.Background(), f.root, f.binding)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.root, ".atlas-private", "state-v1.json")
			switch kind {
			case "chunk", "chunk-symlink":
				path = filepath.Join(f.root, ".atlas-private", "records-v2", partitionName(f.state.Sources[0].RecordPartitions[0]))
			case "seal", "seal-symlink":
				path = filepath.Join(f.root, ".atlas-private", "state-seal-v2.json")
			case "key", "rotated-key", "key-symlink":
				path = filepath.Join(f.root, ".atlas-private", "state-seal.key")
			}
			if kind == "resealed-state" || kind == "receipt" {
				f.state.EvaluatedAt = f.state.EvaluatedAt.Add(time.Second)
				if kind == "receipt" {
					f.state.Sources[0].Receipt.NormalizationPolicyHash[0] ^= 1
					if err := SavePrivateState(f.root, f.state); err != nil {
						t.Fatal(err)
					}
				} else {
					f.saveState(t)
				}
			} else {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(kind, "-symlink") {
					target := filepath.Join(t.TempDir(), "copied-input")
					if err := os.WriteFile(target, data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				} else {
					data[0] ^= 1
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					if kind == "rotated-key" {
						if err := SealPrivateState(context.Background(), f.root, f.binding); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if _, err := verified.Revalidate(context.Background()); err == nil {
				t.Fatal("changed authenticated input reused semantic validation")
			}
		})
	}
}

func TestVerifiedPrivateStateRejectsUnmintedHandlesAndRootReplacement(t *testing.T) {
	for _, verified := range []*VerifiedPrivateState{nil, {}} {
		if _, err := verified.Revalidate(context.Background()); err == nil {
			t.Fatal("unminted handle accepted")
		}
	}
	f := newReceiptSealFixture(t)
	verified, _, err := VerifyPrivateState(context.Background(), f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	copied := *verified
	if _, err := copied.Revalidate(context.Background()); err == nil {
		t.Fatal("copied opaque handle accepted")
	}
	old := f.root + "-original"
	if err := os.Rename(f.root, old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(old) })
	if err := os.CopyFS(f.root, os.DirFS(old)); err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Revalidate(context.Background()); err == nil {
		t.Fatal("identical files in a replaced root borrowed verification")
	}
	if _, err := VerifyPrivateStateSeal(context.Background(), f.root, f.binding); err != nil {
		t.Fatal("replacement fixture did not contain independently valid sealed state", err)
	}
}

func TestVerifiedPrivateStateRequiresFullInitialSemanticsAndHonorsCancellation(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := VerifyPrivateState(ctx, f.root, f.binding); !errors.Is(err, context.Canceled) {
		t.Fatal("initial verification ignored cancellation", err)
	}
	verified, _, err := VerifyPrivateState(context.Background(), f.root, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.Revalidate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("revalidation ignored cancellation", err)
	}
	// A valid local MAC cannot substitute for decoding the normalized union on
	// the first call. This manually forged fixture deliberately bypasses intake.
	record, err := json.Marshal(NormalizedRecord{Version: 3, Kind: RecordEvidence})
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(recordHeader), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(raw[len(recordHeader):], uint32(len(record)))
	raw = append(raw, record...)
	part := RecordPartition{SHA256: sha256.Sum256(raw), Bytes: int64(len(raw)), Records: 1}
	f.state.Sources[0].RecordPartitions = []RecordPartition{part}
	if err := os.WriteFile(filepath.Join(f.root, ".atlas-private", "records-v2", partitionName(part)), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStoredSourceObjects(context.Background(), f.root, f.state.Sources[0]); err != nil {
		t.Fatal("hostile fixture must have intact object identity", err)
	}
	data, err := json.Marshal(f.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivateBytes(f.root, "state-v1.json", data); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(f.root, ".atlas-private", "state-seal.key"))
	if err != nil {
		t.Fatal(err)
	}
	seal := stateSeal{Version: 2, PolicyHash: f.binding, StateHash: sha256.Sum256(data)}
	seal.MAC = sealMAC(key, f.binding, seal.StateHash)
	encoded, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivateBytes(f.root, "state-seal-v2.json", encoded); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPrivateState(context.Background(), f.root, f.binding); err == nil {
		t.Fatal("initial handle accepted invalid normalized semantics")
	}
	if _, err := VerifyPrivateStateSeal(context.Background(), f.root, f.binding); err == nil {
		t.Fatal("existing verifier lost full semantic validation")
	}
}
