package intelligence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type receiptSealFixture struct {
	root                             string
	binding, stateHash, manifestHash [32]byte
	state                            BuildState
	receipt                          []byte
	validUntil                       time.Time
}

// These are private protocol fixtures, not production source qualification or a
// declaration that the artificial manifest contains a valid database.
func newReceiptSealFixture(t *testing.T) receiptSealFixture {
	t.Helper()
	f := receiptSealFixture{root: t.TempDir(), manifestHash: sha256.Sum256([]byte("synthetic immutable manifest")), validUntil: clock().Add(time.Hour)}
	policy, snapshot, binding := stateFixture()
	f.binding = binding
	plan, err := ReconcilePartitioned(context.Background(), f.root, BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil {
		t.Fatal(err)
	}
	f.state = plan.State
	f.saveState(t)
	f.receipt = []byte(`{"normalized_state_sha256":"` + hex.EncodeToString(f.stateHash[:]) + `","release_manifest_sha256":"` + hex.EncodeToString(f.manifestHash[:]) + `"}`)
	return f
}

func (f *receiptSealFixture) saveState(t *testing.T) {
	t.Helper()
	if err := SavePrivateState(f.root, f.state); err != nil {
		t.Fatal(err)
	}
	if err := SealPrivateState(context.Background(), f.root, f.binding); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(f.state)
	if err != nil {
		t.Fatal(err)
	}
	f.stateHash = sha256.Sum256(data)
}
func (f receiptSealFixture) seal(ctx context.Context) error {
	return SealProductionReceipt(ctx, f.root, f.binding, f.receipt, f.stateHash, f.manifestHash, f.validUntil)
}
func (f receiptSealFixture) verify(ctx context.Context) error {
	return VerifyProductionReceiptSeal(ctx, f.root, f.binding, f.receipt, f.stateHash, f.manifestHash, f.validUntil)
}
func (f receiptSealFixture) path() string {
	return filepath.Join(f.root, ".atlas-private", productionReceiptDirectoryName, receiptSealName(sha256.Sum256(f.receipt)))
}

func privateReceiptTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(filepath.Join(root, ".atlas-private"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		tree[name] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestProductionReceiptSealBindsCompilerArtifactAndVerificationIsReadOnly(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	if err := f.verify(ctx); err == nil {
		t.Fatal("an unissued receipt borrowed sealed source qualification")
	}
	if _, err := os.Stat(filepath.Join(f.root, ".atlas-private", productionReceiptDirectoryName)); !os.IsNotExist(err) {
		t.Fatal("verification created private attestation state", err)
	}
	if err := f.seal(ctx); err != nil {
		t.Fatal(err)
	}
	before := privateReceiptTree(t, f.root)
	if err := f.verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.seal(ctx); err != nil {
		t.Fatal("identical attestation is not idempotent", err)
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("verification/idempotent issuance edited private bytes")
	}
	for _, kind := range []string{"receipt", "manifest", "state", "policy", "deadline", "workspace"} {
		t.Run(kind, func(t *testing.T) {
			x := f
			switch kind {
			case "receipt":
				x.receipt = bytes.ReplaceAll(f.receipt, []byte("release_manifest_sha256"), []byte("edited_manifest_sha256"))
			case "manifest":
				x.manifestHash[0] ^= 1
			case "state":
				x.stateHash[0] ^= 1
			case "policy":
				x.binding[0] ^= 1
			case "deadline":
				x.validUntil = x.validUntil.Add(time.Second)
			case "workspace":
				x.root = newReceiptSealFixture(t).root
				if err := os.Mkdir(filepath.Dir(x.path()), 0700); err != nil {
					t.Fatal(err)
				}
				issued, err := os.ReadFile(f.path())
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(x.path(), issued, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := x.verify(ctx); err == nil {
				t.Fatal("edited artifact borrowed an issued receipt", kind)
			}
		})
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("failed verification edited private bytes")
	}
}

func TestProductionReceiptSealRejectsForgedOrNoncanonicalSidecar(t *testing.T) {
	for _, kind := range []string{"mac", "manifest", "state", "clock", "version", "unknown_field", "duplicate_field", "whitespace", "trailing", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f := newReceiptSealFixture(t)
			ctx := context.Background()
			if err := f.seal(ctx); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.path())
			if err != nil {
				t.Fatal(err)
			}
			var seal productionReceiptSeal
			if err := json.Unmarshal(data, &seal); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "mac":
				seal.MAC[0] ^= 1
			case "manifest":
				seal.ManifestSHA256[0] ^= 1
			case "state":
				seal.StateSHA256[0] ^= 1
			case "clock":
				seal.EvaluatedAt--
			case "version":
				seal.SchemaVersion++
			}
			if kind == "mac" || kind == "manifest" || kind == "state" || kind == "clock" || kind == "version" {
				data, _ = json.Marshal(seal)
			}
			switch kind {
			case "unknown_field":
				data = append([]byte(`{"extra":false,`), data[1:]...)
			case "duplicate_field":
				data = append([]byte(`{"schema_version":1,`), data[1:]...)
			case "whitespace":
				data = append([]byte(" "), data...)
			case "trailing":
				data = append(data, []byte("{}")...)
			case "oversized":
				data = bytes.Repeat([]byte(" "), maxProductionReceiptSealBytes+1)
			}
			if err := os.WriteFile(f.path(), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.verify(ctx); err == nil {
				t.Fatal("forged or noncanonical attestation accepted")
			}
			if err := f.seal(ctx); err == nil {
				t.Fatal("issuance replaced an edited immutable attestation")
			}
			after, err := os.ReadFile(f.path())
			if err != nil || !bytes.Equal(data, after) {
				t.Fatal("failed issuance overwrote edited attestation", err)
			}
		})
	}
}

func TestProductionReceiptSealRequiresExactAuthenticatedCurrentState(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	data, err := os.ReadFile(filepath.Join(f.root, ".atlas-private", "state-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Editable state and matching caller hashes cannot manufacture its MAC.
	data = bytes.ReplaceAll(data, []byte("synthetic-private-fixture"), []byte("edited-private-fixture"))
	if err := os.WriteFile(filepath.Join(f.root, ".atlas-private", "state-v1.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f.stateHash = sha256.Sum256(data)
	if err := f.seal(ctx); err == nil {
		t.Fatal("unauthenticated replacement state received an artifact attestation")
	}
	if _, err := os.Stat(filepath.Join(f.root, ".atlas-private", productionReceiptDirectoryName)); !os.IsNotExist(err) {
		t.Fatal("failed authentication created artifact inventory", err)
	}
}

func TestProductionReceiptSealRetainedStateAndRetentionBoundary(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	if err := f.seal(ctx); err != nil {
		t.Fatal(err)
	}
	if err := RetainPrivateStateSeal(ctx, f.root, f.binding); err != nil {
		t.Fatal(err)
	}
	old := f
	f.state.EvaluatedAt = f.state.EvaluatedAt.Add(time.Hour)
	f.saveState(t)
	before := privateReceiptTree(t, f.root)
	if err := old.verify(ctx); err != nil {
		t.Fatal("exact authenticated retained generation was not verified", err)
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("retained verification changed state")
	}
	if err := old.seal(ctx); err == nil {
		t.Fatal("old retained state minted a fresh compiler attestation")
	}
	f.state.EvaluatedAt = clock().Add(48 * time.Hour)
	f.saveState(t)
	if err := old.verify(ctx); err == nil {
		t.Fatal("retained artifact crossed the exclusive 48-hour rollback bound")
	}
}

func TestProductionReceiptSealBoundsLifetimeAndInputs(t *testing.T) {
	for _, kind := range []string{"same_clock", "before_clock", "source_expiry", "fractional_deadline", "empty_receipt", "oversized_receipt", "invalid_json", "invalid_utf8", "zero_manifest", "zero_state", "zero_policy"} {
		t.Run(kind, func(t *testing.T) {
			f := newReceiptSealFixture(t)
			switch kind {
			case "same_clock":
				f.validUntil = f.state.EvaluatedAt
			case "before_clock":
				f.validUntil = f.state.EvaluatedAt.Add(-time.Second)
			case "source_expiry":
				f.validUntil = f.state.Sources[0].ExpiresAt.Add(time.Second)
			case "fractional_deadline":
				f.validUntil = f.validUntil.Add(time.Nanosecond)
			case "empty_receipt":
				f.receipt = nil
			case "oversized_receipt":
				f.receipt = []byte(`{"text":"` + strings.Repeat("a", maxProductionReceiptBytes) + `"}`)
			case "invalid_json":
				f.receipt = []byte(`{"broken":`)
			case "invalid_utf8":
				f.receipt = []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
			case "zero_manifest":
				f.manifestHash = [32]byte{}
			case "zero_state":
				f.stateHash = [32]byte{}
			case "zero_policy":
				f.binding = [32]byte{}
			}
			if err := f.seal(context.Background()); err == nil {
				t.Fatal("invalid artifact/lifetime accepted", kind)
			}
		})
	}
}

func TestProductionReceiptSealInventoryIsBoundedAndOnlyAuthenticatedOldEntriesPruned(t *testing.T) {
	f := newReceiptSealFixture(t)
	ctx := context.Background()
	for i := byte('1'); i <= '3'; i++ {
		f.receipt = []byte{'{', '"', 'i', '"', ':', i, '}'}
		if err := f.seal(ctx); err != nil {
			t.Fatal(err)
		}
	}
	before := privateReceiptTree(t, f.root)
	f.receipt = []byte(`{"i":4}`)
	if err := f.seal(ctx); err == nil {
		t.Fatal("fourth live attestation exceeded inventory")
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("inventory failure pruned live attestations")
	}
	oldHash := f.stateHash
	f.state.EvaluatedAt = f.state.EvaluatedAt.Add(48 * time.Hour)
	f.saveState(t)
	f.validUntil = f.state.EvaluatedAt.Add(time.Hour)
	if oldHash == f.stateHash {
		t.Fatal("fixture did not advance authenticated state")
	}
	if err := f.seal(ctx); err != nil {
		t.Fatal("authenticated aged sidecars were not pruned", err)
	}
	directory := filepath.Dir(f.path())
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("unexpected retained inventory", len(entries), err)
	}
	unknown := filepath.Join(directory, "unrelated.txt")
	if err := os.WriteFile(unknown, []byte("do not remove"), 0600); err != nil {
		t.Fatal(err)
	}
	f.receipt = []byte(`{"i":5}`)
	if err := f.seal(ctx); err == nil {
		t.Fatal("unknown private entry was ignored")
	}
	if data, err := os.ReadFile(unknown); err != nil || string(data) != "do not remove" {
		t.Fatal("unknown entry was removed", err)
	}
}

func TestProductionReceiptSealMissingKeyAndCancellationCannotCreateState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newReceiptSealFixture(t)
	before := privateReceiptTree(t, f.root)
	if err := f.seal(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("issuance cancellation lost", err)
	}
	if err := f.verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("verification cancellation lost", err)
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("cancelled operation created private state")
	}
	if err := os.Remove(filepath.Join(f.root, ".atlas-private", "state-seal.key")); err != nil {
		t.Fatal(err)
	}
	before = privateReceiptTree(t, f.root)
	if err := f.seal(context.Background()); err == nil {
		t.Fatal("issuance recreated a missing workspace key")
	}
	if err := f.verify(context.Background()); err == nil {
		t.Fatal("verification recreated a missing workspace key")
	}
	if !reflect.DeepEqual(before, privateReceiptTree(t, f.root)) {
		t.Fatal("operation recreated a missing key")
	}
}

func TestProductionReceiptSealRejectsSymlinkedInventoryOrEntry(t *testing.T) {
	for _, kind := range []string{"directory", "entry", "key"} {
		t.Run(kind, func(t *testing.T) {
			f := newReceiptSealFixture(t)
			ctx := context.Background()
			if err := f.seal(ctx); err != nil {
				t.Fatal(err)
			}
			var target, link string
			switch kind {
			case "directory":
				link = filepath.Dir(f.path())
				target = filepath.Join(f.root, "outside-receipts")
				if err := os.Rename(link, target); err != nil {
					t.Fatal(err)
				}
			case "entry":
				link = f.path()
				target = filepath.Join(f.root, "outside-entry")
				if err := os.Rename(link, target); err != nil {
					t.Fatal(err)
				}
			case "key":
				link = filepath.Join(f.root, ".atlas-private", "state-seal.key")
				target = filepath.Join(f.root, "outside-key")
				if err := os.Rename(link, target); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skip("platform cannot create test symlink", err)
			}
			if err := f.verify(ctx); err == nil {
				t.Fatal("verification followed symlinked private artifact", kind)
			}
			if err := f.seal(ctx); err == nil {
				t.Fatal("issuance followed symlinked private artifact", kind)
			}
		})
	}
}
