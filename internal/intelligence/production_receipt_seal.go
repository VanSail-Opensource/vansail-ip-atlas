package intelligence

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const productionReceiptDirectoryName = "production-receipts-v1"
const maxProductionReceiptBytes = 2 << 20
const maxProductionReceiptSealBytes = 4096

type productionReceiptSeal struct {
	BindingSHA256  [32]byte `json:"binding_sha256"`
	EvaluatedAt    int64    `json:"evaluated_at"`
	MAC            [32]byte `json:"mac"`
	ManifestSHA256 [32]byte `json:"manifest_sha256"`
	ReceiptSHA256  [32]byte `json:"receipt_sha256"`
	SchemaVersion  uint16   `json:"schema_version"`
	StateSHA256    [32]byte `json:"state_sha256"`
	ValidUntil     int64    `json:"valid_until"`
}

func productionReceiptMAC(key []byte, seal productionReceiptSeal) [32]byte {
	seal.MAC = [32]byte{}
	data, _ := json.Marshal(seal)
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte("VanSail/production-receipt-attestation/v1\x00"))
	hash.Write(data)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func productionReceiptDirectory(workspace string, create bool) (string, error) {
	base, err := statePrivatePath(workspace, "state-v1.json")
	if err != nil {
		return "", err
	}
	directory := filepath.Join(filepath.Dir(base), productionReceiptDirectoryName)
	if create {
		if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("private production receipt directory invalid")
	}
	return directory, nil
}

func receiptSealInputs(receipt []byte, binding, stateHash, manifestHash [32]byte, validUntil time.Time) (productionReceiptSeal, error) {
	if binding == ([32]byte{}) || stateHash == ([32]byte{}) || manifestHash == ([32]byte{}) || len(receipt) == 0 || len(receipt) > maxProductionReceiptBytes || !utf8.Valid(receipt) || !json.Valid(receipt) || receipt[0] != '{' || receipt[len(receipt)-1] != '}' || validUntil.IsZero() || validUntil.Nanosecond() != 0 || validUntil.Unix() < 0 {
		return productionReceiptSeal{}, errors.New("explicit bounded production artifact binding required")
	}
	return productionReceiptSeal{BindingSHA256: binding, ReceiptSHA256: sha256.Sum256(receipt), StateSHA256: stateHash, ManifestSHA256: manifestHash, SchemaVersion: 1, ValidUntil: validUntil.Unix()}, nil
}

func receiptSealName(digest [32]byte) string { return hex.EncodeToString(digest[:]) + ".json" }

func validateReceiptState(state BuildState, expected [32]byte, validUntil time.Time) error {
	data, err := json.Marshal(state)
	if err != nil || sha256.Sum256(data) != expected || state.Version != 2 || state.EvaluatedAt.IsZero() || state.EvaluatedAt.Unix() < 0 || !validUntil.After(state.EvaluatedAt) || len(state.Sources) == 0 {
		return errors.New("production artifact does not bind the authenticated source state")
	}
	for _, source := range state.Sources {
		if source.Receipt == nil || validUntil.After(source.ExpiresAt) {
			return errors.New("production artifact lifetime exceeds authenticated source expiry")
		}
	}
	return nil
}

func readProductionReceiptSeal(ctx context.Context, directory, name string, key []byte) (productionReceiptSeal, []byte, error) {
	var seal productionReceiptSeal
	data, err := historyBytes(ctx, directory, name, maxProductionReceiptSealBytes)
	if err != nil {
		return seal, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seal); err != nil {
		return seal, nil, errors.New("production artifact attestation invalid")
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return seal, nil, errors.New("production artifact attestation has trailing data")
	}
	canonical, err := json.Marshal(seal)
	if err != nil || !bytes.Equal(canonical, data) || seal.SchemaVersion != 1 || seal.BindingSHA256 == ([32]byte{}) || seal.StateSHA256 == ([32]byte{}) || seal.ManifestSHA256 == ([32]byte{}) || seal.ReceiptSHA256 == ([32]byte{}) || name != receiptSealName(seal.ReceiptSHA256) || seal.EvaluatedAt < 0 || seal.ValidUntil <= seal.EvaluatedAt {
		return seal, nil, errors.New("production artifact attestation framing invalid")
	}
	expected := productionReceiptMAC(key, seal)
	if !hmac.Equal(expected[:], seal.MAC[:]) {
		return seal, nil, errors.New("production artifact attestation authentication failed")
	}
	return seal, data, nil
}

// SealProductionReceipt is called only by the production CLI after successful
// source-qualified materialization, final gates and Tier-1 outcome checks while
// holding the workspace writer lock. It binds the exact canonical receipt bytes
// read back from disk to the exact current sealed state and manifest. It does
// not create a key, source review, capability or public release approval.
func SealProductionReceipt(ctx context.Context, workspace string, binding [32]byte, receiptBytes []byte, stateHash, manifestHash [32]byte, validUntil time.Time) (failure error) {
	return sealProductionReceipt(ctx, workspace, binding, receiptBytes, stateHash, manifestHash, validUntil, nil)
}

// SealProductionReceipt preserves all exact artifact and lifetime checks while
// reusing the handle's initial normalized-record semantics. The caller must
// still hold the workspace writer lock and complete the production gates.
func (v *VerifiedPrivateState) SealProductionReceipt(ctx context.Context, workspace string, binding [32]byte, receiptBytes []byte, stateHash, manifestHash [32]byte, validUntil time.Time) error {
	if v == nil {
		return errors.New("verified private state handle required")
	}
	return sealProductionReceipt(ctx, workspace, binding, receiptBytes, stateHash, manifestHash, validUntil, v)
}

func sealProductionReceipt(ctx context.Context, workspace string, binding [32]byte, receiptBytes []byte, stateHash, manifestHash [32]byte, validUntil time.Time, verified *VerifiedPrivateState) (failure error) {
	if ctx == nil {
		return errors.New("production artifact context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if err := ctx.Err(); err != nil {
			failure = err
		}
	}()
	seal, err := receiptSealInputs(receiptBytes, binding, stateHash, manifestHash, validUntil)
	if err != nil {
		return err
	}
	var state BuildState
	var identity privateStateIdentity
	if verified == nil {
		state, identity, err = verifyPrivateState(ctx, workspace, binding, nil)
	} else {
		state, err = verified.RevalidateFor(ctx, workspace, binding)
		identity = verified.identity
	}
	if err != nil {
		return err
	}
	if err = validateReceiptState(state, stateHash, validUntil); err != nil {
		return err
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if err != nil || len(key) != 32 || sha256.Sum256(key) != identity.keyHash {
		return errors.New("existing production artifact key required")
	}
	checkAuthentication := func() error {
		_, current, err := readAuthenticatedPrivateState(ctx, workspace, binding)
		if err != nil || current != identity || verified != nil && !verified.sameRoot() {
			return errors.New("source authentication changed before artifact attestation")
		}
		return ctx.Err()
	}
	seal.EvaluatedAt = state.EvaluatedAt.Unix()
	seal.MAC = productionReceiptMAC(key, seal)
	data, err := json.Marshal(seal)
	if err != nil || len(data) > maxProductionReceiptSealBytes {
		return errors.New("production artifact attestation exceeds bound")
	}
	directory, err := productionReceiptDirectory(workspace, true)
	if err != nil {
		return err
	}
	name := receiptSealName(seal.ReceiptSHA256)
	if _, existing, err := readProductionReceiptSeal(ctx, directory, name, key); err == nil {
		if bytes.Equal(existing, data) {
			return checkAuthentication()
		}
		return errors.New("immutable production artifact attestation already differs")
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 3 {
		return errors.New("private production artifact inventory exceeded")
	}
	type expiredSeal struct{ name string }
	var expired []expiredSeal
	live := 0
	for _, entry := range entries {
		old, _, err := readProductionReceiptSeal(ctx, directory, entry.Name(), key)
		if err != nil {
			return err
		}
		if state.EvaluatedAt.Unix() < old.EvaluatedAt {
			return errors.New("production artifact attestation clock cannot move backwards")
		}
		if state.EvaluatedAt.Sub(time.Unix(old.EvaluatedAt, 0)) >= 48*time.Hour {
			expired = append(expired, expiredSeal{entry.Name()})
		} else {
			live++
		}
	}
	if live >= 3 {
		return errors.New("three live production artifact attestations already retained")
	}
	for _, entry := range expired {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(directory, entry.name)); err != nil {
			return err
		}
	}
	// Recheck the exact current file after verification and before publishing the
	// attestation. Writer locking prevents concurrent intake from mixing roots.
	current, err := readPrivateBounded(ctx, workspace, "state-v1.json", 64<<20)
	if err != nil || sha256.Sum256(current) != stateHash {
		return errors.New("source state changed before artifact attestation")
	}
	file, err := os.CreateTemp(directory, "receipt-attestation-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Authenticate both state and key immediately before the atomic publication.
	// A key rotation cannot produce a new attestation from old verified inputs.
	if err = checkAuthentication(); err != nil {
		return err
	}
	// Link publishes a complete content-addressed object without overwriting any
	// existing attestation, including on a concurrent conflicting creation.
	if err = os.Link(file.Name(), filepath.Join(directory, name)); err != nil {
		return err
	}
	return nil
}

// VerifyProductionReceiptSeal is read-only. The requested state must be the
// current authenticated index or its exact authenticated retained generation;
// receipt edits and unrelated valid VIA3 trees cannot borrow its qualification.
// Current rights, capabilities, withdrawal and wall-clock expiry are separate
// mandatory checks performed by the production verifier.
func VerifyProductionReceiptSeal(ctx context.Context, workspace string, binding [32]byte, receiptBytes []byte, stateHash, manifestHash [32]byte, validUntil time.Time) (failure error) {
	if ctx == nil {
		return errors.New("production artifact context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if err := ctx.Err(); err != nil {
			failure = err
		}
	}()
	expected, err := receiptSealInputs(receiptBytes, binding, stateHash, manifestHash, validUntil)
	if err != nil {
		return err
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if err != nil || len(key) != 32 {
		return errors.New("existing production artifact key required")
	}
	directory, err := productionReceiptDirectory(workspace, false)
	if err != nil {
		return err
	}
	seal, _, err := readProductionReceiptSeal(ctx, directory, receiptSealName(expected.ReceiptSHA256), key)
	if err != nil {
		return err
	}
	if seal.BindingSHA256 != binding || seal.StateSHA256 != stateHash || seal.ManifestSHA256 != manifestHash || seal.ValidUntil != validUntil.Unix() {
		return errors.New("production artifact attestation binding differs")
	}
	current, err := VerifyPrivateStateSeal(ctx, workspace, binding)
	if err != nil {
		return err
	}
	state := current
	currentBytes, err := json.Marshal(current)
	if err != nil {
		return err
	}
	// Select from the exact authenticated generation, never a second file read
	// that could have moved between verification and state decoding.
	currentRaw, err := readPrivateBounded(ctx, workspace, "state-v1.json", 64<<20)
	currentHash := sha256.Sum256(currentBytes)
	if err != nil || sha256.Sum256(currentRaw) != currentHash {
		return errors.New("current source state changed during artifact verification")
	}
	if currentHash != stateHash {
		state, err = VerifyRetainedPrivateStateSeal(ctx, workspace, binding, stateHash)
		if err != nil {
			return err
		}
		if current.EvaluatedAt.Before(state.EvaluatedAt) || current.EvaluatedAt.Sub(state.EvaluatedAt) >= 48*time.Hour {
			return errors.New("production artifact state exceeds rollback retention")
		}
	}
	if seal.EvaluatedAt != state.EvaluatedAt.Unix() {
		return errors.New("production artifact evaluation clock differs")
	}
	if err := validateReceiptState(state, stateHash, validUntil); err != nil {
		return err
	}
	after, err := readPrivateBounded(ctx, workspace, "state-v1.json", 64<<20)
	if err != nil || sha256.Sum256(after) != currentHash {
		return errors.New("current source state changed during artifact verification")
	}
	return nil
}
