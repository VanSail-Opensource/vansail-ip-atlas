package intelligence

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type stateSeal struct {
	Version                    uint16
	PolicyHash, StateHash, MAC [32]byte
}

func statePrivatePath(workspace, name string) (string, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, ".atlas-private")
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("private state directory invalid")
	}
	path := filepath.Join(directory, name)
	if filepath.Base(name) != name {
		return "", errors.New("private state basename invalid")
	}
	if info, err = os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("private state entry invalid")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return path, nil
}
func readPrivateBounded(ctx context.Context, workspace, name string, limit int64) ([]byte, error) {
	path, err := statePrivatePath(workspace, name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("private state entry exceeds limit")
	}
	data, err := io.ReadAll(&recordContextReader{ctx, io.LimitReader(file, limit+1)})
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("private state entry exceeds limit")
	}
	return data, nil
}
func sealMAC(key []byte, policy, state [32]byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("atlas-private-state-seal-v2\x00"))
	h.Write(policy[:])
	h.Write(state[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
func atomicPrivateBytes(workspace, name string, data []byte) error {
	destination, err := statePrivatePath(workspace, name)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), "state-auth-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}

// SealPrivateState is called by the admission engine only after a successful
// atomic intake commit while its exclusive workspace writer lock is held.
// It authenticates the exact private index (including all chunk roots) and the
// config/certification/implementation binding; it never certifies source rights.
func SealPrivateState(ctx context.Context, workspace string, policyHash [32]byte) error {
	if policyHash == ([32]byte{}) {
		return errors.New("explicit state seal binding required")
	}
	state, err := LoadPrivateState(workspace)
	if err != nil {
		return err
	}
	if state.Version != 2 || state.PolicyHash != policyHash {
		return errors.New("state must be re-intaken before sealing")
	}
	for _, source := range state.Sources {
		if source.Receipt == nil || source.Receipt.NormalizationPolicyHash != policyHash {
			return errors.New("source admission receipt required")
		}
		if err = WalkStoredSource(ctx, workspace, source, func(NormalizedRecord) error { return nil }); err != nil {
			return err
		}
	}
	data, err := readPrivateBounded(ctx, workspace, "state-v1.json", 64<<20)
	if err != nil {
		return err
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		path, err := statePrivatePath(workspace, "state-seal.key")
		if err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = file.Write(key)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	} else if err != nil {
		return err
	}
	if len(key) != 32 {
		return errors.New("private state seal key invalid")
	}
	seal := stateSeal{Version: 2, PolicyHash: policyHash, StateHash: sha256.Sum256(data)}
	seal.MAC = sealMAC(key, seal.PolicyHash, seal.StateHash)
	encoded, err := json.Marshal(seal)
	if err != nil {
		return err
	}
	return atomicPrivateBytes(workspace, "state-seal-v2.json", encoded)
}

// VerifyPrivateStateSeal is read-only. Legacy or manually edited state remains
// available to engineering readers but cannot pass this production precondition.
func VerifyPrivateStateSeal(ctx context.Context, workspace string, policyHash [32]byte) (BuildState, error) {
	state, _, err := verifyPrivateState(ctx, workspace, policyHash, nil)
	return state, err
}

type privateStateIdentity struct {
	seal     stateSeal
	keyHash  [32]byte
	sealHash [32]byte
}

// VerifiedPrivateState carries process-local semantic validation of one exact
// authenticated state. Its zero value and copied values are invalid. It grants
// no source rights, freshness, production qualification or publication approval.
type VerifiedPrivateState struct {
	self       *VerifiedPrivateState
	root       string
	rootInfo   os.FileInfo
	policyHash [32]byte
	identity   privateStateIdentity
}

// VerifyPrivateState performs the same complete semantic verification as
// VerifyPrivateStateSeal, then returns a handle scoped to that root and exact
// authenticated identity. The returned state is independently owned by callers.
func VerifyPrivateState(ctx context.Context, workspace string, policyHash [32]byte) (*VerifiedPrivateState, BuildState, error) {
	if err := ctx.Err(); err != nil {
		return nil, BuildState{}, err
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, BuildState{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, BuildState{}, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, BuildState{}, errors.New("verified private state root invalid")
	}
	state, identity, err := verifyPrivateState(ctx, root, policyHash, nil)
	if err != nil {
		return nil, BuildState{}, err
	}
	verified := &VerifiedPrivateState{root: root, rootInfo: info, policyHash: policyHash, identity: identity}
	if !verified.sameRoot() {
		return nil, BuildState{}, errors.New("verified private state root changed")
	}
	verified.self = verified
	return verified, state, nil
}

func (v *VerifiedPrivateState) sameRoot() bool {
	root, err := filepath.EvalSymlinks(v.root)
	if err != nil || root != v.root {
		return false
	}
	info, err := os.Lstat(root)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && os.SameFile(v.rootInfo, info)
}

// Revalidate reauthenticates the current seal, key and state, verifies every
// exact chunk, then reauthenticates again. Only the initial normalized-record
// semantic decoding is reused; changed bytes require full verification anew.
// Every successful result is freshly decoded and shares no mutable state with
// the handle or earlier results. Eligibility still belongs to the caller.
func (v *VerifiedPrivateState) Revalidate(ctx context.Context) (BuildState, error) {
	if err := ctx.Err(); err != nil {
		return BuildState{}, err
	}
	if v == nil || v.self != v || v.rootInfo == nil || v.policyHash == ([32]byte{}) || !v.sameRoot() {
		return BuildState{}, errors.New("verified private state handle invalid")
	}
	state, _, err := verifyPrivateState(ctx, v.root, v.policyHash, &v.identity)
	if err != nil {
		return BuildState{}, err
	}
	if !v.sameRoot() {
		return BuildState{}, errors.New("verified private state root changed")
	}
	return state, nil
}

// RevalidateFor additionally binds reuse to the caller's exact canonical
// workspace and policy, so an otherwise valid handle cannot authorize another
// tree containing copied state files.
func (v *VerifiedPrivateState) RevalidateFor(ctx context.Context, workspace string, binding [32]byte) (BuildState, error) {
	if ctx == nil {
		return BuildState{}, errors.New("verified private state context required")
	}
	if err := ctx.Err(); err != nil {
		return BuildState{}, err
	}
	if v == nil || v.self != v || binding != v.policyHash {
		return BuildState{}, errors.New("verified private state binding differs")
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return BuildState{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil || root != v.root {
		return BuildState{}, errors.New("verified private state workspace differs")
	}
	return v.Revalidate(ctx)
}

// recheckAuthentication is a final metadata boundary used only after this
// operation has already revalidated every object through RevalidateFor.
func (v *VerifiedPrivateState) recheckAuthentication(ctx context.Context) error {
	if v == nil || v.self != v || !v.sameRoot() {
		return errors.New("verified private state handle invalid")
	}
	_, identity, err := readAuthenticatedPrivateState(ctx, v.root, v.policyHash)
	if err != nil || identity != v.identity || !v.sameRoot() {
		return errors.New("verified private state authentication changed")
	}
	return ctx.Err()
}

func readAuthenticatedPrivateState(ctx context.Context, workspace string, policyHash [32]byte) ([]byte, privateStateIdentity, error) {
	fail := func() ([]byte, privateStateIdentity, error) {
		return nil, privateStateIdentity{}, errors.New("private state seal invalid; reviewed intake required")
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if err != nil {
		return fail()
	}
	if len(key) != 32 {
		return fail()
	}
	encoded, err := readPrivateBounded(ctx, workspace, "state-seal-v2.json", 4096)
	if err != nil {
		return fail()
	}
	var seal stateSeal
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&seal); err != nil {
		return fail()
	}
	if err = decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return fail()
	}
	if seal.Version != 2 || policyHash == ([32]byte{}) || seal.PolicyHash != policyHash {
		return fail()
	}
	expected := sealMAC(key, policyHash, seal.StateHash)
	if !hmac.Equal(expected[:], seal.MAC[:]) {
		return fail()
	}
	data, err := readPrivateBounded(ctx, workspace, "state-v1.json", 64<<20)
	if err != nil {
		return fail()
	}
	if sha256.Sum256(data) != seal.StateHash {
		return fail()
	}
	return data, privateStateIdentity{seal: seal, keyHash: sha256.Sum256(key), sealHash: sha256.Sum256(encoded)}, nil
}

func verifyPrivateState(ctx context.Context, workspace string, policyHash [32]byte, expected *privateStateIdentity) (BuildState, privateStateIdentity, error) {
	fail := func() (BuildState, privateStateIdentity, error) {
		return BuildState{}, privateStateIdentity{}, errors.New("private state seal invalid; reviewed intake required")
	}
	data, identity, err := readAuthenticatedPrivateState(ctx, workspace, policyHash)
	if err != nil {
		return BuildState{}, privateStateIdentity{}, err
	}
	if expected != nil && *expected != identity {
		return fail()
	}
	// Decode the bytes that were actually authenticated, not a second path read
	// that could return a concurrently replaced state between the hash checks.
	var state BuildState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil {
		return fail()
	}
	if err = decoder.Decode(new(json.RawMessage)); err != io.EOF || state.Version != 2 || state.PolicyHash != policyHash {
		return fail()
	}
	for _, source := range state.Sources {
		// Preserve LoadPrivateState's descriptor, attribution and inline-union
		// checks as well as the source receipt binding on every verification.
		if len(source.RecordPartitions) > maxRecordPartitions || len(source.Records) > 0 && len(source.RecordPartitions) > 0 || source.Receipt == nil || source.Receipt.NormalizationPolicyHash != policyHash {
			return fail()
		}
		for _, part := range source.RecordPartitions {
			if !validPartition(part) {
				return fail()
			}
		}
		if source.Attribution != nil && source.Attribution.Validate() != nil {
			return fail()
		}
		for _, record := range source.Records {
			if record.Validate() != nil {
				return fail()
			}
		}
		if expected == nil {
			err = WalkStoredSource(ctx, workspace, source, func(NormalizedRecord) error { return nil })
		} else {
			err = VerifyStoredSourceObjects(ctx, workspace, source)
		}
		if err != nil {
			return BuildState{}, privateStateIdentity{}, err
		}
	}
	_, after, err := readAuthenticatedPrivateState(ctx, workspace, policyHash)
	if err != nil || after != identity {
		return fail()
	}
	if err := ctx.Err(); err != nil {
		return BuildState{}, privateStateIdentity{}, err
	}
	return state, identity, nil
}
