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
	fail := func() (BuildState, error) {
		return BuildState{}, errors.New("private state seal invalid; reviewed intake required")
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
	state, err := LoadPrivateState(workspace)
	if err != nil {
		return fail()
	}
	if state.Version != 2 || state.PolicyHash != policyHash {
		return fail()
	}
	for _, source := range state.Sources {
		if source.Receipt == nil || source.Receipt.NormalizationPolicyHash != policyHash {
			return fail()
		}
		if err = WalkStoredSource(ctx, workspace, source, func(NormalizedRecord) error { return nil }); err != nil {
			return BuildState{}, err
		}
	}
	after, err := readPrivateBounded(ctx, workspace, "state-v1.json", 64<<20)
	if err != nil || sha256.Sum256(after) != seal.StateHash {
		return fail()
	}
	return state, nil
}
