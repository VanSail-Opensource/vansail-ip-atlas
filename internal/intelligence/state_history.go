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
	"sort"
	"time"
)

func stateHistoryDirectory(workspace string, create bool) (string, error) {
	path, err := statePrivatePath(workspace, "state-v1.json")
	if err != nil {
		return "", err
	}
	directory := filepath.Join(filepath.Dir(path), "state-history-v2")
	if create {
		if err = os.MkdirAll(directory, 0700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("private state history directory invalid")
	}
	return directory, nil
}
func historyBytes(ctx context.Context, directory, name string, limit int64) ([]byte, error) {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("private history entry invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(&recordContextReader{ctx, io.LimitReader(file, limit+1)})
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("private history entry exceeds limit")
	}
	return data, nil
}
func writeHistoryBytes(directory, name string, data []byte) error {
	path := filepath.Join(directory, name)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("private state history destination invalid")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(directory, "state-history-*.partial")
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
	return os.Rename(file.Name(), path)
}

// RetainPrivateStateSeal archives the exact currently authenticated index/seal.
// The digest is its only filename component. At most three recent indexes are
// retained; actual source objects still follow immediate withdrawal/expiry GC.
func RetainPrivateStateSeal(ctx context.Context, workspace string, binding [32]byte) error {
	state, identity, err := verifyPrivateState(ctx, workspace, binding, nil)
	if err != nil {
		return err
	}
	return retainPrivateStateSeal(ctx, workspace, binding, state, identity)
}

// RetainPrivateStateSeal retains only the handle's exact authenticated current
// state. Callers must hold the same workspace writer lock as the full entry.
func (v *VerifiedPrivateState) RetainPrivateStateSeal(ctx context.Context, workspace string, binding [32]byte) error {
	state, err := v.RevalidateFor(ctx, workspace, binding)
	if err != nil {
		return err
	}
	if err = retainPrivateStateSeal(ctx, workspace, binding, state, v.identity); err != nil {
		return err
	}
	return v.recheckAuthentication(ctx)
}

func retainPrivateStateSeal(ctx context.Context, workspace string, binding [32]byte, state BuildState, expected privateStateIdentity) error {
	data, identity, err := readAuthenticatedPrivateState(ctx, workspace, binding)
	if err != nil || identity != expected {
		return errors.New("source state changed before retention")
	}
	seal, err := readPrivateBounded(ctx, workspace, "state-seal-v2.json", 4096)
	if err != nil || sha256.Sum256(seal) != expected.sealHash {
		return errors.New("source seal changed before retention")
	}
	digest := sha256.Sum256(data)
	directory, err := stateHistoryDirectory(workspace, true)
	if err != nil {
		return err
	}
	name := hex.EncodeToString(digest[:])
	if err = writeHistoryBytes(directory, name+".json", data); err != nil {
		return err
	}
	if err = writeHistoryBytes(directory, name+".seal", seal); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 8 {
		return errors.New("private state history inventory exceeded")
	}
	type retained struct {
		name  string
		clock time.Time
	}
	var indexes []retained
	for _, entry := range entries {
		filename := entry.Name()
		if len(filename) != 69 || (filepath.Ext(filename) != ".json" && filepath.Ext(filename) != ".seal") {
			return errors.New("unknown private state history entry")
		}
		decoded, err := hex.DecodeString(filename[:64])
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != filename[:64] {
			return errors.New("private history digest invalid")
		}
		if filepath.Ext(filename) == ".json" {
			raw, err := historyBytes(ctx, directory, filename, 64<<20)
			if err != nil {
				return err
			}
			var old BuildState
			if err = json.Unmarshal(raw, &old); err != nil {
				return err
			}
			indexes = append(indexes, retained{filename[:64], old.EvaluatedAt})
		}
	}
	sort.Slice(indexes, func(i, j int) bool {
		if !indexes[i].clock.Equal(indexes[j].clock) {
			return indexes[j].clock.Before(indexes[i].clock)
		}
		return indexes[i].name < indexes[j].name
	})
	for i, index := range indexes {
		if i < 3 && !index.clock.IsZero() && !state.EvaluatedAt.Before(index.clock) && state.EvaluatedAt.Sub(index.clock) <= 48*time.Hour {
			continue
		}
		for _, extension := range []string{".json", ".seal"} {
			if err = os.Remove(filepath.Join(directory, index.name+extension)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	_, after, err := readAuthenticatedPrivateState(ctx, workspace, binding)
	if err != nil || after != expected {
		return errors.New("source state changed during retention")
	}
	return ctx.Err()
}

// VerifyRetainedPrivateStateSeal is read-only and never substitutes current
// state for the requested digest. Revalidation of current rights/certification
// and release eligibility remains a separate mandatory production gate.
func VerifyRetainedPrivateStateSeal(ctx context.Context, workspace string, binding, stateHash [32]byte) (BuildState, error) {
	if stateHash == ([32]byte{}) || binding == ([32]byte{}) {
		return BuildState{}, errors.New("explicit retained state binding required")
	}
	directory, err := stateHistoryDirectory(workspace, false)
	if err != nil {
		return BuildState{}, err
	}
	name := hex.EncodeToString(stateHash[:])
	data, err := historyBytes(ctx, directory, name+".json", 64<<20)
	if err != nil {
		return BuildState{}, err
	}
	if sha256.Sum256(data) != stateHash {
		return BuildState{}, errors.New("retained state digest mismatch")
	}
	rawSeal, err := historyBytes(ctx, directory, name+".seal", 4096)
	if err != nil {
		return BuildState{}, err
	}
	var seal stateSeal
	decoder := json.NewDecoder(bytes.NewReader(rawSeal))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&seal); err != nil {
		return BuildState{}, err
	}
	if err = decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return BuildState{}, errors.New("retained seal trailing data")
	}
	key, err := readPrivateBounded(ctx, workspace, "state-seal.key", 32)
	if err != nil || len(key) != 32 {
		return BuildState{}, errors.New("retained state key unavailable")
	}
	expected := sealMAC(key, binding, stateHash)
	if seal.Version != 2 || seal.PolicyHash != binding || seal.StateHash != stateHash || !hmac.Equal(expected[:], seal.MAC[:]) {
		return BuildState{}, errors.New("retained state seal invalid")
	}
	var state BuildState
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil {
		return BuildState{}, err
	}
	if err = decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return BuildState{}, errors.New("retained state trailing data")
	}
	if state.Version != 2 || state.PolicyHash != binding {
		return BuildState{}, errors.New("retained state version/binding invalid")
	}
	for _, source := range state.Sources {
		if source.Receipt == nil || source.Receipt.NormalizationPolicyHash != binding {
			return BuildState{}, errors.New("retained source receipt missing")
		}
		if err = WalkStoredSource(ctx, workspace, source, func(NormalizedRecord) error { return nil }); err != nil {
			return BuildState{}, err
		}
	}
	return state, nil
}
