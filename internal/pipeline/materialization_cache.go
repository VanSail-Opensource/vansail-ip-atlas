package pipeline

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

const materializationCacheVersion = 1
const materializationCacheIndexLimit = 4 << 20

type materializationCacheIndex struct {
	Version    int
	Identity   [32]byte
	Descriptor via3.Descriptor
	MAC        [32]byte
}

type materializationCache struct {
	root, workspace string
	key, identity   [32]byte
	index           *materializationCacheIndex
	bytes, maximum  uint64
	state           intelligence.BuildState
	created         bool
}

var errMaterializationCache = errors.New("private materialization cache invalid")

// The cache accelerates the real materializer. All source/configuration gates
// still run, and its exact identity includes executable bytes, clocks, packing
// limits, complete normalized roots, scoring and authenticated routing outcomes.
func openMaterializationCache(ctx context.Context, options Options, state intelligence.BuildState, policy intelligence.Policy, inputs ProductionInputs) (*materializationCache, error) {
	parent, err := recordSpoolParent(options.Workspace)
	if err != nil {
		return nil, err
	}
	c := &materializationCache{root: filepath.Join(parent, "materialization-cache-v1"), workspace: options.Workspace, state: state, maximum: options.Limits.ScratchBytes / 4}
	executable, err := os.Executable()
	if err != nil {
		return nil, errMaterializationCache
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, errMaterializationCache
	}
	implementation, err := cacheFileHash(ctx, executable, 256<<20)
	if err != nil {
		return nil, err
	}
	var tier1 [32]byte
	if inputs.Tier1 != nil {
		tier1, err = inputs.Tier1.MaterializationIdentity()
		if err != nil {
			return nil, err
		}
	}
	observedAt, coverageValidUntil, completeVRP := inputs.Qualification.RPKIObservation()
	identity, err := json.Marshal(struct {
		Version                                int
		Implementation, Tier1                  [32]byte
		PrivateLabels                          []string
		State                                  intelligence.BuildState
		Policy                                 intelligence.Policy
		Clock, ValidUntil                      int64
		Mode                                   string
		Limits                                 Limits
		VRPComplete                            bool
		RPKIObservedAt, RPKICoverageValidUntil time.Time
	}{materializationCacheVersion, implementation, tier1, options.PrivateLabelValues, state, policy, options.Clock, options.ValidUntil, options.Mode, options.Limits, completeVRP, observedAt, coverageValidUntil})
	if err != nil {
		return nil, err
	}
	c.identity = sha256.Sum256(identity)
	keyPath := filepath.Join(parent, "materialization-cache-v1.key")
	key, err := cacheRead(ctx, keyPath, 32)
	if os.IsNotExist(err) {
		if _, statErr := os.Lstat(c.root); !os.IsNotExist(statErr) {
			return nil, errMaterializationCache
		}
		if _, err = rand.Read(c.key[:]); err != nil {
			return nil, err
		}
		if err = cacheWrite(keyPath, c.key[:]); err != nil {
			return nil, err
		}
	} else if err != nil || len(key) != 32 {
		return nil, errMaterializationCache
	} else {
		copy(c.key[:], key)
	}
	c.bytes = 32
	info, err := os.Lstat(c.root)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errMaterializationCache
	}
	data, err := cacheRead(ctx, filepath.Join(c.root, "index.json"), materializationCacheIndexLimit)
	if err != nil {
		return nil, errMaterializationCache
	}
	var index materializationCacheIndex
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&index) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, errMaterializationCache
	}
	canonical, err := json.Marshal(index)
	if err != nil || !bytes.Equal(canonical, data) || index.Version != materializationCacheVersion {
		return nil, errMaterializationCache
	}
	expected := cacheMAC(c.key, index)
	// A known schema4 generation may be removed after the same authenticated,
	// bounded closed-inventory checks. It can never be a schema5 cache hit.
	legacySchema := index.Descriptor.SchemaVersion == 4
	descriptor := index.Descriptor
	if legacySchema {
		descriptor.SchemaVersion = 5
	}
	if !hmac.Equal(expected[:], index.MAC[:]) || !validCacheDescriptor(descriptor, DefaultLimits()) {
		return nil, errMaterializationCache
	}
	// Closed inventory: bounded regular files only, with no symlinks, extra
	// objects, nested directories or paths supplied by cached metadata.
	entries, err := cacheDirectory(c.root, 2)
	if err != nil || len(entries) != 2 || entries[0].Name() != "index.json" || entries[1].Name() != "objects" {
		return nil, errMaterializationCache
	}
	objects := filepath.Join(c.root, "objects")
	info, err = os.Lstat(objects)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errMaterializationCache
	}
	entries, err = cacheDirectory(objects, len(index.Descriptor.Objects))
	if err != nil || len(entries) != len(index.Descriptor.Objects) {
		return nil, errMaterializationCache
	}
	c.bytes += uint64(len(data))
	for i, object := range index.Descriptor.Objects {
		if entries[i].Name() != object.SHA256+".via3" {
			return nil, errMaterializationCache
		}
		info, err := entries[i].Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(object.Bytes) {
			return nil, errMaterializationCache
		}
		c.bytes += uint64(object.Bytes)
		if c.bytes > DefaultLimits().ScratchBytes/4 {
			return nil, errMaterializationCache
		}
	}
	if index.Identity == c.identity {
		if legacySchema || c.bytes > c.maximum {
			return nil, errMaterializationCache
		}
		c.index = &index
		return c, nil
	}
	// Keep only one generation. This fixed, validated cache directory cannot
	// contain input partitions or caller paths; changed inputs rebuild fully.
	if err = os.RemoveAll(c.root); err != nil {
		return nil, err
	}
	c.bytes = 32
	return c, nil
}

func validCacheDescriptor(d via3.Descriptor, limits Limits) bool {
	if d.Codec != "zstd-1" || d.FormatVersion != 3 || d.SchemaVersion != 5 || (d.Mode != "synthetic" && d.Mode != "engineering" && d.Mode != "production") || d.ValidFrom < 0 || d.ValidUntil <= d.ValidFrom || d.ValidUntil-d.ValidFrom > 720*3600 || len(d.Objects) == 0 || len(d.Objects) > limits.MaxObjects {
		return false
	}
	last := ""
	for _, object := range d.Objects {
		hash, err := hex.DecodeString(object.SHA256)
		if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != object.SHA256 || object.SHA256 <= last || object.Bytes < 64 || uint64(object.Bytes) > limits.ObjectBytes || object.Kind < 1 || object.Kind > 14 || object.Partition == "" || len(object.Partition) > 128 {
			return false
		}
		last = object.SHA256
	}
	return true
}

func cacheMAC(key [32]byte, index materializationCacheIndex) [32]byte {
	index.MAC = [32]byte{}
	data, _ := json.Marshal(index)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("atlas-materialization-cache-v1\x00"))
	_, _ = mac.Write(data)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func cacheRead(ctx context.Context, path string, maximum int64) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if resolved != path {
		return nil, errMaterializationCache
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, errMaterializationCache
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errMaterializationCache
	}
	data, err := io.ReadAll(io.LimitReader(&cacheContextReader{ctx, file}, maximum+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errMaterializationCache
	}
	return data, nil
}

func cacheDirectory(path string, maximum int) ([]os.DirEntry, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errMaterializationCache
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	actual, err := directory.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errMaterializationCache
	}
	entries, err := directory.ReadDir(maximum + 1)
	if err != nil && err != io.EOF || len(entries) > maximum {
		return nil, errMaterializationCache
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

type cacheContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *cacheContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func cacheFileHash(ctx context.Context, path string, maximum int64) ([32]byte, error) {
	var result [32]byte
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return result, errMaterializationCache
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return result, errMaterializationCache
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(&cacheContextReader{ctx, file}, maximum+1))
	if err != nil || n != info.Size() {
		return result, errMaterializationCache
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func cacheWrite(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	return errors.Join(writeErr, syncErr, file.Close())
}

func (c *materializationCache) verifyInputs(ctx context.Context) error {
	for _, source := range c.state.Sources {
		if err := intelligence.VerifyStoredSourceObjects(ctx, c.workspace, source); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (c *compiler) restoreMaterialization() (bool, error) {
	cache := c.options.materializationCache
	if cache == nil || cache.index == nil {
		return false, nil
	}
	if err := cache.verifyInputs(c.ctx); err != nil {
		return false, err
	}
	descriptor := cache.index.Descriptor
	if !validCacheDescriptor(descriptor, c.options.Limits) || descriptor.Mode != c.options.Mode || descriptor.ValidFrom != c.options.Clock || descriptor.ValidUntil != c.options.ValidUntil {
		return false, errMaterializationCache
	}
	for _, info := range descriptor.Objects {
		data, err := cacheRead(c.ctx, filepath.Join(cache.root, "objects", info.SHA256+".via3"), int64(info.Bytes))
		if err != nil || len(data) != info.Bytes || via3.Hash(data) != info.SHA256 {
			return false, errMaterializationCache
		}
		shard, err := via3.Read(c.ctx, data)
		if err != nil || shard.Kind != info.Kind || via3.ValidatePublicProfile(shard) != nil {
			return false, errMaterializationCache
		}
		if err = c.object(via3.BuiltObject{Info: info, Bytes: data}); err != nil {
			return false, err
		}
	}
	c.stats.MaterializationCacheHits = 1
	return true, nil
}

func (c *compiler) retainMaterialization(result Candidate, output string) error {
	cache := c.options.materializationCache
	if cache == nil || cache.index != nil {
		return nil
	}
	index := materializationCacheIndex{Version: materializationCacheVersion, Identity: cache.identity, Descriptor: result.Descriptor}
	index.MAC = cacheMAC(cache.key, index)
	data, err := json.Marshal(index)
	if err != nil {
		return err
	}
	size := result.Stats.OutputBytes + uint64(len(data))
	// Caching is optional when a full retained generation cannot fit alongside
	// the current work. It must never enlarge the reviewed scratch ceiling.
	if size+32 > cache.maximum || len(data) > materializationCacheIndexLimit {
		return nil
	}
	if err = c.reserve(size); err != nil {
		return nil
	}
	stage, err := os.MkdirTemp(filepath.Dir(cache.root), "materialization-cache-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err = os.Mkdir(filepath.Join(stage, "objects"), 0700); err != nil {
		return err
	}
	for _, info := range result.Descriptor.Objects {
		from := filepath.Join(output, "objects", info.SHA256+".via3")
		to := filepath.Join(stage, "objects", info.SHA256+".via3")
		if err = os.Link(from, to); err != nil {
			object, readErr := cacheRead(c.ctx, from, int64(info.Bytes))
			if readErr != nil || len(object) != info.Bytes || via3.Hash(object) != info.SHA256 {
				return errMaterializationCache
			}
			if err = cacheWrite(to, object); err != nil {
				return err
			}
		}
		digest, err := cacheFileHash(c.ctx, to, int64(info.Bytes))
		if err != nil || hex.EncodeToString(digest[:]) != info.SHA256 {
			return errMaterializationCache
		}
	}
	if err = cacheWrite(filepath.Join(stage, "index.json"), data); err != nil {
		return err
	}
	if err = os.Rename(stage, cache.root); err != nil {
		return err
	}
	cache.created = true
	return nil
}
