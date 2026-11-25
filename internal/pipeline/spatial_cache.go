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
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vansail-ip-atlas/internal/intelligence"
)

const spatialCacheVersion = 4
const spatialCacheIndexLimit = 16 << 20
const spatialCacheEntryLimit = 16384
const spatialCacheObjectLimit = 32768

var errSpatialCache = errors.New("private spatial cache invalid")

type spatialCacheSeed struct {
	Parts [6][]intelligence.RecordPartition
}
type spatialCacheTerminal struct {
	Prefix, Cover netip.Prefix
	Parts         []intelligence.RecordPartition
}
type spatialCacheScatter struct{ Terminals []spatialCacheTerminal }
type spatialCacheStream struct {
	SHA256                       [32]byte
	Bytes, DecodedBytes, Records uint64
}
type spatialCacheLeaf struct {
	RiskInput [32]byte `json:",omitzero"`
	Split     bool
	Stream    spatialCacheStream
}
type spatialCacheEntry struct {
	Domain     string
	Key        [32]byte
	SeedSource *seedSourceSummary      `json:",omitempty"`
	Seed       *spatialCacheSeed       `json:",omitempty"`
	Scatter    *spatialCacheScatter    `json:",omitempty"`
	Leaf       *spatialCacheLeaf       `json:",omitempty"`
	Compiled   *compiledPartitionEntry `json:",omitempty"`
	Packed     *compiledIndexEntry     `json:",omitempty"`
}
type spatialCacheIndex struct {
	Version  int
	Contract [32]byte
	Entries  []spatialCacheEntry
	MAC      [32]byte
}
type spatialCacheEntryKey struct {
	domain string
	key    [32]byte
}

// This store authenticates derived files, not source eligibility or canonical
// frame capabilities. Every consumer must still validate bytes it actually
// imports, and every build retains its independent source/publication gates.
// The cache budget includes both generations, the key, indexes and in-flight
// reservations. No old object is hardlinked into a differently charged copy.
type spatialCache struct {
	workspace, parent, root                     string
	workspaceInfo, parentInfo, rootInfo         os.FileInfo
	key, contract, indexHash, stagedIndexHash   [32]byte
	maximum                                     uint64
	fits                                        func(uint64) bool
	currentBytes, stagedBytes, indexReservation uint64
	current                                     map[spatialCacheEntryKey]spatialCacheEntry
	currentObjects                              map[[32]byte]uint64
	entries                                     map[spatialCacheEntryKey]spatialCacheEntry
	objects                                     map[[32]byte]uint64
	stage, backup                               string
	stageInfo, backupInfo                       os.FileInfo
	prepared, committed, aborted, failed        bool
}

func spatialCacheEntryID(e spatialCacheEntry) spatialCacheEntryKey {
	return spatialCacheEntryKey{e.Domain, e.Key}
}
func spatialCacheFileName(digest [32]byte) string { return hex.EncodeToString(digest[:]) + ".cache" }

func validSpatialPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Zone() == "" && p == p.Masked() && !p.Addr().Is4In6()
}

// Only reviewed descriptor shapes enter the signed index. Semantic decoding of
// cached records/public streams remains the consumer's responsibility.
func spatialCacheFiles(e spatialCacheEntry) (map[[32]byte]uint64, error) {
	e, err := e.expanded()
	if err != nil {
		return nil, err
	}
	files := map[[32]byte]uint64{}
	if e.Key == ([32]byte{}) {
		return nil, errSpatialCache
	}
	if e.Domain == seedSourceDomain || e.SeedSource != nil {
		if e.Domain != seedSourceDomain || e.SeedSource == nil || e.Seed != nil || e.Leaf != nil || e.Scatter != nil || e.Compiled != nil || !e.SeedSource.valid() {
			return nil, errSpatialCache
		}
		return files, nil
	}
	if e.Leaf != nil && e.Leaf.RiskInput != ([32]byte{}) && (e.Domain != "risk" || e.Leaf.Split || e.Key == e.Leaf.RiskInput) {
		return nil, errSpatialCache
	}
	if e.Domain == "compiled" {
		if e.Compiled == nil || e.Seed != nil || e.Scatter != nil || e.Leaf != nil {
			return nil, errSpatialCache
		}
		return compiledPartitionFiles(e.Compiled)
	}
	if e.Compiled != nil {
		return nil, errSpatialCache
	}
	add := func(hash [32]byte, size uint64) error {
		if hash == ([32]byte{}) || size == 0 || size > DefaultLimits().ScratchBytes/4 {
			return errSpatialCache
		}
		if previous, ok := files[hash]; ok && previous != size {
			return errSpatialCache
		}
		files[hash] = size
		return nil
	}
	parts := func(values []intelligence.RecordPartition) error {
		if len(values) > 16384 {
			return errSpatialCache
		}
		for _, p := range values {
			if p.SHA256 == ([32]byte{}) || p.Bytes < 8 || p.Bytes > 64<<20 || p.Records == 0 || p.Records > 100000 || !(p.Codec == "" && p.DecodedBytes == 0 || p.Codec == "zstd-v1" && p.DecodedBytes >= 8 && p.DecodedBytes <= 64<<20) {
				return errSpatialCache
			}
			if err := add(p.SHA256, uint64(p.Bytes)); err != nil {
				return err
			}
		}
		return nil
	}
	switch e.Domain {
	case "seed":
		if e.Seed == nil || e.Scatter != nil || e.Leaf != nil {
			return nil, errSpatialCache
		}
		for _, group := range e.Seed.Parts {
			if err := parts(group); err != nil {
				return nil, err
			}
		}
	case "scatter":
		if e.Seed != nil || e.Scatter == nil || e.Leaf != nil || len(e.Scatter.Terminals) == 0 || len(e.Scatter.Terminals) > 16 {
			return nil, errSpatialCache
		}
		for i, terminal := range e.Scatter.Terminals {
			if !validSpatialPrefix(terminal.Prefix) || terminal.Prefix.Addr().Is4() && terminal.Prefix.Bits() > 24 {
				return nil, errSpatialCache
			}
			if len(terminal.Parts) == 0 {
				if terminal.Cover.IsValid() {
					return nil, errSpatialCache
				}
			} else if !validSpatialPrefix(terminal.Cover) || terminal.Prefix.Addr().Is4() != terminal.Cover.Addr().Is4() || !(terminal.Prefix.Contains(terminal.Cover.Addr()) || terminal.Cover.Contains(terminal.Prefix.Addr())) {
				return nil, errSpatialCache
			}
			for _, prior := range e.Scatter.Terminals[:i] {
				if prior.Prefix.Contains(terminal.Prefix.Addr()) || terminal.Prefix.Contains(prior.Prefix.Addr()) {
					return nil, errSpatialCache
				}
			}
			if err := parts(terminal.Parts); err != nil {
				return nil, err
			}
		}
	case rawSplitDomain:
		if e.Seed != nil || e.Scatter != nil || e.Leaf == nil || *e.Leaf != (spatialCacheLeaf{Split: true}) {
			return nil, errSpatialCache
		}
	case "risk", "risk-input", "public", "location":
		if e.Seed != nil || e.Scatter != nil || e.Leaf == nil || (e.Domain == "location" || e.Domain == "risk-input") && e.Leaf.Split {
			return nil, errSpatialCache
		}
		s := e.Leaf.Stream
		if e.Leaf.Split || s == (spatialCacheStream{}) {
			if s != (spatialCacheStream{}) {
				return nil, errSpatialCache
			}
		} else {
			if s.Records == 0 || s.DecodedBytes == 0 || s.DecodedBytes > spatialStreamDecodedLimit || s.Records > s.DecodedBytes/4 || (e.Domain == "risk" || e.Domain == "risk-input") && s.Records > 200000 || e.Domain == "location" && s.Records > 400000 {
				return nil, errSpatialCache
			}
			if err := add(s.SHA256, s.Bytes); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errSpatialCache
	}
	if len(files) > spatialCacheObjectLimit {
		return nil, errSpatialCache
	}
	return files, nil
}

func spatialIndexMAC(key [32]byte, index spatialCacheIndex) [32]byte {
	index.MAC = [32]byte{}
	data, _ := json.Marshal(index)
	mac := hmac.New(sha256.New, key[:])
	switch index.Version {
	case 1:
		_, _ = mac.Write([]byte("atlas-spatial-cache-v1\x00"))
	case 2:
		_, _ = mac.Write([]byte("atlas-spatial-cache-v2\x00"))
	case 3:
		_, _ = mac.Write([]byte("atlas-spatial-cache-v3\x00"))
	case 4:
		_, _ = mac.Write([]byte("atlas-spatial-cache-v4\x00"))
	}
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func openSpatialCache(ctx context.Context, workspace string, contract [32]byte, maximum uint64, fits func(uint64) bool) (*spatialCache, error) {
	if contract == ([32]byte{}) || maximum < 32 || maximum > DefaultLimits().ScratchBytes/4 || fits == nil {
		return nil, errSpatialCache
	}
	parent, err := recordSpoolParent(workspace)
	if err != nil {
		return nil, err
	}
	c := &spatialCache{workspace: filepath.Dir(parent), parent: parent, root: filepath.Join(parent, "spatial-cache-v1"), contract: contract, maximum: maximum, fits: fits,
		current: map[spatialCacheEntryKey]spatialCacheEntry{}, currentObjects: map[[32]byte]uint64{}, entries: map[spatialCacheEntryKey]spatialCacheEntry{}, objects: map[[32]byte]uint64{}}
	c.workspaceInfo, err = os.Stat(c.workspace)
	if err != nil {
		return nil, err
	}
	c.parentInfo, err = os.Stat(parent)
	if err != nil {
		return nil, err
	}
	// A previous crashed operation is not owned by this instance. Do not
	// silently omit its disk use or recursively delete an unverified tree.
	privateEntries, err := cacheDirectory(parent, spatialCacheObjectLimit)
	if err != nil {
		return nil, errSpatialCache
	}
	for _, entry := range privateEntries {
		if strings.HasPrefix(entry.Name(), "spatial-cache-stage-") || strings.HasPrefix(entry.Name(), "spatial-cache-previous-") {
			return nil, errSpatialCache
		}
	}
	keyPath := filepath.Join(parent, "spatial-cache-v1.key")
	key, err := cacheRead(ctx, keyPath, 32)
	if os.IsNotExist(err) {
		if _, statErr := os.Lstat(c.root); !os.IsNotExist(statErr) {
			return nil, errSpatialCache
		}
		if !fits(32) {
			return nil, errors.New("spatial cache key exceeds scratch budget")
		}
		if _, err = rand.Read(c.key[:]); err != nil {
			return nil, err
		}
		if err = cacheWrite(keyPath, c.key[:]); err != nil {
			return nil, err
		}
	} else if err != nil || len(key) != 32 {
		return nil, errSpatialCache
	} else {
		copy(c.key[:], key)
	}
	info, err := os.Lstat(c.root)
	if os.IsNotExist(err) {
		return c, ctx.Err()
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errSpatialCache
	}
	c.rootInfo = info
	index, files, size, hash, err := c.readGeneration(ctx, c.root)
	if err != nil {
		return nil, err
	}
	c.currentBytes, c.indexHash, c.currentObjects = size, hash, files
	if c.DiskBytes() > maximum || !fits(c.DiskBytes()) {
		return nil, errors.New("spatial cache exceeds scratch budget")
	}
	if index.Contract == contract {
		for _, entry := range index.Entries {
			c.current[spatialCacheEntryID(entry)] = entry.packed()
		}
	}
	return c, nil
}

func (c *spatialCache) checkRoot() error {
	if c == nil || c.aborted || c.failed || c.committed {
		return errSpatialCache
	}
	for _, p := range []struct {
		path string
		info os.FileInfo
	}{{c.workspace, c.workspaceInfo}, {c.parent, c.parentInfo}} {
		resolved, err := filepath.EvalSymlinks(p.path)
		if err != nil || resolved != p.path {
			return errSpatialCache
		}
		info, err := os.Lstat(p.path)
		if err != nil || !info.IsDir() || !os.SameFile(info, p.info) {
			return errSpatialCache
		}
	}
	key, err := cacheRead(context.Background(), filepath.Join(c.parent, "spatial-cache-v1.key"), 32)
	if err != nil || !hmac.Equal(key, c.key[:]) {
		return errSpatialCache
	}
	return nil
}

func (c *spatialCache) readGeneration(ctx context.Context, root string) (spatialCacheIndex, map[[32]byte]uint64, uint64, [32]byte, error) {
	var index spatialCacheIndex
	fail := func() (spatialCacheIndex, map[[32]byte]uint64, uint64, [32]byte, error) {
		return index, nil, 0, [32]byte{}, errors.Join(errSpatialCache, ctx.Err())
	}
	entries, err := cacheDirectory(root, 2)
	if err != nil || len(entries) != 2 || entries[0].Name() != "index.json" || entries[1].Name() != "objects" {
		return fail()
	}
	data, err := cacheRead(ctx, filepath.Join(root, "index.json"), spatialCacheIndexLimit)
	if err != nil {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&index) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return fail()
	}
	canonical, err := json.Marshal(index)
	if err != nil || !bytes.Equal(data, canonical) || (index.Version < 1 || index.Version > spatialCacheVersion) || index.Contract == ([32]byte{}) || len(index.Entries) == 0 || len(index.Entries) > spatialCacheEntryLimit {
		return fail()
	}
	mac := spatialIndexMAC(c.key, index)
	if !hmac.Equal(mac[:], index.MAC[:]) {
		return fail()
	}
	files := map[[32]byte]uint64{}
	for i, entry := range index.Entries {
		if !entry.matchesIndexVersion(index.Version) {
			return fail()
		}
		if i > 0 && !spatialEntryLess(index.Entries[i-1], entry) {
			return fail()
		}
		group, e := spatialCacheFiles(entry)
		if e != nil {
			return fail()
		}
		for hash, size := range group {
			if previous, ok := files[hash]; ok && previous != size {
				return fail()
			}
			files[hash] = size
		}
		if len(files) > spatialCacheObjectLimit {
			return fail()
		}
	}
	objects, err := cacheDirectory(filepath.Join(root, "objects"), len(files))
	if err != nil || len(objects) != len(files) {
		return fail()
	}
	size := uint64(len(data))
	for _, object := range objects {
		name := object.Name()
		if len(name) != 70 || !strings.HasSuffix(name, ".cache") {
			return fail()
		}
		decoded, e := hex.DecodeString(name[:64])
		if e != nil || hex.EncodeToString(decoded) != name[:64] {
			return fail()
		}
		var hash [32]byte
		copy(hash[:], decoded)
		expected, ok := files[hash]
		if !ok {
			return fail()
		}
		info, e := object.Info()
		if e != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != expected || expected > DefaultLimits().ScratchBytes/4-size {
			return fail()
		}
		size += expected
	}
	return index, files, size, sha256.Sum256(data), ctx.Err()
}

func spatialEntryLess(a, b spatialCacheEntry) bool {
	if a.Domain != b.Domain {
		return a.Domain < b.Domain
	}
	return bytes.Compare(a.Key[:], b.Key[:]) < 0
}
func cloneSpatialEntry(e spatialCacheEntry) spatialCacheEntry {
	if e.SeedSource != nil {
		summary := *e.SeedSource
		summary.ASNs = append([]uint32(nil), summary.ASNs...)
		summary.Risk = append([]byte(nil), summary.Risk...)
		e.SeedSource = &summary
	}
	if e.Seed != nil {
		value := *e.Seed
		for i := range value.Parts {
			value.Parts[i] = append([]intelligence.RecordPartition(nil), value.Parts[i]...)
		}
		e.Seed = &value
	}
	if e.Scatter != nil {
		value := *e.Scatter
		value.Terminals = append([]spatialCacheTerminal(nil), value.Terminals...)
		for i := range value.Terminals {
			value.Terminals[i].Parts = append([]intelligence.RecordPartition(nil), value.Terminals[i].Parts...)
		}
		e.Scatter = &value
	}
	if e.Leaf != nil {
		value := *e.Leaf
		e.Leaf = &value
	}
	if e.Compiled != nil {
		e.Compiled = cloneCompiledPartition(e.Compiled)
	}
	return e
}

func (c *spatialCache) DiskBytes() uint64 {
	if c == nil {
		return 0
	}
	return 32 + c.currentBytes + c.stagedBytes
}

func (c *spatialCache) ObjectPath(hash [32]byte) (string, error) {
	if err := c.checkRoot(); err != nil {
		return "", err
	}
	if _, ok := c.objects[hash]; ok && c.stage != "" {
		return spatialGenerationPath(c.stage, c.stageInfo, hash)
	}
	if _, ok := c.currentObjects[hash]; !ok {
		return "", errSpatialCache
	}
	return spatialGenerationPath(c.root, c.rootInfo, hash)
}

func spatialGenerationPath(root string, expected os.FileInfo, hash [32]byte) (string, error) {
	info, err := os.Lstat(root)
	if err != nil || expected == nil || !info.IsDir() || !os.SameFile(info, expected) {
		return "", errSpatialCache
	}
	path := filepath.Join(root, "objects", spatialCacheFileName(hash))
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errSpatialCache
	}
	return path, nil
}

func (c *spatialCache) checkStage() error {
	if c.stage == "" {
		return errSpatialCache
	}
	resolved, err := filepath.EvalSymlinks(c.stage)
	if err != nil || resolved != c.stage {
		return errSpatialCache
	}
	info, err := os.Lstat(c.stage)
	if err != nil || c.stageInfo == nil || !info.IsDir() || !os.SameFile(info, c.stageInfo) {
		return errSpatialCache
	}
	return nil
}

func (c *spatialCache) Lookup(ctx context.Context, domain string, key [32]byte) (spatialCacheEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return spatialCacheEntry{}, false, err
	}
	if err := c.checkRoot(); err != nil {
		return spatialCacheEntry{}, false, err
	}
	if key == ([32]byte{}) || domain != "seed" && domain != seedSourceDomain && domain != "scatter" && domain != "risk" && domain != "risk-input" && domain != "public" && domain != "compiled" && domain != "location" && domain != rawSplitDomain {
		return spatialCacheEntry{}, false, errSpatialCache
	}
	id := spatialCacheEntryKey{domain, key}
	entry, ok := c.entries[id]
	if !ok {
		entry, ok = c.current[id]
	}
	if !ok {
		return spatialCacheEntry{}, false, nil
	}
	entry, err := entry.expanded()
	if err != nil {
		return spatialCacheEntry{}, false, err
	}
	files, err := spatialCacheFiles(entry)
	if err != nil {
		return spatialCacheEntry{}, false, err
	}
	for digest, size := range files {
		path, err := c.ObjectPath(digest)
		if err != nil {
			return spatialCacheEntry{}, false, err
		}
		hash, err := cacheFileHash(ctx, path, int64(size))
		if err != nil || hash != digest {
			return spatialCacheEntry{}, false, errors.Join(errSpatialCache, err)
		}
	}
	return cloneSpatialEntry(entry), true, nil
}

func (c *spatialCache) ensureStage() error {
	if c.stage != "" {
		return nil
	}
	path, err := os.MkdirTemp(c.parent, "spatial-cache-stage-")
	if err != nil {
		return err
	}
	c.stage = path
	c.stageInfo, err = os.Lstat(path)
	if err != nil {
		return err
	}
	return os.Mkdir(filepath.Join(path, "objects"), 0700)
}

func (c *spatialCache) Retain(ctx context.Context, entry spatialCacheEntry, files map[[32]byte]string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := c.checkRoot(); err != nil {
		return false, err
	}
	if c.prepared || c.committed || entry.Packed != nil {
		return false, errSpatialCache
	}
	objects, err := spatialCacheFiles(entry)
	if err != nil {
		return false, err
	}
	entry = cloneSpatialEntry(entry).packed()
	encoded, err := json.Marshal(entry)
	if err != nil {
		return false, err
	}
	id := spatialCacheEntryID(entry)
	if prior, ok := c.entries[id]; ok {
		old, _ := json.Marshal(prior)
		if !bytes.Equal(old, encoded) {
			return false, errSpatialCache
		}
		return true, nil
	}
	// An exact authenticated hit may carry its immutable objects into the new
	// generation without caller paths. This is not permission to attach old
	// output to a new key or changed metadata: those require actual input files.
	carry := false
	if prior, ok := c.current[id]; ok {
		old, _ := json.Marshal(cloneSpatialEntry(prior))
		carry = bytes.Equal(old, encoded)
	}
	sources := make(map[[32]byte]string, len(objects))
	if len(c.entries) >= spatialCacheEntryLimit {
		return false, nil
	}
	indexExtra := uint64(len(encoded) + 1)
	if c.indexReservation == 0 {
		indexExtra += 1024
	}
	if indexExtra > spatialCacheIndexLimit-c.indexReservation {
		return false, nil
	}
	extra := indexExtra
	newObjects := 0
	for digest, size := range objects {
		source := files[digest]
		if source == "" && (!carry || c.currentObjects[digest] != size) {
			return false, errSpatialCache
		}
		if previous, ok := c.objects[digest]; ok {
			if previous != size {
				return false, errSpatialCache
			}
			continue
		}
		if source == "" {
			var err error
			source, err = c.ObjectPath(digest)
			if err != nil {
				return false, err
			}
		}
		sources[digest] = source
		if size > c.maximum || extra > c.maximum-size {
			return false, nil
		}
		extra += size
		newObjects++
	}
	if len(c.objects)+newObjects > spatialCacheObjectLimit || extra > c.maximum || c.DiskBytes() > c.maximum-extra || !c.fits(c.DiskBytes()+extra) {
		return false, nil
	}
	if err = c.ensureStage(); err != nil {
		return false, err
	}
	c.stagedBytes += extra
	c.indexReservation += indexExtra
	for digest, size := range objects {
		if _, ok := c.objects[digest]; ok {
			continue
		}
		destination := filepath.Join(c.stage, "objects", spatialCacheFileName(digest))
		if err = spatialCacheCopy(ctx, c.workspace, sources[digest], destination, digest, size); err != nil {
			// Keep every reservation until the exact owned staging directory is
			// removed. A partial-write cleanup failure must never undercount disk.
			c.failed = true
			return false, err
		}
		c.objects[digest] = size
	}
	c.entries[id] = entry
	return true, nil
}

func spatialCacheCopy(ctx context.Context, workspace, source, destination string, digest [32]byte, size uint64) (returnErr error) {
	if !filepath.IsAbs(source) {
		return errSpatialCache
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil || resolved != source {
		return errSpatialCache
	}
	rel, err := filepath.Rel(workspace, source)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errSpatialCache
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != size {
		return errSpatialCache
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	actual, err := input.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return errSpatialCache
	}
	parent := filepath.Dir(destination)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errSpatialCache
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, output.Close())
		if returnErr != nil {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(&cacheContextReader{ctx, input}, int64(size)))
	if err != nil || uint64(n) != size {
		return errors.Join(err, errSpatialCache)
	}
	var extra [1]byte
	nExtra, readErr := input.Read(extra[:])
	if nExtra != 0 || readErr != io.EOF {
		return errSpatialCache
	}
	var copied [32]byte
	copy(copied[:], hash.Sum(nil))
	if copied != digest {
		return errSpatialCache
	}
	if err = output.Sync(); err != nil {
		return err
	}
	written, err := cacheFileHash(ctx, destination, int64(size))
	if err != nil || written != digest {
		return errors.Join(err, errSpatialCache)
	}
	return ctx.Err()
}

func (c *spatialCache) checkCurrent(ctx context.Context) error {
	if c.rootInfo == nil {
		if _, err := os.Lstat(c.root); !os.IsNotExist(err) {
			return errSpatialCache
		}
		return nil
	}
	info, err := os.Lstat(c.root)
	if err != nil || !os.SameFile(info, c.rootInfo) {
		return errSpatialCache
	}
	_, _, size, hash, err := c.readGeneration(ctx, c.root)
	if err != nil || hash != c.indexHash || size != c.currentBytes {
		return errSpatialCache
	}
	return nil
}

func (c *spatialCache) Prepare(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.checkRoot(); err != nil {
		return err
	}
	if c.committed {
		return errSpatialCache
	}
	if c.prepared {
		return nil
	}
	if err := c.checkCurrent(ctx); err != nil {
		return err
	}
	if len(c.entries) == 0 {
		c.prepared = true
		return nil
	}
	if err := c.checkStage(); err != nil {
		return err
	}
	index := spatialCacheIndex{Version: spatialCacheVersion, Contract: c.contract, Entries: make([]spatialCacheEntry, 0, len(c.entries))}
	for _, entry := range c.entries {
		index.Entries = append(index.Entries, entry)
	}
	sort.Slice(index.Entries, func(i, j int) bool { return spatialEntryLess(index.Entries[i], index.Entries[j]) })
	index.MAC = spatialIndexMAC(c.key, index)
	data, err := json.Marshal(index)
	if err != nil || len(data) > spatialCacheIndexLimit || uint64(len(data)) > c.indexReservation {
		return errSpatialCache
	}
	for digest, size := range c.objects {
		path, err := spatialGenerationPath(c.stage, c.stageInfo, digest)
		if err != nil {
			return err
		}
		hash, err := cacheFileHash(ctx, path, int64(size))
		if err != nil || hash != digest {
			return errors.Join(errSpatialCache, err)
		}
	}
	if !c.fits(c.DiskBytes()) {
		return errors.New("spatial cache exceeds scratch budget")
	}
	if err = cacheWrite(filepath.Join(c.stage, "index.json"), data); err != nil {
		c.failed = true
		return err
	}
	c.stagedBytes -= c.indexReservation - uint64(len(data))
	c.indexReservation = uint64(len(data))
	c.stagedIndexHash = sha256.Sum256(data)
	if err := c.checkStage(); err != nil {
		return err
	}
	_, _, size, hash, err := c.readGeneration(ctx, c.stage)
	if err != nil || size != c.stagedBytes || hash != c.stagedIndexHash {
		return errSpatialCache
	}
	c.prepared = true
	return ctx.Err()
}

// Commit switches only complete generations. The prior generation stays in an
// owned backup until Abort closes the successful operation, so a failed rename
// can restore it without deleting any old authenticated object.
func (c *spatialCache) Commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.checkRoot(); err != nil {
		return err
	}
	if !c.prepared || c.committed {
		return errSpatialCache
	}
	if err := c.checkCurrent(ctx); err != nil {
		return err
	}
	if !c.fits(c.DiskBytes()) {
		return errors.New("spatial cache exceeds scratch budget")
	}
	if len(c.entries) == 0 {
		c.committed = true
		return nil
	}
	// Prepare precedes the final build gates. Recheck the exact staged bytes
	// before their atomic switch as well; mutable cache files cannot borrow a
	// successful earlier hash read.
	if err := c.checkStage(); err != nil {
		return err
	}
	_, _, size, hash, err := c.readGeneration(ctx, c.stage)
	if err != nil || size != c.stagedBytes || hash != c.stagedIndexHash {
		return errors.Join(errSpatialCache, err)
	}
	for digest, size := range c.objects {
		path, err := spatialGenerationPath(c.stage, c.stageInfo, digest)
		if err != nil {
			return err
		}
		hash, err := cacheFileHash(ctx, path, int64(size))
		if err != nil || hash != digest {
			return errors.Join(errSpatialCache, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.rootInfo != nil {
		backup, err := os.MkdirTemp(c.parent, "spatial-cache-previous-")
		if err != nil {
			return err
		}
		if err = os.Remove(backup); err != nil {
			return err
		}
		if err = os.Rename(c.root, backup); err != nil {
			return err
		}
		c.backup, c.backupInfo = backup, c.rootInfo
	}
	if err := ctx.Err(); err != nil {
		if c.backup != "" {
			rollback := os.Rename(c.backup, c.root)
			if rollback == nil {
				c.backup = ""
				c.backupInfo = nil
			}
			return errors.Join(err, rollback)
		}
		return err
	}
	if err := os.Rename(c.stage, c.root); err != nil {
		if c.backup != "" {
			rollback := os.Rename(c.backup, c.root)
			if rollback == nil {
				c.backup = ""
				c.backupInfo = nil
			}
			return errors.Join(err, rollback)
		}
		return err
	}
	c.stage = ""
	c.stageInfo = nil
	c.committed = true
	return nil
}

func removeOwnedSpatialDirectory(path string, info os.FileInfo) error {
	if path == "" {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errSpatialCache
	}
	current, err := os.Lstat(path)
	if err != nil || info == nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(current, info) {
		return errSpatialCache
	}
	return os.RemoveAll(path)
}

// Abort after a successful Commit only discards its previous generation. It
// never removes the newly committed cache. Before Commit it discards only the
// exact staging directory created by this instance.
func (c *spatialCache) Abort() error {
	if c == nil || c.aborted {
		return nil
	}
	if c.committed {
		if err := removeOwnedSpatialDirectory(c.backup, c.backupInfo); err != nil {
			return err
		}
		if len(c.entries) > 0 {
			c.currentBytes = c.stagedBytes
			c.stagedBytes = 0
		}
		c.backup = ""
		c.backupInfo = nil
	} else {
		if err := removeOwnedSpatialDirectory(c.stage, c.stageInfo); err != nil {
			return err
		}
		c.stage = ""
		c.stageInfo = nil
		c.stagedBytes = 0
		c.indexReservation = 0
	}
	c.aborted = true
	return nil
}
