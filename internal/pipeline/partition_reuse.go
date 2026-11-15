package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/via3"
)

const compiledCaptureBytes = 32 << 20
const compiledCaptureDepth = 132

type compiledRoute struct {
	Prefix       netip.Prefix
	ASNs         []uint32
	Destinations []via3.ObjectInfo
}
type compiledPartitionEntry struct {
	Objects []via3.ObjectInfo
	Routes  []compiledRoute
}
type compiledCaptureBudget struct{ used uint64 }
type compiledPartitionCapture struct {
	objects       map[string]via3.ObjectInfo
	budget        *compiledCaptureBudget
	bytes         uint64
	disabled      bool
	inputPath     string
	inputHash     [32]byte
	inputBytes    int64
	inputInfo     os.FileInfo
	inputVerified bool
}

// This binding belongs only to an active compiled capture. Its digest covers
// the raw bytes actually supplied to framing/decompression, not a second read
// of the path that could miss an intervening change followed by restoration.
type compiledRunBinding struct {
	ctx           context.Context
	input         io.Reader
	digest        hash.Hash
	bytes         int64
	expectedHash  [32]byte
	expectedBytes int64
	info          os.FileInfo
	captures      []*compiledPartitionCapture
}

func (b *compiledRunBinding) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if b.bytes > b.expectedBytes {
		return 0, errSpatialCache
	}
	// One excess byte suffices to reject growth after opening. Never follow an
	// appended run beyond the input extent authenticated in the cache key.
	if remaining := b.expectedBytes - b.bytes + 1; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := b.input.Read(p)
	if n > 0 {
		_, _ = b.digest.Write(p[:n])
		b.bytes += int64(n)
	}
	if b.bytes > b.expectedBytes {
		return n, errSpatialCache
	}
	return n, err
}

func (b *compiledRunBinding) verifyEOF() error {
	var digest [32]byte
	copy(digest[:], b.digest.Sum(nil))
	if b.bytes != b.expectedBytes || digest != b.expectedHash {
		return errSpatialCache
	}
	if err := b.ctx.Err(); err != nil {
		return err
	}
	for _, capture := range b.captures {
		capture.inputVerified = true
	}
	return nil
}

func (c *compiler) openCompiledRun(path string) (*runReader, error) {
	var binding *compiledRunBinding
	for _, capture := range c.compiledCaptures {
		if capture.inputPath != path {
			continue
		}
		if binding == nil {
			binding = &compiledRunBinding{ctx: c.ctx, digest: sha256.New(), expectedHash: capture.inputHash, expectedBytes: capture.inputBytes, info: capture.inputInfo}
		} else if capture.inputHash != binding.expectedHash || capture.inputBytes != binding.expectedBytes || !os.SameFile(capture.inputInfo, binding.info) {
			return nil, errSpatialCache
		}
		binding.captures = append(binding.captures, capture)
	}
	return openRunBound(path, c.options.Limits.RecordBytes, binding)
}

func cloneCompiledPartition(value *compiledPartitionEntry) *compiledPartitionEntry {
	out := *value
	out.Objects = append([]via3.ObjectInfo(nil), value.Objects...)
	out.Routes = append([]compiledRoute(nil), value.Routes...)
	for i := range out.Routes {
		out.Routes[i].ASNs = append([]uint32(nil), out.Routes[i].ASNs...)
		out.Routes[i].Destinations = append([]via3.ObjectInfo(nil), out.Routes[i].Destinations...)
	}
	return &out
}

func compiledScope(value string) (scope, error) {
	var s scope
	if strings.HasPrefix(value, "asn:") {
		parts := strings.Split(value, ":")
		if len(parts) != 3 {
			return s, errSpatialCache
		}
		first, e1 := strconv.ParseUint(parts[1], 10, 32)
		last, e2 := strconv.ParseUint(parts[2], 10, 32)
		if e1 != nil || e2 != nil || first > last {
			return s, errSpatialCache
		}
		s = scope{asn: true, first: uint32(first), last: uint32(last)}
	} else if strings.HasPrefix(value, "4:") || strings.HasPrefix(value, "6:") {
		parts := strings.Split(value[2:], "/")
		if len(parts) != 2 {
			return s, errSpatialCache
		}
		data, e1 := hex.DecodeString(parts[0])
		bits, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || len(data) != 16 {
			return s, errSpatialCache
		}
		var raw [16]byte
		copy(raw[:], data)
		address := netip.AddrFrom16(raw)
		if value[0] == '4' {
			for _, b := range raw[:12] {
				if b != 0 {
					return s, errSpatialCache
				}
			}
			address = netip.AddrFrom4([4]byte(raw[12:]))
		}
		s.prefix = netip.PrefixFrom(address, bits)
		if !validSpatialPrefix(s.prefix) {
			return s, errSpatialCache
		}
	} else {
		return s, errSpatialCache
	}
	if s.name() != value {
		return scope{}, errSpatialCache
	}
	return s, nil
}

func compiledPartitionFiles(entry *compiledPartitionEntry) (map[[32]byte]uint64, error) {
	if entry == nil || len(entry.Objects) == 0 || len(entry.Objects) > DefaultLimits().MaxObjects || len(entry.Routes) == 0 || len(entry.Routes) > DefaultLimits().MaxObjects {
		return nil, errSpatialCache
	}
	files := make(map[[32]byte]uint64, len(entry.Objects))
	infos := make(map[string]via3.ObjectInfo, len(entry.Objects))
	for i, info := range entry.Objects {
		if info.Kind < 2 || info.Kind > 14 || info.Bytes < 64 || uint64(info.Bytes) > DefaultLimits().ObjectBytes || len(info.SHA256) != 64 || i > 0 && entry.Objects[i-1].SHA256 >= info.SHA256 {
			return nil, errSpatialCache
		}
		decoded, err := hex.DecodeString(info.SHA256)
		if err != nil || hex.EncodeToString(decoded) != info.SHA256 {
			return nil, errSpatialCache
		}
		if info.Partition != "all" {
			if _, err := compiledScope(info.Partition); err != nil {
				return nil, err
			}
		}
		var hash [32]byte
		copy(hash[:], decoded)
		files[hash] = uint64(info.Bytes)
		infos[info.SHA256] = info
	}
	var routeBytes uint64
	destinationScopes := make(map[string]map[string]bool)
	for _, r := range entry.Routes {
		if len(r.Destinations) == 0 || len(r.Destinations) > 12 || len(r.ASNs) > DefaultLimits().PartitionRecords {
			return nil, errSpatialCache
		}
		ip := r.Prefix.IsValid()
		if ip {
			if !validSpatialPrefix(r.Prefix) || len(r.ASNs) != 0 {
				return nil, errSpatialCache
			}
		} else if len(r.ASNs) == 0 {
			return nil, errSpatialCache
		}
		for i, asn := range r.ASNs {
			if !facts.PublicASN(asn) || i > 0 && r.ASNs[i-1] >= asn {
				return nil, errSpatialCache
			}
		}
		for i, d := range r.Destinations {
			object, ok := infos[d.SHA256]
			if !ok || object.Kind != d.Kind || object.Bytes != d.Bytes || i > 0 && r.Destinations[i-1].Kind >= d.Kind {
				return nil, errSpatialCache
			}
			if ip && (d.Kind < 2 || d.Kind > 7 && d.Kind != 9 && d.Kind != 10) || !ip && d.Kind != 8 && d.Kind != 11 && d.Kind != 12 && d.Kind != 13 {
				return nil, errSpatialCache
			}
			local, err := compiledScope(d.Partition)
			if err != nil || local.asn == ip {
				return nil, errSpatialCache
			}
			if ip && local.prefix != r.Prefix || !ip && (r.ASNs[0] < local.first || r.ASNs[len(r.ASNs)-1] > local.last) {
				return nil, errSpatialCache
			}
			if object.Partition != "all" && object.Partition != d.Partition {
				return nil, errSpatialCache
			}
			if destinationScopes[d.SHA256] == nil {
				destinationScopes[d.SHA256] = make(map[string]bool)
			}
			destinationScopes[d.SHA256][d.Partition] = true
		}
		routeBytes += uint64(16 + 4*len(r.Destinations) + 8*len(r.ASNs))
		if ip {
			routeBytes += 32
		}
		if routeBytes > via3.PublicObjectDecoded {
			return nil, errSpatialCache
		}
	}
	for _, info := range entry.Objects {
		if info.Partition != "all" && !destinationScopes[info.SHA256][info.Partition] {
			return nil, errSpatialCache
		}
	}
	return files, nil
}

// The input's key is computed before compilation. Authenticate that same owned
// run again at its actual consumption/removal boundary before retaining output.
func (c *compiler) checkCompiledRunRemoval(path string) error {
	for _, capture := range c.compiledCaptures {
		if capture.inputPath != path {
			continue
		}
		if !capture.inputVerified {
			return errSpatialCache
		}
		hash, err := cacheFileHash(c.ctx, path, capture.inputBytes)
		if err != nil || hash != capture.inputHash {
			return errors.Join(err, errSpatialCache)
		}
	}
	return nil
}

// Every active subtree captures original registrations, including objects that
// a sibling already registered globally. Only sharing within that subtree may
// promote its local manifest scope to all.
func (c *compiler) captureCompiledObject(info via3.ObjectInfo) {
	for _, capture := range c.compiledCaptures {
		if capture.disabled {
			continue
		}
		if prior, ok := capture.objects[info.SHA256]; ok {
			if prior.Kind != info.Kind || prior.Bytes != info.Bytes {
				capture.disabled = true
				capture.budget.used -= capture.bytes
				capture.bytes = 0
				capture.objects = nil
				continue
			}
			if prior.Partition != info.Partition {
				prior.Partition = "all"
				capture.objects[info.SHA256] = prior
			}
			continue
		}
		cost := uint64(512 + len(info.Partition))
		if len(capture.objects) >= c.options.Limits.MaxObjects || cost > compiledCaptureBytes-capture.budget.used {
			capture.disabled = true
			capture.budget.used -= capture.bytes
			capture.bytes = 0
			capture.objects = nil
			continue
		}
		capture.objects[info.SHA256] = info
		capture.bytes += cost
		capture.budget.used += cost
	}
}

func (c *compiler) registerCompiledRoute(value route) error {
	charge := uint64(16 + 4*len(value.destinations))
	if value.prefix.IsValid() {
		charge += 32
	} else {
		charge += 8 * uint64(len(value.asns))
	}
	if charge > via3.PublicObjectDecoded-c.routerBytes || uint64(len(c.objects))*40+charge+c.routerBytes > via3.PublicObjectDecoded {
		return &via3.Error{Code: "resource_limit"}
	}
	c.routerBytes += charge
	c.routes = append(c.routes, value)
	c.stats.Partitions++
	return nil
}

func (c *compiler) partition(path string, s scope) error {
	cache := c.options.compiledReuse
	if cache == nil || len(c.compiledCaptures) >= compiledCaptureDepth {
		return c.partitionFresh(path, s)
	}
	var dependency [32]byte
	if c.options.partitionDependencies != nil {
		var err error
		dependency, err = c.options.partitionDependencies(c.ctx)
		if err != nil {
			return err
		}
	} else if c.options.prefixProvider != nil {
		return c.partitionFresh(path, s)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || uint64(info.Size()) > c.options.Limits.ScratchBytes {
		return errSpatialCache
	}
	hash, err := cacheFileHash(c.ctx, path, info.Size())
	if err != nil {
		return err
	}
	key, err := spatialReuseKey("compiled", struct {
		Input, Dependencies [32]byte
		Bytes               int64
		Prefix              netip.Prefix
		ASN                 bool
		First, Last         uint32
	}{hash, dependency, info.Size(), s.prefix, s.asn, s.first, s.last})
	if err != nil {
		return err
	}
	entry, hit, err := cache.Lookup(c.ctx, "compiled", key)
	if err != nil {
		return err
	}
	if hit {
		if err = c.restoreCompiledPartition(entry.Compiled, s); err != nil {
			return err
		}
		// Check the bytes actually consumed at this boundary, not only a prior
		// path hash, before discarding their immutable input run.
		after, err := cacheFileHash(c.ctx, path, info.Size())
		if err != nil || after != hash {
			return errors.Join(err, errSpatialCache)
		}
		if _, err = cache.Retain(c.ctx, entry, nil); err != nil {
			return err
		}
		return c.remove(path)
	}
	capture := &compiledPartitionCapture{objects: map[string]via3.ObjectInfo{}, budget: &compiledCaptureBudget{}, inputPath: path, inputHash: hash, inputBytes: info.Size(), inputInfo: info}
	if len(c.compiledCaptures) > 0 {
		capture.budget = c.compiledCaptures[0].budget
	}
	c.compiledCaptures = append(c.compiledCaptures, capture)
	defer func() {
		c.compiledCaptures = c.compiledCaptures[:len(c.compiledCaptures)-1]
		capture.budget.used -= capture.bytes
	}()
	first := len(c.routes)
	if err = c.partitionFresh(path, s); err != nil {
		return err
	}
	if capture.disabled || len(capture.objects) == 0 || first == len(c.routes) || len(c.routes)-first > c.options.Limits.MaxObjects {
		return nil
	}
	out := &compiledPartitionEntry{Objects: make([]via3.ObjectInfo, 0, len(capture.objects)), Routes: make([]compiledRoute, 0, len(c.routes)-first)}
	files := make(map[[32]byte]string, len(capture.objects))
	for _, info := range capture.objects {
		out.Objects = append(out.Objects, info)
		raw, _ := hex.DecodeString(info.SHA256)
		var digest [32]byte
		copy(digest[:], raw)
		files[digest] = filepath.Join(c.output, "objects", info.SHA256+".via3")
	}
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].SHA256 < out.Objects[j].SHA256 })
	for _, value := range c.routes[first:] {
		out.Routes = append(out.Routes, compiledRoute{value.prefix, append([]uint32(nil), value.asns...), append([]via3.ObjectInfo(nil), value.destinations...)})
	}
	_, err = cache.Retain(c.ctx, spatialCacheEntry{Domain: "compiled", Key: key, Compiled: out}, files)
	return err
}

func (c *compiler) restoreCompiledPartition(entry *compiledPartitionEntry, parent scope) error {
	if _, err := compiledPartitionFiles(entry); err != nil {
		return err
	}
	if len(entry.Objects) > c.options.Limits.MaxObjects {
		return errSpatialCache
	}
	infos := make(map[string]via3.ObjectInfo, len(entry.Objects))
	for _, info := range entry.Objects {
		infos[info.SHA256] = info
	}
	var prefixes []netip.Prefix
	seenASNs := map[uint32]bool{}
	for _, value := range entry.Routes {
		if parent.asn {
			if value.Prefix.IsValid() || len(value.ASNs) > c.options.Limits.PartitionRecords {
				return errSpatialCache
			}
			for _, destination := range value.Destinations {
				local, err := compiledScope(destination.Partition)
				if err != nil || !local.asn || local.first < parent.first || local.last > parent.last {
					return errSpatialCache
				}
			}
			for _, asn := range value.ASNs {
				if asn < parent.first || asn > parent.last || seenASNs[asn] {
					return errSpatialCache
				}
				seenASNs[asn] = true
			}
		} else {
			if !value.Prefix.IsValid() || value.Prefix.Addr().Is4() != parent.prefix.Addr().Is4() || value.Prefix.Bits() < parent.prefix.Bits() || !parent.prefix.Contains(value.Prefix.Addr()) {
				return errSpatialCache
			}
			prefixes = append(prefixes, value.Prefix)
		}
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if order := prefixes[i].Addr().Compare(prefixes[j].Addr()); order != 0 {
			return order < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	for i := 1; i < len(prefixes); i++ {
		if prefixes[i-1].Contains(prefixes[i].Addr()) {
			return errSpatialCache
		}
	}
	// Walk the object closure from routes. Deduplicate before queueing so even
	// repeated dependency rows retain at most one small item per object.
	seen := make(map[string]bool, len(entry.Objects))
	var pending []string
	for _, value := range entry.Routes {
		for _, destination := range value.Destinations {
			if !seen[destination.SHA256] {
				seen[destination.SHA256] = true
				pending = append(pending, destination.SHA256)
			}
		}
	}
	for len(pending) != 0 {
		info := infos[pending[len(pending)-1]]
		pending = pending[:len(pending)-1]
		if uint64(info.Bytes) > c.options.Limits.ObjectBytes {
			return errSpatialCache
		}
		raw, _ := hex.DecodeString(info.SHA256)
		var hash [32]byte
		copy(hash[:], raw)
		path, err := c.options.compiledReuse.ObjectPath(hash)
		if err != nil {
			return err
		}
		data, err := cacheRead(c.ctx, path, int64(info.Bytes))
		if err != nil || len(data) != info.Bytes || sha256.Sum256(data) != hash {
			return errors.Join(err, errSpatialCache)
		}
		shard, err := via3.Read(c.ctx, data)
		if err != nil || shard.Kind != info.Kind {
			return errors.Join(err, errSpatialCache)
		}
		if err = via3.ValidatePublicProfile(shard); err != nil {
			return err
		}
		directory, _ := shard.Rows(7)
		for p := 0; p < len(directory); p += 40 {
			var encoded [64]byte
			hex.Encode(encoded[:], directory[p+8:p+40])
			target, ok := infos[string(encoded[:])]
			if !ok || target.Kind != uint16(directory[p])|uint16(directory[p+1])<<8 || target.Bytes != int(uint32(directory[p+4])|uint32(directory[p+5])<<8|uint32(directory[p+6])<<16|uint32(directory[p+7])<<24) {
				return errSpatialCache
			}
			if !seen[target.SHA256] {
				seen[target.SHA256] = true
				pending = append(pending, target.SHA256)
			}
		}
		if prior, ok := c.objects[info.SHA256]; ok {
			if prior.Kind != info.Kind || prior.Bytes != info.Bytes {
				return errSpatialCache
			}
			written, err := cacheFileHash(c.ctx, filepath.Join(c.output, "objects", info.SHA256+".via3"), int64(info.Bytes))
			if err != nil || written != hash {
				return errors.Join(err, errSpatialCache)
			}
		}
		if err = c.object(via3.BuiltObject{Info: info, Bytes: data, Shard: shard}); err != nil {
			return err
		}
	}
	if len(seen) != len(entry.Objects) {
		return errSpatialCache
	}
	for _, value := range entry.Routes {
		if err := c.registerCompiledRoute(route{value.Prefix, append([]uint32(nil), value.ASNs...), append([]via3.ObjectInfo(nil), value.Destinations...)}); err != nil {
			return err
		}
	}
	return c.ctx.Err()
}
