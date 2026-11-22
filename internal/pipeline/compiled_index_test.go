package pipeline

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestCompiledIndexPreservesSharedObjectScopesAndRejectsInvalidOrdinals(t *testing.T) {
	first, second := scope{prefix: netip.MustParsePrefix("11.0.0.0/24")}, scope{prefix: netip.MustParsePrefix("12.0.0.0/24")}
	shared := via3.ObjectInfo{Kind: 6, Bytes: 100, SHA256: strings.Repeat("a", 64), Partition: "all"}
	original := &compiledPartitionEntry{Objects: []via3.ObjectInfo{shared}}
	for _, s := range []scope{first, second} {
		dest := shared
		dest.Partition = s.name()
		original.Routes = append(original.Routes, compiledRoute{Prefix: s.prefix, Destinations: []via3.ObjectInfo{dest}})
	}
	if _, err := compiledPartitionFiles(original); err != nil {
		t.Fatal(err)
	}
	packed := packCompiledIndex(original)
	restored, err := packed.expand()
	if err != nil || !reflect.DeepEqual(original, restored) {
		t.Fatal("shared destination scope lost", err)
	}
	for _, change := range []func(*compiledIndexEntry){
		func(p *compiledIndexEntry) { p.Routes[0].Destinations[0] = uint16(len(p.Table.Sizes)) },
		func(p *compiledIndexEntry) { p.Routes[0].Destinations = nil },
		func(p *compiledIndexEntry) { p.Routes[0].Scopes = []string{"", ""} },
		func(p *compiledIndexEntry) { p.Routes[0].Scopes[0] = "" }, // unnecessary override array
		func(p *compiledIndexEntry) { p.Routes[0].Scopes[0] = "all" },
		func(p *compiledIndexEntry) { p.Routes[0].Scopes[0] = second.name() }, // valid scope, wrong route
	} {
		bad := packCompiledIndex(original)
		change(bad)
		if _, err := spatialCacheFiles(spatialCacheEntry{Domain: "compiled", Key: [32]byte{1}, Packed: bad}); !errors.Is(err, errSpatialCache) {
			t.Fatal("invalid compact route passed", err)
		}
	}
}

func TestCompiledIndexObjectColumnsRequireCompleteValidatedInventory(t *testing.T) {
	p := netip.MustParsePrefix("11.0.0.0/16")
	object := via3.ObjectInfo{Kind: 6, Bytes: 100, SHA256: strings.Repeat("1", 64), Partition: (scope{prefix: p}).name()}
	entry := &compiledPartitionEntry{Objects: []via3.ObjectInfo{object}, Routes: []compiledRoute{{Prefix: p, Destinations: []via3.ObjectInfo{object}}}}
	for _, change := range []func(*compiledIndexEntry){
		func(p *compiledIndexEntry) { p.Objects = entry.Objects },
		func(p *compiledIndexEntry) { p.Table.Hashes = p.Table.Hashes[:31] },
		func(p *compiledIndexEntry) { p.Table.Hashes = append(p.Table.Hashes, 1) },
		func(p *compiledIndexEntry) { p.Table.Sizes = nil },
		func(p *compiledIndexEntry) { p.Table.Kinds = nil },
		func(p *compiledIndexEntry) { p.Table.Scopes = nil },
		func(p *compiledIndexEntry) { p.Table.Sizes[0] = 40 },
		func(p *compiledIndexEntry) { p.Table.Kinds[0] = 255 },
		func(p *compiledIndexEntry) { p.Table.Scopes[0] = "unknown" },
	} {
		bad := packCompiledIndex(entry)
		change(bad)
		if _, err := spatialCacheFiles(spatialCacheEntry{Domain: "compiled", Key: [32]byte{1}, Packed: bad}); !errors.Is(err, errSpatialCache) {
			t.Fatal("accepted inconsistent object columns", err)
		}
	}
}

func TestCompiledIndexASNDeltaBoundsAndExactMembership(t *testing.T) {
	s := scope{asn: true, first: 1, last: 4_199_999_999}
	object := via3.ObjectInfo{Kind: 8, Bytes: 100, SHA256: strings.Repeat("c", 64), Partition: s.name()}
	entry := &compiledPartitionEntry{
		Objects: []via3.ObjectInfo{object},
		Routes: []compiledRoute{{
			ASNs: []uint32{1, 2, 131_072, 4_199_999_999}, Destinations: []via3.ObjectInfo{object},
		}},
	}
	if _, err := compiledPartitionFiles(entry); err != nil {
		t.Fatal(err)
	}
	packed := packCompiledIndex(entry)
	restored, err := packed.expand()
	if err != nil || !reflect.DeepEqual(restored, entry) {
		t.Fatal("changed ASN membership", err)
	}
	if _, err = unpackCompiledASNs(packed.Routes[0].ASNDeltas, 3); !errors.Is(err, errSpatialCache) {
		t.Fatal("ignored decoded count bound", err)
	}
	for _, encoded := range [][]byte{
		{0}, {1, 0}, {0x80}, {1, 0x80}, {0x81, 0},
		binary.AppendUvarint(nil, 1<<32),
		append(binary.AppendUvarint(nil, 1<<32-1), 1),
		binary.AppendUvarint(nil, 23_456), // reserved ASN
		bytes.Repeat([]byte{1}, DefaultLimits().PartitionRecords+1),
	} {
		packed.Routes[0].ASNDeltas = encoded
		if _, err := spatialCacheFiles(spatialCacheEntry{Domain: "compiled", Key: [32]byte{1}, Packed: packed}); !errors.Is(err, errSpatialCache) {
			t.Fatal("accepted invalid ASN membership", err)
		}
	}
}

func TestCurrentSpatialIndexUpgradesAuthenticatedLegacyGenerations(t *testing.T) {
	s := scope{prefix: netip.MustParsePrefix("11.0.0.0/24")}
	rows := []via3.PublicRecord{{Version: 3, Kind: 10, Prefix: s.prefix, Origins: &via3.OriginsData{ASNs: []uint32{13335}}}}
	c, entry, _ := compiledReviewFixture(t, rows, s)
	cache := c.options.compiledReuse
	if err := cache.Prepare(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := cache.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := cache.Abort(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache.root, "index.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index spatialCacheIndex
	if err = json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.Version != spatialCacheVersion || len(index.Entries) != 1 || index.Entries[0].Packed == nil || index.Entries[0].Compiled != nil {
		t.Fatal("new generation did not retain compact metadata")
	}
	generated := index.Entries[0]
	for _, tc := range []struct {
		name    string
		version int
		literal bool
		packed  bool
	}{
		{"compact route in legacy index", 1, false, true},
		{"literal route in current index", 3, true, false},
		{"new object table in older index", 2, false, true},
		{"both route encodings", 2, true, true},
		{"missing route encoding", 2, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := index
			bad.Version = tc.version
			bad.Entries = []spatialCacheEntry{generated}
			if !tc.packed {
				bad.Entries[0].Packed = nil
			}
			if tc.literal {
				bad.Entries[0].Compiled = entry
			}
			bad.MAC = spatialIndexMAC(cache.key, bad)
			wire, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, err := cache.readGeneration(t.Context(), cache.root); !errors.Is(err, errSpatialCache) {
				t.Fatal("accepted an inconsistent signed cache index", err)
			}
		})
	}
	// Recreate each previous wire shape with its original authenticated domain.
	for _, version := range []int{1, 2} {
		t.Run("migrate "+strconv.Itoa(version), func(t *testing.T) {
			index := index
			index.Version = version
			index.Entries = []spatialCacheEntry{generated}
			if version == 1 {
				index.Entries[0].Packed = nil
				index.Entries[0].Compiled = entry
			} else {
				legacy := *generated.Packed
				legacy.Objects, legacy.Table = entry.Objects, nil
				index.Entries[0].Packed = &legacy
			}
			index.MAC = spatialIndexMAC(cache.key, index)
			data, err = json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			upgraded := hostileOpenSpatial(t, c.options.Workspace, 64<<20, func(uint64) bool { return true })
			t.Cleanup(func() { _ = upgraded.Abort() })
			id := index.Entries[0].Key
			lookup, ok, err := upgraded.Lookup(t.Context(), "compiled", id)
			if err != nil || !ok || lookup.Packed != nil || !reflect.DeepEqual(lookup.Compiled, entry) {
				t.Fatal("valid legacy entry did not reopen", err)
			}
			if retained, err := upgraded.Retain(t.Context(), lookup, nil); err != nil || !retained {
				t.Fatal("valid legacy bytes could not carry forward", err)
			}
			lookup.Compiled.Objects[0].Bytes++ // the public API to the cache owns its result
			again, ok, err := upgraded.Lookup(t.Context(), "compiled", id)
			if err != nil || !ok || !reflect.DeepEqual(again.Compiled, entry) {
				t.Fatal("caller altered retained compact metadata", err)
			}
			if err := upgraded.Prepare(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := upgraded.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			newIndex, files, _, _, err := upgraded.readGeneration(t.Context(), cache.root)
			if err != nil || newIndex.Version != spatialCacheVersion || len(files) != len(entry.Objects) || newIndex.Entries[0].Packed == nil || newIndex.Entries[0].Compiled != nil {
				t.Fatal("upgraded index or object inventory failed validation", err)
			}
		})
	}
}
