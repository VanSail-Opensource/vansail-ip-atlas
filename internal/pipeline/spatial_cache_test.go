package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func spatialBackendFixture(t *testing.T) (string, [32]byte, intelligence.RecordPartition, map[[32]byte]string) {
	t.Helper()
	root := t.TempDir()
	store, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(context.Background())
	defer writer.Abort()
	record := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Prefix: netip.MustParsePrefix("8.8.8.0/24"), PhysicalCountry: "US", Family: "fixture", Current: true}}
	if err = writer.Append(record); err != nil {
		t.Fatal(err)
	}
	parts, err := writer.Finish()
	if err != nil || len(parts) != 1 {
		t.Fatal(err)
	}
	part := parts[0]
	path := filepath.Join(root, ".atlas-private", "records-v2", digestHex(part.SHA256)+".records")
	return root, sha256.Sum256([]byte("spatial-backend-reviewed-contract")), part, map[[32]byte]string{part.SHA256: path}
}

func digestHex(v [32]byte) string { return spatialCacheFileName(v)[:64] }

func TestSpatialCacheTypedRoundTripKeepsOwnedMetadataAndExactFiles(t *testing.T) {
	ctx := context.Background()
	root, contract, part, files := spatialBackendFixture(t)
	c, err := openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("exact-input"))
	seed := spatialCacheEntry{Domain: "seed", Key: key, Seed: &spatialCacheSeed{}}
	seed.Seed.Parts[0] = []intelligence.RecordPartition{part}
	scatter := spatialCacheEntry{Domain: "scatter", Key: key, Scatter: &spatialCacheScatter{Terminals: []spatialCacheTerminal{{Prefix: netip.MustParsePrefix("8.0.0.0/8"), Cover: netip.MustParsePrefix("8.8.8.0/24"), Parts: []intelligence.RecordPartition{part}}}}}
	risk := spatialCacheEntry{Domain: "risk", Key: key, Leaf: &spatialCacheLeaf{Split: true}}
	public := spatialCacheEntry{Domain: "public", Key: key, Leaf: &spatialCacheLeaf{}}
	entries := []spatialCacheEntry{seed, scatter, risk, public}
	for _, entry := range entries {
		if retained, err := c.Retain(ctx, entry, files); err != nil || !retained {
			t.Fatal(retained, err)
		}
	}
	// Retention and lookup both own their descriptor slices. Caller mutation
	// cannot rewrite the generation that a later process authenticates.
	seed.Seed.Parts[0][0].Records++
	actual, hit, err := c.Lookup(ctx, "seed", key)
	if err != nil || !hit || actual.Seed.Parts[0][0] != part {
		t.Fatal("retained metadata aliases its caller", err)
	}
	actual.Seed.Parts[0][0].Bytes++
	if err = c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	preparedBytes := c.DiskBytes()
	if err = c.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Abort(); err != nil {
		t.Fatal(err)
	}
	if c.DiskBytes() != preparedBytes {
		t.Fatal("first-generation accounting changed at commit")
	}
	if err = c.Abort(); err != nil {
		t.Fatal(err)
	}
	next, err := openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer next.Abort()
	for _, entry := range entries {
		if entry.Domain == "seed" {
			entry.Seed.Parts[0][0] = part
		}
		value, hit, err := next.Lookup(ctx, entry.Domain, key)
		if err != nil || !hit || !reflect.DeepEqual(value, entry) {
			t.Fatal("typed cache roundtrip differs", entry.Domain, err)
		}
	}
	path, err := next.ObjectPath(part.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(data) != part.SHA256 {
		t.Fatal("cached object bytes differ", err)
	}
}

func TestSpatialCacheContractChangeIsMissWithoutBorrowingEntry(t *testing.T) {
	ctx := context.Background()
	root, contract, part, files := spatialBackendFixture(t)
	c, err := openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	entry := spatialCacheEntry{Domain: "seed", Key: sha256.Sum256([]byte("same-input")), Seed: &spatialCacheSeed{}}
	entry.Seed.Parts[0] = []intelligence.RecordPartition{part}
	if ok, err := c.Retain(ctx, entry, files); err != nil || !ok {
		t.Fatal(err)
	}
	if err = c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Abort(); err != nil {
		t.Fatal(err)
	}
	contract[0] ^= 1
	c, err = openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Abort()
	if _, hit, err := c.Lookup(ctx, "seed", entry.Key); err != nil || hit {
		t.Fatal("changed compiler contract borrowed cached derivation", err)
	}
	if c.DiskBytes() <= uint64(part.Bytes)+32 {
		t.Fatal("ineligible prior generation disappeared from accounting")
	}
}

func TestSpatialCacheCarriesOnlyExactAuthenticatedEntryWithoutCallerFiles(t *testing.T) {
	ctx := context.Background()
	root, contract, part, files := spatialBackendFixture(t)
	entry := spatialCacheEntry{Domain: "seed", Key: sha256.Sum256([]byte("carry-input")), Seed: &spatialCacheSeed{}}
	entry.Seed.Parts[0] = []intelligence.RecordPartition{part}
	c, err := openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Retain(ctx, entry, files); err != nil || !ok {
		t.Fatal(err)
	}
	if err = c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Abort(); err != nil {
		t.Fatal(err)
	}
	c, err = openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Abort()
	changed := cloneSpatialEntry(entry)
	changed.Key[0] ^= 1
	if ok, err := c.Retain(ctx, changed, nil); err == nil || ok {
		t.Fatal("new key borrowed old output without a producer file")
	}
	changed = cloneSpatialEntry(entry)
	changed.Seed.Parts[0][0].Records++
	if ok, err := c.Retain(ctx, changed, nil); err == nil || ok {
		t.Fatal("changed metadata borrowed old output")
	}
	before := c.DiskBytes()
	if ok, err := c.Retain(ctx, entry, nil); err != nil || !ok {
		t.Fatal("exact authenticated hit did not carry forward", err)
	}
	if c.DiskBytes() <= before+uint64(part.Bytes) {
		t.Fatal("carried generation skipped staging/index accounting")
	}
	changed = cloneSpatialEntry(entry)
	changed.Key[0] ^= 1
	if ok, err := c.Retain(ctx, changed, nil); err == nil || ok {
		t.Fatal("new key borrowed an already staged object without a producer file")
	}
	changed = cloneSpatialEntry(entry)
	changed.Seed.Parts[0][0].Records++
	if ok, err := c.Retain(ctx, changed, nil); err == nil || ok {
		t.Fatal("changed metadata borrowed an already staged object")
	}
	if err = c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSpatialCacheCommitRejectsPostPrepareObjectAndIndexChanges(t *testing.T) {
	for _, what := range []string{"object", "authenticated-index"} {
		t.Run(what, func(t *testing.T) {
			ctx := context.Background()
			root, contract, part, files := spatialBackendFixture(t)
			c, err := openSpatialCache(ctx, root, contract, 64<<20, func(uint64) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort()
			entry := spatialCacheEntry{Domain: "seed", Key: sha256.Sum256([]byte("input")), Seed: &spatialCacheSeed{}}
			entry.Seed.Parts[0] = []intelligence.RecordPartition{part}
			if ok, err := c.Retain(ctx, entry, files); err != nil || !ok {
				t.Fatal(err)
			}
			if err = c.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			if what == "object" {
				path, err := c.ObjectPath(part.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(c.stage, "index.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var index spatialCacheIndex
				if err = json.Unmarshal(data, &index); err != nil {
					t.Fatal(err)
				}
				index.Contract[0] ^= 1
				index.MAC = spatialIndexMAC(c.key, index)
				data, err = json.Marshal(index)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = c.Commit(ctx); err == nil {
				t.Fatal("cache changed after final preparation was committed")
			}
			if _, err = os.Stat(c.root); !os.IsNotExist(err) {
				t.Fatal("failed cache commit created current generation", err)
			}
		})
	}
}
