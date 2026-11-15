package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func hostileSpatialInputs(t *testing.T) (string, spatialCacheEntry, map[[32]byte]string) {
	t.Helper()
	root := t.TempDir()
	data := []byte("synthetic bounded cached stream")
	digest := sha256.Sum256(data)
	path := filepath.Join(root, "stream")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	entry := spatialCacheEntry{Domain: "public", Key: [32]byte{2}, Leaf: &spatialCacheLeaf{
		Stream: spatialCacheStream{SHA256: digest, Bytes: uint64(len(data)), DecodedBytes: uint64(len(data)), Records: 1}}}
	return root, entry, map[[32]byte]string{digest: path}
}

func hostileOpenSpatial(t *testing.T, root string, maximum uint64, fits func(uint64) bool) *spatialCache {
	t.Helper()
	c, err := openSpatialCache(context.Background(), root, [32]byte{1}, maximum, fits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hostilePrimeSpatial(t *testing.T, root string, entry spatialCacheEntry, files map[[32]byte]string) {
	t.Helper()
	c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	if retained, err := c.Retain(context.Background(), entry, files); err != nil || !retained {
		t.Fatal("cache fixture retention failed", retained, err)
	}
	if err := c.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
}

func hostileCacheBytes(t *testing.T, c *spatialCache) uint64 {
	t.Helper()
	var total uint64 = 32
	for _, path := range []string{c.root, c.stage, c.backup} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		if err := filepath.WalkDir(path, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				total += uint64(info.Size())
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return total
}

func TestSpatialCacheHostileIndexAndInventoryFailClosedWithoutDeletion(t *testing.T) {
	for _, mutation := range []string{"mac", "unknown-member", "duplicate-entry", "empty-index", "huge-size", "extra-object", "nested-object", "linked-object", "noncanonical"} {
		t.Run(mutation, func(t *testing.T) {
			root, entry, files := hostileSpatialInputs(t)
			hostilePrimeSpatial(t, root, entry, files)
			c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
			path := filepath.Join(c.root, "index.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var index spatialCacheIndex
			if err := json.Unmarshal(data, &index); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "mac":
				index.MAC[0] ^= 1
			case "duplicate-entry":
				index.Entries = append(index.Entries, index.Entries[0])
			case "empty-index":
				index.Entries = nil
			case "huge-size":
				index.Entries[0].Leaf.Stream.Bytes = ^uint64(0)
			case "extra-object":
				err = os.WriteFile(filepath.Join(c.root, "objects", "unexpected"), []byte("preserve"), 0600)
			case "nested-object":
				err = os.Mkdir(filepath.Join(c.root, "objects", "nested"), 0700)
			case "linked-object":
				object := filepath.Join(c.root, "objects", spatialCacheFileName(entry.Leaf.Stream.SHA256))
				if err = os.Remove(object); err == nil {
					err = os.Symlink(files[entry.Leaf.Stream.SHA256], object)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "mac" {
				index.MAC = spatialIndexMAC(c.key, index)
			}
			data, err = json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "unknown-member" {
				data = append(append([]byte{}, data[:len(data)-1]...), []byte(",\"unexpected\":true}")...)
			}
			if mutation == "noncanonical" {
				data = append(data, '\n')
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := openSpatialCache(context.Background(), root, [32]byte{3}, 1<<20, func(uint64) bool { return true }); err == nil {
				t.Fatal("changed contract hid an invalid old generation")
			}
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != string(data) {
				t.Fatal("invalid generation was altered during rejection", err)
			}
		})
	}
}

func TestSpatialCacheHostileMissingOrChangedKeyCannotReplaceOldGeneration(t *testing.T) {
	for _, mutation := range []string{"missing", "short", "changed"} {
		t.Run(mutation, func(t *testing.T) {
			root, entry, files := hostileSpatialInputs(t)
			hostilePrimeSpatial(t, root, entry, files)
			path := filepath.Join(root, ".atlas-private", "spatial-cache-v1.key")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				err = os.Remove(path)
			case "short":
				data = data[:31]
				err = os.WriteFile(path, data, 0600)
			case "changed":
				data[0] ^= 1
				err = os.WriteFile(path, data, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := openSpatialCache(context.Background(), root, [32]byte{1}, 1<<20, func(uint64) bool { return true }); err == nil {
				t.Fatal("invalid old key was replaced or accepted")
			}
			actual, err := os.ReadFile(path)
			if mutation == "missing" {
				if !os.IsNotExist(err) {
					t.Fatal("missing key was regenerated over an existing generation", err)
				}
			} else if err != nil || string(actual) != string(data) {
				t.Fatal("invalid key was rewritten", err)
			}
		})
	}
}

func TestSpatialCacheHostileSharedObjectAccountingAndSuccessfulAbort(t *testing.T) {
	root, entry, files := hostileSpatialInputs(t)
	hostilePrimeSpatial(t, root, entry, files)
	c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	old := c.DiskBytes()
	if old != hostileCacheBytes(t, c) {
		t.Fatal("old generation accounting differs")
	}
	if retained, err := c.Retain(context.Background(), entry, files); err != nil || !retained {
		t.Fatal(err)
	}
	first := c.DiskBytes()
	if retained, err := c.Retain(context.Background(), entry, files); err != nil || !retained || c.DiskBytes() != first {
		t.Fatal("same entry was charged twice", err)
	}
	second := cloneSpatialEntry(entry)
	second.Key[0]++
	if retained, err := c.Retain(context.Background(), second, files); err != nil || !retained || len(c.objects) != 1 {
		t.Fatal("shared staged object was duplicated", err)
	}
	if err := c.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.DiskBytes() != hostileCacheBytes(t, c) || c.DiskBytes() <= old+entry.Leaf.Stream.Bytes {
		t.Fatal("both generations and indexes were not charged")
	}
	previousStage := c.stage
	if err := c.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.DiskBytes() != hostileCacheBytes(t, c) {
		t.Fatal("previous generation was uncharged before cleanup")
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := c.Abort(); err != nil {
		t.Fatal("successful cleanup was not idempotent", err)
	}
	if _, err := os.Stat(previousStage); !os.IsNotExist(err) {
		t.Fatal("published stage retained its previous path", err)
	}
	reopened := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	for _, key := range [][32]byte{entry.Key, second.Key} {
		if _, hit, err := reopened.Lookup(context.Background(), entry.Domain, key); err != nil || !hit {
			t.Fatal("Abort deleted committed cache", hit, err)
		}
	}
	if reopened.DiskBytes() != hostileCacheBytes(t, reopened) {
		t.Fatal("committed accounting retained the deleted backup")
	}
}

func TestSpatialCacheHostileCapacityAndCancellationPreserveCommittedGeneration(t *testing.T) {
	for _, failure := range []string{"capacity", "canceled-retain", "canceled-copy", "canceled-prepare", "canceled-commit", "late-capacity"} {
		t.Run(failure, func(t *testing.T) {
			root, entry, files := hostileSpatialInputs(t)
			hostilePrimeSpatial(t, root, entry, files)
			allow := true
			c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return allow })
			old, err := os.ReadFile(filepath.Join(c.root, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "capacity" {
				allow = false
				retained, err := c.Retain(context.Background(), entry, files)
				if err != nil || retained || c.stage != "" {
					t.Fatal("optional retention did not decline before writing", retained, err)
				}
			} else if failure == "canceled-retain" {
				cancel()
				if _, err := c.Retain(ctx, entry, files); !errors.Is(err, context.Canceled) || c.stage != "" {
					t.Fatal("canceled retention created staging", err)
				}
			} else if failure == "canceled-copy" {
				trigger := &hostileSpatialCancel{Context: context.Background(), ready: func() bool {
					if c.stage == "" {
						return false
					}
					_, err := os.Stat(filepath.Join(c.stage, "objects", spatialCacheFileName(entry.Leaf.Stream.SHA256)))
					return err == nil
				}}
				if _, err := c.Retain(trigger, entry, files); !errors.Is(err, context.Canceled) || !trigger.fired {
					t.Fatal("copy cancellation was not exercised", err)
				}
				if c.DiskBytes() < hostileCacheBytes(t, c) {
					t.Fatal("failed copy undercharged remaining staging")
				}
			} else {
				if retained, err := c.Retain(ctx, entry, files); err != nil || !retained {
					t.Fatal(err)
				}
				if failure == "canceled-prepare" {
					cancel()
					if err := c.Prepare(ctx); !errors.Is(err, context.Canceled) {
						t.Fatal("canceled preparation succeeded", err)
					}
				} else {
					if err := c.Prepare(ctx); err != nil {
						t.Fatal(err)
					}
					if failure == "canceled-commit" {
						cancel()
					} else {
						allow = false
					}
					if err := c.Commit(ctx); err == nil {
						t.Fatal("invalid final boundary committed staging")
					}
				}
			}
			stage := c.stage
			if err := c.Abort(); err != nil {
				t.Fatal(err)
			}
			if stage != "" {
				if _, err := os.Stat(stage); !os.IsNotExist(err) {
					t.Fatal("failed staging was not removed", err)
				}
			}
			actual, err := os.ReadFile(filepath.Join(c.root, "index.json"))
			if err != nil || string(actual) != string(old) {
				t.Fatal("failed retention changed committed generation", err)
			}
		})
	}
}

type hostileSpatialCancel struct {
	context.Context
	ready func() bool
	fired bool
}

func (c *hostileSpatialCancel) Err() error {
	if c.fired || c.ready() {
		c.fired = true
		return context.Canceled
	}
	return c.Context.Err()
}

func TestSpatialCacheHostileHitRejectsReplacedObjectDirectory(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "staged"}[staged], func(t *testing.T) {
			root, entry, files := hostileSpatialInputs(t)
			hostilePrimeSpatial(t, root, entry, files)
			c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
			generation := c.root
			if staged {
				if retained, err := c.Retain(context.Background(), entry, files); err != nil || !retained {
					t.Fatal(err)
				}
				generation = c.stage
			}
			objects := filepath.Join(generation, "objects")
			moved := filepath.Join(root, "moved-objects")
			if err := os.Rename(objects, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, objects); err != nil {
				t.Fatal(err)
			}
			if _, hit, err := c.Lookup(context.Background(), entry.Domain, entry.Key); err == nil || hit {
				t.Fatal("cache hit followed a replaced object-directory symlink")
			}
		})
	}
}

func TestSpatialCacheHostileOrphansCannotDisappearFromAccounting(t *testing.T) {
	for _, prefix := range []string{"spatial-cache-stage-", "spatial-cache-previous-"} {
		t.Run(prefix, func(t *testing.T) {
			root, entry, files := hostileSpatialInputs(t)
			hostilePrimeSpatial(t, root, entry, files)
			orphan := filepath.Join(root, ".atlas-private", prefix+"interrupted")
			if err := os.Mkdir(orphan, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(orphan, "preserve")
			if err := os.WriteFile(path, []byte("unaccounted private bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := openSpatialCache(context.Background(), root, [32]byte{1}, 1<<20, func(uint64) bool { return true }); err == nil {
				t.Fatal("cache reopened while ignoring an interrupted generation")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("rejection deleted unowned private bytes", err)
			}
		})
	}
}

func TestSpatialCacheHostilePreparedIndexCannotChangeMappingAtEqualLength(t *testing.T) {
	root, entry, files := hostileSpatialInputs(t)
	hostilePrimeSpatial(t, root, entry, files)
	c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	if retained, err := c.Retain(context.Background(), entry, files); err != nil || !retained {
		t.Fatal(err)
	}
	if err := c.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.stage, "index.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index spatialCacheIndex
	if err := json.Unmarshal(original, &index); err != nil {
		t.Fatal(err)
	}
	var changed []byte
	// MAC arrays use decimal bytes in JSON. Search a bounded set for a different
	// authentic key mapping with identical encoded length, avoiding a test that
	// accidentally passes only because the size check rejects its new MAC.
	for i := 1; i < 4096; i++ {
		index.Entries[0].Key[0], index.Entries[0].Key[1] = byte(i), byte(i>>8)
		if index.Entries[0].Key == entry.Key {
			continue
		}
		index.MAC = spatialIndexMAC(c.key, index)
		value, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		if len(value) == len(original) {
			changed = value
			break
		}
	}
	if changed == nil {
		t.Fatal("could not construct equal-length authenticated index mutation")
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(c.root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(context.Background()); err == nil {
		t.Fatal("prepared mapping changed even though all object hashes remained valid")
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(c.root, "index.json"))
	if err != nil || string(actual) != string(old) {
		t.Fatal("rejected prepared mutation replaced committed cache", err)
	}
}

func TestSpatialCacheHostileZeroObjectGenerationStillBindsStageInode(t *testing.T) {
	root, entry, files := hostileSpatialInputs(t)
	hostilePrimeSpatial(t, root, entry, files)
	c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	zero := spatialCacheEntry{Domain: "public", Key: [32]byte{3}, Leaf: &spatialCacheLeaf{Split: true}}
	if retained, err := c.Retain(context.Background(), zero, nil); err != nil || !retained {
		t.Fatal(err)
	}
	if err := c.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(c.stage, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved-stage")
	if err := os.Rename(c.stage, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.stage, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.stage, "index.json"), index, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(context.Background()); err == nil {
		t.Fatal("zero-object stage replacement bypassed generation identity")
	}
	if err := c.Abort(); err == nil {
		t.Fatal("cleanup deleted an unowned replacement staging directory")
	}
	for _, path := range []string{filepath.Join(c.stage, "index.json"), filepath.Join(moved, "index.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("unowned staging files were altered during rejection", err)
		}
	}
}

type hostileSpatialMutation struct {
	context.Context
	ready  func() bool
	mutate func() error
	fired  bool
	err    error
}

func (c *hostileSpatialMutation) Err() error {
	if !c.fired && c.ready() {
		c.fired = true
		c.err = c.mutate()
	}
	return c.Context.Err()
}

func TestSpatialCacheHostileRetainHashesBytesActuallyCopied(t *testing.T) {
	root, entry, files := hostileSpatialInputs(t)
	hostilePrimeSpatial(t, root, entry, files)
	c := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	source := files[entry.Leaf.Stream.SHA256]
	ctx := &hostileSpatialMutation{Context: context.Background(), ready: func() bool {
		if c.stage == "" {
			return false
		}
		_, err := os.Stat(filepath.Join(c.stage, "objects", spatialCacheFileName(entry.Leaf.Stream.SHA256)))
		return err == nil
	}, mutate: func() error {
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		data[0] ^= 1
		return os.WriteFile(source, data, 0600)
	}}
	if retained, err := c.Retain(ctx, entry, files); err == nil || retained || !ctx.fired || ctx.err != nil {
		t.Fatal("retention accepted source mutation during actual copy", retained, err, ctx.fired, ctx.err)
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	reopened := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	if _, hit, err := reopened.Lookup(context.Background(), entry.Domain, entry.Key); err != nil || !hit {
		t.Fatal("failed source copy damaged previous committed bytes", hit, err)
	}
}
