package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func partitionSpatialFixture(t *testing.T, root string, state intelligence.BuildState) intelligence.BuildState {
	t.Helper()
	state.Sources = append([]intelligence.StoredSource(nil), state.Sources...)
	limits := intelligence.DefaultRecordStoreLimits()
	limits.PartitionRecords = 2
	store, err := intelligence.NewRecordStore(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	for i, source := range state.Sources {
		writer := store.Writer(context.Background())
		for _, record := range source.Records {
			if err := writer.Append(record); err != nil {
				t.Fatal(err)
			}
		}
		parts, err := writer.Finish()
		if err != nil {
			t.Fatal(err)
		}
		state.Sources[i].Records = nil
		state.Sources[i].RecordPartitions = parts
	}
	state.Version = 2
	return state
}

func cloneSpatialFixture(t *testing.T, state intelligence.BuildState) intelligence.BuildState {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var clone intelligence.BuildState
	if err = json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestSpatialReuseMixedChangesMatchColdMaterialization(t *testing.T) {
	for _, change := range []string{"city", "anycast", "global_usage", "relationship", "withdrawal"} {
		t.Run(change, func(t *testing.T) {
			state, policy, _, _, _ := intelligenceFixture(t)
			// Keep one independently removable side source. Its ASN usage is a
			// dependency of spatial results through the current origins join.
			state.Sources = append(state.Sources, intelligence.StoredSource{ID: "usage-side", Fingerprint: [32]byte{22}, ExpiresAt: state.Sources[0].ExpiresAt,
				Records: []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, ObservedAt: state.EvaluatedAt,
					Evidence: intelligence.UsageEvidence{Family: "usage-side", Type: "business", Current: true}}}}})
			options := testOptions(t)
			options.Limits = DefaultLimits()
			baseline := partitionSpatialFixture(t, options.Workspace, state)
			checks := 0
			options.InputGate = func(context.Context) error { checks++; return nil }
			first, err := BuildStreamedIntelligence(context.Background(), options, baseline, policy)
			if err != nil {
				t.Fatal(err)
			}
			if checks != 2 {
				t.Fatal("initial source gates did not run")
			}
			index := filepath.Join(options.Workspace, ".atlas-private", "spatial-cache-v1", "index.json")
			before, err := os.ReadFile(index)
			if err != nil {
				t.Fatal("spatial reuse generation was not retained", err)
			}
			options.Output = filepath.Join(options.Workspace, "build-private", "unchanged")
			again, err := BuildStreamedIntelligence(context.Background(), options, baseline, policy)
			if err != nil || again.Pointer != first.Pointer || again.Stats.MaterializationCacheHits != 1 {
				t.Fatal("unchanged result reuse failed", err)
			}
			after, err := os.ReadFile(index)
			if err != nil || string(before) != string(after) {
				t.Fatal("whole-result hit discarded spatial reuse generation", err)
			}
			changed := cloneSpatialFixture(t, state)
			switch change {
			case "city":
				for _, record := range changed.Sources[0].Records {
					if record.Geo != nil {
						record.Geo.City = "Changed city"
						record.Geo.PhysicalCountry = "AU"
						break
					}
				}
			case "anycast":
				for _, record := range changed.Sources[0].Records {
					if record.Usage != nil && record.Usage.Evidence.Anycast != nil {
						*record.Usage.Evidence.Anycast = false
						break
					}
				}
			case "global_usage":
				changed.Sources[len(changed.Sources)-1].Records[0].Usage.Evidence.Type = "hosting"
			case "relationship":
				for _, record := range changed.Sources[0].Records {
					if record.Relationship != nil {
						record.Relationship.Relation = intelligence.Customer
						break
					}
				}
			case "withdrawal":
				changed.Sources = changed.Sources[:len(changed.Sources)-1]
			}
			warmState := partitionSpatialFixture(t, options.Workspace, changed)
			if !reflect.DeepEqual(warmState.Sources[0].Fingerprint, baseline.Sources[0].Fingerprint) {
				t.Fatal("fixture must preserve source fingerprint across actual content change")
			}
			checks = 0
			options.Output = filepath.Join(options.Workspace, "build-private", "changed")
			warm, err := BuildStreamedIntelligence(context.Background(), options, warmState, policy)
			if err != nil || checks != 2 || warm.Stats.MaterializationCacheHits != 0 {
				t.Fatal("mixed reuse bypassed source gates or state identity", err)
			}
			coldOptions := testOptions(t)
			coldOptions.Limits = DefaultLimits()
			cold, err := BuildStreamedIntelligence(context.Background(), coldOptions, changed, policy)
			if err != nil || cold.Pointer != warm.Pointer {
				t.Fatalf("warm output differs from uncached inline build: warm=%s cold=%s error=%v", warm.Pointer.ReleaseID, cold.Pointer.ReleaseID, err)
			}
		})
	}
}

func TestSpatialReuseFailurePreservesPriorGenerationAndPublishesNothing(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	options := testOptions(t)
	options.Limits = DefaultLimits()
	baseline := partitionSpatialFixture(t, options.Workspace, state)
	if _, err := BuildStreamedIntelligence(context.Background(), options, baseline, policy); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(options.Workspace, ".atlas-private", "spatial-cache-v1", "index.json")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	changed := cloneSpatialFixture(t, state)
	for _, record := range changed.Sources[0].Records {
		if record.Geo != nil {
			record.Geo.PhysicalCountry = "AU"
			break
		}
	}
	changed = partitionSpatialFixture(t, options.Workspace, changed)
	checks := 0
	options.InputGate = func(context.Context) error {
		checks++
		if checks == 2 {
			return errors.New("input changed at final gate")
		}
		return nil
	}
	options.Output = filepath.Join(options.Workspace, "build-private", "failed")
	if _, err = BuildStreamedIntelligence(context.Background(), options, changed, policy); err == nil || checks != 2 {
		t.Fatal("final gate was bypassed", err)
	}
	if _, err := os.Lstat(options.Output); !os.IsNotExist(err) {
		t.Fatal("failed candidate was published", err)
	}
	after, err := os.ReadFile(index)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed build replaced authenticated prior cache", err)
	}
}

func TestSpatialSeedHitCannotSkipCompleteStrictSourceWalk(t *testing.T) {
	state, _, _, _, _ := intelligenceFixture(t)
	root := t.TempDir()
	if _, err := intelligence.NewRecordStore(root, intelligence.DefaultRecordStoreLimits()); err != nil {
		t.Fatal(err)
	}
	var valid []byte
	for _, record := range state.Sources[0].Records {
		if record.Geo != nil {
			valid, _ = json.Marshal(record)
			break
		}
	}
	if len(valid) == 0 {
		t.Fatal("fixture lacks geographic input")
	}
	invalid := append(append([]byte{}, valid[:len(valid)-1]...), []byte(",\"Unexpected\":true}")...)
	data := []byte("ATNR\x02\x03\x00\x00")
	for _, row := range [][]byte{valid, invalid} {
		data = binary.LittleEndian.AppendUint32(data, uint32(len(row)))
		data = append(data, row...)
	}
	part := intelligence.RecordPartition{SHA256: sha256.Sum256(data), Bytes: int64(len(data)), Records: 2}
	path := filepath.Join(root, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := spatialReuseKey("seed", part)
	if err != nil {
		t.Fatal(err)
	}
	// Even a correctly authenticated derived-cache entry is not permission to
	// skip the invalid second source frame after the first frame found a hit.
	hostilePrimeSpatial(t, root, spatialCacheEntry{Domain: "seed", Key: key, Seed: &spatialCacheSeed{}}, nil)
	cache := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	defer cache.Abort()
	spool, err := newBulkSpool(root, state.EvaluatedAt, state.PolicyHash, DefaultLimits().ScratchBytes, func() uint64 { return cache.DiskBytes() })
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(spool.root)
	spool.reuse = cache
	state.Sources = []intelligence.StoredSource{{ID: "strict-source", Fingerprint: [32]byte{1}, ExpiresAt: state.Sources[0].ExpiresAt, RecordPartitions: []intelligence.RecordPartition{part}}}
	state.Version = 2
	if _, _, err := spool.seedStable(context.Background(), root, state); err == nil {
		t.Fatal("a cache hit skipped strict validation of the rest of its source")
	}
}
