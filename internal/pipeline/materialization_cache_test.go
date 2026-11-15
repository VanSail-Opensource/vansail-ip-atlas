package pipeline

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestMaterializationCacheReusesExactStateAndRunsBothGates(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	options := testOptions(t)
	options.Limits = DefaultLimits()
	checks := 0
	options.InputGate = func(context.Context) error { checks++; return nil }
	first, err := BuildStreamedIntelligence(context.Background(), options, state, policy)
	if err != nil {
		t.Fatal(err)
	}
	if first.Stats.MaterializationCacheHits != 0 || checks != 2 {
		t.Fatal("initial materialization skipped work or input checks")
	}
	options.Output = filepath.Join(options.Workspace, "build-private", "same-inputs")
	checks = 0
	second, err := BuildStreamedIntelligence(context.Background(), options, state, policy)
	if err != nil {
		t.Fatal(err)
	}
	if second.Stats.MaterializationCacheHits != 1 || checks != 2 || first.Pointer != second.Pointer || second.Stats.SortRuns != 0 {
		t.Fatal("exact cache hit did not preserve output and validation")
	}
	if second.Stats.ScratchPeak == 0 || second.Stats.OutputBytes == 0 || !second.Stats.ProcessRSSMeasured {
		t.Fatal("cache reuse omitted resource accounting")
	}
}

func TestMaterializationCacheSemanticChangesMiss(t *testing.T) {
	for _, change := range []string{"state", "record", "withdrawal", "policy", "clock", "deadline", "limits", "mode"} {
		t.Run(change, func(t *testing.T) {
			state, policy, _, _, _ := intelligenceFixture(t)
			options := testOptions(t)
			options.Limits = DefaultLimits()
			if _, err := BuildStreamedIntelligence(context.Background(), options, state, policy); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "state":
				state.PolicyHash[0] ^= 1
			case "record":
				geo := *state.Sources[0].Records[0].Geo
				geo.City = "Changed Synthetic City"
				state.Sources[0].Records[0].Geo = &geo
			case "withdrawal":
				state.Sources = state.Sources[1:]
			case "policy":
				policy.GeoMargin += 0.01
			case "clock":
				options.Clock++
				state.EvaluatedAt = state.EvaluatedAt.Add(time.Second)
			case "deadline":
				options.ValidUntil--
			case "limits":
				options.Limits.SortBytes /= 2
			case "mode":
				options.Mode = "engineering"
			}
			options.Output = filepath.Join(options.Workspace, "build-private", "changed")
			var result Candidate
			var err error
			if change == "mode" {
				result, err = BuildEngineeringBenchmark(context.Background(), options, state, state, policy, ProductionInputs{})
			} else {
				result, err = BuildStreamedIntelligence(context.Background(), options, state, policy)
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Stats.MaterializationCacheHits != 0 || result.Stats.SortRuns == 0 {
				t.Fatal("changed semantic input reused prior materialization")
			}
		})
	}
}

func TestMaterializationCacheRejectsTamperingAndUnsafeFiles(t *testing.T) {
	for _, change := range []string{"index", "mac", "empty", "object", "object-symlink", "key-symlink"} {
		t.Run(change, func(t *testing.T) {
			state, policy, _, _, _ := intelligenceFixture(t)
			options := testOptions(t)
			options.Limits = DefaultLimits()
			first, err := BuildStreamedIntelligence(context.Background(), options, state, policy)
			if err != nil {
				t.Fatal(err)
			}
			cache := filepath.Join(options.Workspace, ".atlas-private", "materialization-cache-v1")
			switch change {
			case "index":
				if err := os.WriteFile(filepath.Join(cache, "index.json"), []byte(`{"Version":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "mac", "empty":
				indexPath := filepath.Join(cache, "index.json")
				data, err := os.ReadFile(indexPath)
				var index materializationCacheIndex
				if err != nil || json.Unmarshal(data, &index) != nil {
					t.Fatal("cache fixture unavailable")
				}
				if change == "mac" {
					index.Identity[0] ^= 1
				} else {
					index.Descriptor.Objects = nil
					key, err := os.ReadFile(filepath.Join(options.Workspace, ".atlas-private", "materialization-cache-v1.key"))
					if err != nil {
						t.Fatal(err)
					}
					index.MAC = cacheMAC([32]byte(key), index)
				}
				data, err = json.Marshal(index)
				if err != nil || os.WriteFile(indexPath, data, 0600) != nil {
					t.Fatal("cache fixture mutation failed")
				}
			case "object":
				path := filepath.Join(cache, "objects", first.Manifest.Objects[0].SHA256+".via3")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "object-symlink", "key-symlink":
				path := filepath.Join(cache, "objects", first.Manifest.Objects[0].SHA256+".via3")
				if change == "key-symlink" {
					path = filepath.Join(options.Workspace, ".atlas-private", "materialization-cache-v1.key")
				}
				target := filepath.Join(options.Workspace, "unrelated-private-file")
				if err := os.WriteFile(target, []byte("synthetic-private-value"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skip(err)
				}
			}
			options.Output = filepath.Join(options.Workspace, "build-private", "rejected")
			if _, err = BuildStreamedIntelligence(context.Background(), options, state, policy); err == nil {
				t.Fatal("tampered materialization cache accepted")
			}
			if _, err = os.Lstat(options.Output); !os.IsNotExist(err) {
				t.Fatal("cache failure published output")
			}
		})
	}
}

func TestMaterializationCacheRechecksLocalPartitionBytesAtBothBoundaries(t *testing.T) {
	for _, changeAtEnd := range []bool{false, true} {
		state, policy, _, _, _ := intelligenceFixture(t)
		options := testOptions(t)
		options.Limits = DefaultLimits()
		store, err := intelligence.NewRecordStore(options.Workspace, intelligence.DefaultRecordStoreLimits())
		if err != nil {
			t.Fatal(err)
		}
		state.Version = 2
		for i := range state.Sources {
			writer := store.Writer(context.Background())
			for _, record := range state.Sources[i].Records {
				if err := writer.Append(record); err != nil {
					t.Fatal(err)
				}
			}
			parts, err := writer.Finish()
			if err != nil {
				t.Fatal(err)
			}
			state.Sources[i].RecordPartitions = parts
			state.Sources[i].Records = nil
		}
		if _, err := BuildStreamedIntelligence(context.Background(), options, state, policy); err != nil {
			t.Fatal(err)
		}
		part := state.Sources[0].RecordPartitions[0]
		path := filepath.Join(options.Workspace, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
		mutate := func() {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)-1] ^= 1
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		checks := 0
		options.InputGate = func(context.Context) error {
			checks++
			if changeAtEnd && checks == 2 {
				mutate()
			}
			return nil
		}
		if !changeAtEnd {
			mutate()
		}
		options.Output = filepath.Join(options.Workspace, "build-private", "local-chunk-corrupt")
		if _, err := BuildStreamedIntelligence(context.Background(), options, state, policy); err == nil {
			t.Fatal("same descriptor hid mutated local normalized bytes")
		}
		if _, err := os.Lstat(options.Output); !os.IsNotExist(err) {
			t.Fatal("corrupt local input published cached output")
		}
	}
}

func TestMaterializationCachePreservesIndependentProductionGate(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	options := testOptions(t)
	options.Limits = DefaultLimits()
	options.Mode = "production"
	inputChecks, productionChecks := 0, 0
	options.InputGate = func(context.Context) error { inputChecks++; return nil }
	options.ProductionGate = func(context.Context) error { productionChecks++; return nil }
	var err error
	options.materializationCache, err = openMaterializationCache(context.Background(), options, state, policy, ProductionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Build(context.Background(), options, producer(fusedFixture())); err != nil {
		t.Fatal(err)
	}
	options.Output = filepath.Join(options.Workspace, "build-private", "cached-production")
	options.materializationCache, err = openMaterializationCache(context.Background(), options, state, policy, ProductionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	inputChecks, productionChecks = 0, 0
	result, err := Build(context.Background(), options, producer(nil))
	if err != nil || result.Stats.MaterializationCacheHits != 1 || inputChecks != 2 || productionChecks != 2 {
		t.Fatal("cache bypassed independent production/input gates", err)
	}
}

func TestMaterializationCacheCannotBypassInputWithdrawalOrCancellation(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		state, policy, _, _, _ := intelligenceFixture(t)
		options := testOptions(t)
		options.Limits = DefaultLimits()
		if _, err := BuildStreamedIntelligence(context.Background(), options, state, policy); err != nil {
			t.Fatal(err)
		}
		checks := 0
		options.InputGate = func(context.Context) error {
			checks++
			if checks == failAt {
				return errors.New("synthetic withdrawal")
			}
			return nil
		}
		options.Output = filepath.Join(options.Workspace, "build-private", "withdrawn")
		if _, err := BuildStreamedIntelligence(context.Background(), options, state, policy); err == nil || checks != failAt {
			t.Fatal("cache bypassed input gate")
		}
		if _, err := os.Lstat(options.Output); !os.IsNotExist(err) {
			t.Fatal("withdrawn input published cached output")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := BuildStreamedIntelligence(ctx, options, state, policy); err == nil {
			t.Fatal("cache ignored cancellation")
		}
	}
}
