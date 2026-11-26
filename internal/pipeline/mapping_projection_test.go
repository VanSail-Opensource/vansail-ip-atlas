package pipeline

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestMappingProjectionScopesJoinedRolesAndKeepsNetworkIndependent(t *testing.T) {
	spool := bulkSpool{batchBytes: 1 << 20, batchRecords: 123, usage: asnUsageIndex{
		13335: []intelligence.UsageEvidence{{Family: "a", Current: true, Type: "hosting"}},
		15169: []intelligence.UsageEvidence{{Family: "b", Current: true, Type: "business"}},
	}}
	bucket := bulkBucket{prefix: netip.MustParsePrefix("203.0.113.0/24")}
	keys := func(asns ...uint32) [2][32]byte {
		t.Helper()
		result, err := spool.mappingKeys(&bucket, [32]byte{1}, asns)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	a, b, absent := keys(13335), keys(15169), keys()
	delete(spool.usage, 13335)
	if next := keys(13335); a[0] == next[0] || a[1] != next[1] {
		t.Fatal("role removal should invalidate its location projection only")
	}
	if keys(15169) != b || keys() != absent {
		t.Fatal("unrelated role removal invalidated the leaf")
	}
	unknown := keys(13335)
	delete(spool.usage, 15169)
	if next := keys(13335); unknown[0] == next[0] || unknown[1] != next[1] || keys() != absent {
		t.Fatal("role join disablement lost unknown-boundary dependency or invalidated network/empty leaves")
	}
}

func TestMappingProjectionReusesCurrentInputsWithoutFreezingRisk(t *testing.T) {
	for _, damage := range []bool{false, true} {
		name := "clock-advance"
		if damage {
			name = "corrupt-mapping-stream"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			state, policy, _, _, _ := intelligenceFixture(t)
			opt := testOptions(t)
			opt.Limits = DefaultLimits()
			partitioned := partitionSpatialFixture(t, opt.Workspace, state)
			first, err := BuildStreamedIntelligence(ctx, opt, partitioned, policy)
			if err != nil {
				t.Fatal(err)
			}
			cacheRoot := filepath.Join(opt.Workspace, ".atlas-private", "spatial-cache-v1")
			data, err := os.ReadFile(filepath.Join(cacheRoot, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			var index spatialCacheIndex
			if err = json.Unmarshal(data, &index); err != nil {
				t.Fatal(err)
			}
			var retained bool
			tampered := map[[32]byte]bool{}
			for _, e := range index.Entries {
				if e.Domain == "mapping" && e.Leaf.Stream.Records > 0 {
					retained = true
					if damage && !tampered[e.Leaf.Stream.SHA256] {
						tampered[e.Leaf.Stream.SHA256] = true
						path := filepath.Join(cacheRoot, "objects", spatialCacheFileName(e.Leaf.Stream.SHA256))
						payload, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						payload[len(payload)-1] ^= 1
						if err := os.WriteFile(path, payload, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if !retained {
				t.Fatal("baseline did not retain its validated mapping rows")
			}
			partitioned.EvaluatedAt = state.EvaluatedAt.Add(30 * time.Minute)
			warm := opt
			warm.Clock = partitioned.EvaluatedAt.Unix()
			warm.ValidUntil = state.Sources[0].ExpiresAt.Unix()
			warm.Output = filepath.Join(opt.Workspace, "build-private", "clock-advanced")
			got, err := BuildStreamedIntelligence(ctx, warm, partitioned, policy)
			if damage {
				if err == nil {
					t.Fatal("clock-advanced build accepted the changed mapping bytes")
				}
				if _, err := os.Lstat(warm.Output); !os.IsNotExist(err) {
					t.Fatal("invalid mapping stream produced an output")
				}
				return
			}
			if err != nil || first.Pointer == got.Pointer || got.Stats.MaterializationCacheHits != 0 {
				t.Fatal("clock-advanced output was not rebuilt", err)
			}
			cold := testOptions(t)
			cold.Clock, cold.ValidUntil, cold.Limits = warm.Clock, warm.ValidUntil, warm.Limits
			state.EvaluatedAt = partitioned.EvaluatedAt
			want, err := BuildStreamedIntelligence(ctx, cold, partitionSpatialFixture(t, cold.Workspace, state), policy)
			if err != nil || want.Pointer != got.Pointer {
				t.Fatal("reused mapping differs from a cold rebuild", err)
			}
			read := func(options Options) float64 {
				t.Helper()
				release, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
				if err != nil {
					t.Fatal(err)
				}
				answer, err := release.Lookup(ctx, "203.0.113.0")
				if err != nil || answer.Quality == nil || answer.Quality.Layers.Exact == nil {
					t.Fatal("fixture exact risk missing", err)
				}
				return *answer.Quality.Layers.Exact
			}
			if read(warm) >= read(opt) {
				t.Fatal("cached mapping froze an exact score across the build clock")
			}
		})
	}
}
