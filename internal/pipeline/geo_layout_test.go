package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestGeoLayoutReplaysExactBoundaryCountsAfterRoleExpiry(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources = state.Sources[:1]
	origin := netip.MustParsePrefix("11.0.0.0/16")
	state.Sources[0].Records = []intelligence.NormalizedRecord{
		{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: origin, Origins: []uint32{13335}}},
		{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Address: netip.MustParseAddr("11.0.0.1"), Scope: intelligence.Exact, Signal: "abuse", Weight: 75, Family: "runtime", Current: true, SourcePublishedAt: state.EvaluatedAt}},
	}
	for i := 0; i < 1650; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, byte(i >> 8), byte(i)}), 32)
		geo := &intelligence.GeoEvidence{Prefix: prefix, Family: "data", PhysicalCountry: "US", City: fmt.Sprintf("City %d", i%37), Region: "Fixture Region", Weight: 100, Current: true}
		row := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: geo}
		state.Sources[0].Records = append(state.Sources[0].Records, row)
		if i%8 == 0 {
			state.Sources[0].Records = append(state.Sources[0].Records, row)
		}
	}
	role := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, ObservedAt: state.EvaluatedAt, Evidence: intelligence.UsageEvidence{Family: "roles", Type: "hosting", Current: true}}}
	state.Sources = append(state.Sources, intelligence.StoredSource{ID: "roles", ExpiresAt: state.EvaluatedAt.Add(30 * time.Minute), Fingerprint: [32]byte{51}, Records: []intelligence.NormalizedRecord{role}})
	ctx := context.Background()
	store := func(t *testing.T, opts Options, raw intelligence.BuildState) intelligence.BuildState {
		t.Helper()
		raw.Version = 2
		raw.Sources = append([]intelligence.StoredSource(nil), raw.Sources...)
		s, err := intelligence.NewRecordStore(opts.Workspace, intelligence.DefaultRecordStoreLimits())
		if err != nil {
			t.Fatal(err)
		}
		for n, source := range raw.Sources {
			w := s.Writer(ctx)
			for _, row := range source.Records {
				if err = w.Append(row); err != nil {
					t.Fatal(err)
				}
			}
			parts, err := w.Finish()
			if err != nil {
				t.Fatal(err)
			}
			raw.Sources[n].Records, raw.Sources[n].RecordPartitions = nil, parts
		}
		return raw
	}
	for _, damage := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt=%t", damage), func(t *testing.T) {
			opt := testOptions(t)
			opt.Limits = DefaultLimits()
			opt.ValidUntil = state.Sources[1].ExpiresAt.Unix()
			partitioned := store(t, opt, state)
			if _, err := BuildStreamedIntelligence(ctx, opt, partitioned, policy); err != nil {
				t.Fatal(err)
			}
			cacheRoot := filepath.Join(opt.Workspace, ".atlas-private", "spatial-cache-v1")
			data, err := os.ReadFile(filepath.Join(cacheRoot, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			var index spatialCacheIndex
			if err := json.Unmarshal(data, &index); err != nil {
				t.Fatal(err)
			}
			var described bool
			for _, e := range index.Entries {
				if e.Domain != geoLayoutDomain {
					continue
				}
				g := e.Leaf.GeoLayout
				if g.GeoRecords != 1650 || g.OtherRecords != 2 || g.Boundaries != 1650 {
					t.Fatalf("layout didn't preserve raw dedupe and retained record counts: %+v", g)
				}
				described = true
				if damage {
					path := filepath.Join(cacheRoot, "objects", spatialCacheFileName(e.Leaf.Stream.SHA256))
					contents, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					contents[len(contents)-1] ^= 1
					if err := os.WriteFile(path, contents, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if !described {
				t.Fatal("mixed leaf did not retain a geographic layout")
			}
			partitioned.Sources = partitioned.Sources[:1]
			partitioned.EvaluatedAt = state.Sources[1].ExpiresAt
			warm := opt
			warm.Clock, warm.ValidUntil = partitioned.EvaluatedAt.Unix(), partitioned.Sources[0].ExpiresAt.Unix()
			warm.Output = filepath.Join(opt.Workspace, "build-private", "new-clock")
			got, err := BuildStreamedIntelligence(ctx, warm, partitioned, policy)
			if damage {
				if err == nil {
					t.Fatal("replayed a damaged proof")
				}
				if _, err := os.Lstat(warm.Output); !os.IsNotExist(err) {
					t.Fatal("failed proof wrote output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cold := testOptions(t)
			cold.Clock, cold.ValidUntil, cold.Limits = warm.Clock, warm.ValidUntil, warm.Limits
			current := state
			current.Sources, current.EvaluatedAt = state.Sources[:1], partitioned.EvaluatedAt
			want, err := BuildStreamedIntelligence(ctx, cold, store(t, cold, current), policy)
			if err != nil || got.Pointer != want.Pointer {
				t.Fatal("replay and ordinary materialization produced different bytes", err)
			}
			lookup, err := via3.OpenRelease(warm.Output, func() int64 { return warm.Clock })
			if err != nil {
				t.Fatal(err)
			}
			answer, err := lookup.Lookup(ctx, "11.0.0.1")
			if err != nil || answer.Geo == nil || answer.Quality == nil || answer.Quality.Layers.Exact == nil || answer.Usage != nil && answer.Usage.Type != "unknown" {
				t.Fatal("projected geography, score or withdrawn role differs", answer, err)
			}
		})
	}
}
