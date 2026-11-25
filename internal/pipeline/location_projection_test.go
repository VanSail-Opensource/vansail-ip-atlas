package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestLocationProjectionClockAndASNUsageWithdrawal(t *testing.T) {
	for _, mode := range []string{"normal", "damaged-location-cache"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			state, policy, _, _, _ := intelligenceFixture(t)
			at := state.EvaluatedAt.Add(time.Minute)
			// The ASN usage join contributes boundaries outside the geographic
			// tree and under an existing geographic parent. Both disappear at expiry.
			for _, prefix := range []string{"198.51.100.0/24", "203.0.116.0/24"} {
				state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: netip.MustParsePrefix(prefix), Origins: []uint32{13335}}})
			}
			state.Sources = append(state.Sources, intelligence.StoredSource{ID: "expiring-usage", Fingerprint: sha256.Sum256([]byte("usage")), ExpiresAt: at, Records: []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{ASN: 13335, ObservedAt: state.EvaluatedAt, Evidence: intelligence.UsageEvidence{Current: true, Family: "usage-side", Type: "hosting"}}}}})
			opt := testOptions(t)
			opt.Limits = DefaultLimits()
			opt.ValidUntil = at.Unix()
			before := partitionSpatialFixture(t, opt.Workspace, state)
			initial, err := BuildStreamedIntelligence(ctx, opt, before, policy)
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
			var used bool
			for _, entry := range index.Entries {
				if entry.Domain == "location" && entry.Leaf.Stream.Records > 0 {
					used = true
					if mode == "damaged-location-cache" {
						name := filepath.Join(cacheRoot, "objects", spatialCacheFileName(entry.Leaf.Stream.SHA256))
						b, err := os.ReadFile(name)
						if err != nil {
							t.Fatal(err)
						}
						b[len(b)-1] ^= 1
						if err = os.WriteFile(name, b, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if !used {
				t.Fatal("baseline failed to retain geographic changes")
			}
			changed := cloneSpatialFixture(t, state)
			changed.EvaluatedAt = at
			changed.Sources = changed.Sources[:len(changed.Sources)-1]
			opt.Clock, opt.ValidUntil = at.Unix(), changed.Sources[0].ExpiresAt.Unix()
			opt.Output = filepath.Join(opt.Workspace, "build-private", "later")
			warm, err := BuildStreamedIntelligence(ctx, opt, partitionSpatialFixture(t, opt.Workspace, changed), policy)
			if mode == "damaged-location-cache" {
				if err == nil {
					t.Fatal("changed-clock lookup failed to reauthenticate its geographic stream")
				}
				if _, err := os.Lstat(opt.Output); !os.IsNotExist(err) {
					t.Fatal("invalid cache produced an output")
				}
				return
			}
			if err != nil || warm.Pointer == initial.Pointer || warm.Stats.MaterializationCacheHits != 0 {
				t.Fatal("clock/usage transition not rebuilt", err)
			}
			cold := testOptions(t)
			cold.Clock, cold.ValidUntil, cold.Limits = opt.Clock, opt.ValidUntil, opt.Limits
			want, err := BuildStreamedIntelligence(ctx, cold, changed, policy)
			if err != nil || warm.Pointer != want.Pointer {
				t.Fatal("changed clock/withdrawal differs from independent uncached build", err)
			}
		})
	}
}

func TestLocationProjectionRetainsGeographicWorkingSetLimit(t *testing.T) {
	state, policy := mappingFixture(t)
	state.Sources = state.Sources[:1]
	source := &state.Sources[0]
	geo := source.Records[0]
	source.Records = make([]intelligence.NormalizedRecord, 8193)
	for i := range source.Records {
		source.Records[i] = geo
	}
	for _, projection := range []*locationProjection{nil, {hit: true}} {
		build := mappingProducer(state, policy, state.EvaluatedAt, nil, false, netip.Prefix{}, projection)
		err := build(context.Background(), func(via3.PublicRecord) error { return nil })
		if err == nil || err.Error() != "mapping boundary working set exceeded" {
			t.Fatalf("geographic ancestry bound lost during materialization: %v", err)
		}
	}
}

func TestLocationProjectionRejectsInvalidChanges(t *testing.T) {
	scope := netip.MustParsePrefix("203.0.0.0/16")
	child := netip.MustParsePrefix("203.0.113.0/24")
	geo := via3.PublicRecord{Version: 3, Kind: 2, Prefix: child, Geo: &via3.GeoData{Country: "US"}}
	coord := via3.PublicRecord{Version: 3, Kind: 3, Prefix: child, Coordinates: &via3.CoordinateData{Latitude: 12, Longitude: 14, Precision: 3}}
	outside := geo
	outside.Prefix = netip.MustParsePrefix("198.51.100.0/24")
	for _, tc := range []struct {
		name    string
		rows    []via3.PublicRecord
		current netip.Prefix
		changed bool
	}{
		{"foreign-kind", []via3.PublicRecord{{Version: 3, Kind: 5, Prefix: child, Usage: &via3.UsageData{}}}, child, true},
		{"foreign-scope", []via3.PublicRecord{outside}, child, true},
		{"duplicate-value", []via3.PublicRecord{geo, geo}, child, true},
		{"reversed-kinds", []via3.PublicRecord{coord, geo}, child, true},
		{"vanished-prefix", []via3.PublicRecord{geo}, netip.MustParsePrefix("203.0.114.0/24"), true},
		{"context-only-prefix", []via3.PublicRecord{geo}, child, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			for _, r := range tc.rows {
				row, err := encodeCompactRunRecord(r)
				if err != nil {
					t.Fatal(err)
				}
				if err = writeRunFrame(&buf, row); err != nil {
					t.Fatal(err)
				}
			}
			p := locationProjection{scope: scope, hit: true, rows: &runReader{reader: &buf, limit: DefaultLimits().RecordBytes, leafBodies: &leafPayloads{}}, entry: spatialCacheEntry{Leaf: &spatialCacheLeaf{Stream: spatialCacheStream{Records: uint64(len(tc.rows)), DecodedBytes: uint64(buf.Len())}}}}
			err := p.advance()
			if err == nil {
				_, err = p.resolve(tc.current, intelligence.Policy{}, nil, false, tc.changed, locationValue{coordinates: via3.CoordinateData{Unknown: true}})
			}
			if err == nil {
				t.Fatal("invalid cached location change accepted")
			}
		})
	}
}

func TestFullLeafHitCarriesGeographicProjectionAcrossGenerations(t *testing.T) {
	ctx := context.Background()
	state, policy := mappingFixture(t)
	original := intelligence.GeoEvidence{Family: state.Sources[0].ID, Weight: 100, Prefix: netip.MustParsePrefix("2001:db8::/32"), PhysicalCountry: "DE", Current: true}
	state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &original})
	opt := testOptions(t)
	opt.Limits = DefaultLimits()
	build := func(current intelligence.BuildState, dir string) map[[32]byte]bool {
		t.Helper()
		opt.Output = filepath.Join(opt.Workspace, "build-private", dir)
		if _, err := BuildStreamedIntelligence(ctx, opt, partitionSpatialFixture(t, opt.Workspace, current), policy); err != nil {
			t.Fatal(err)
		}
		var index spatialCacheIndex
		b, err := os.ReadFile(filepath.Join(opt.Workspace, ".atlas-private", "spatial-cache-v1", "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, &index); err != nil {
			t.Fatal(err)
		}
		keys := map[[32]byte]bool{}
		for _, entry := range index.Entries {
			if entry.Domain == "location" {
				keys[entry.Key] = true
			}
		}
		return keys
	}
	before := build(state, "both-families")
	original.PhysicalCountry = "NL"
	after := build(state, "changed-v6")
	if len(before) != 2 || len(after) != 2 {
		t.Fatalf("separate geographic projections were lost: %d then %d", len(before), len(after))
	}
	common := 0
	for key := range before {
		if after[key] {
			common++
		}
	}
	if common != 1 {
		t.Fatal("changing only the IPv6 records did not preserve exactly the IPv4 projection")
	}
}
