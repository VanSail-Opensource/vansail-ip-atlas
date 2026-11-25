package pipeline

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestLeafOriginContextsBindOnlyCompleteLocalMembership(t *testing.T) {
	origins := []uint32{3356, 13335}
	current := map[uint32]intelligence.ASNContext{3356: {Risk: .3, Confidence: .2, Contribution: .01, Present: true, Support: 1}}
	scope, err := newLeafOriginContexts(origins, current)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		if got, err := scope.matches(current); err != nil || got != want {
			t.Fatalf("matches=%v, want %v, err=%v", got, want, err)
		}
	}
	current[15169] = current[3356]
	check(true)
	current[13335] = current[3356]
	check(false)
	delete(current, 13335)
	original := current[3356]
	for _, change := range []func(*intelligence.ASNContext){
		func(v *intelligence.ASNContext) { v.Risk += .01 },
		func(v *intelligence.ASNContext) { v.Confidence += .01 },
		func(v *intelligence.ASNContext) { v.Contribution += .01 },
		func(v *intelligence.ASNContext) { v.Present = false },
		func(v *intelligence.ASNContext) { v.Support++ },
	} {
		v := original
		change(&v)
		current[3356] = v
		check(false)
	}
	delete(current, 3356)
	check(false)
	current[3356] = original
	check(true)
	if ok, err := (*leafOriginContexts)(nil).matches(current); err != nil || ok {
		t.Fatal("legacy unscoped leaf hit a scoped lookup", err)
	}
}

func TestLeafOriginContextIndexStrictShapeAndOwnership(t *testing.T) {
	scope, err := newLeafOriginContexts([]uint32{3356, 13335}, map[uint32]intelligence.ASNContext{})
	if err != nil {
		t.Fatal(err)
	}
	entry := spatialCacheEntry{Domain: "public", Key: [32]byte{1}, Leaf: &spatialCacheLeaf{OriginContexts: scope}}
	if _, err := spatialCacheFiles(entry); err != nil || entry.matchesIndexVersion(4) || !entry.matchesIndexVersion(5) {
		t.Fatal("origin descriptors require their reviewed index version", err)
	}
	clone := cloneSpatialEntry(entry)
	clone.Leaf.OriginContexts.ASNDeltas[0] ^= 1
	clone.Leaf.OriginContexts.Digest[0] ^= 1
	if slices.Equal(clone.Leaf.OriginContexts.ASNDeltas, scope.ASNDeltas) || clone.Leaf.OriginContexts.Digest == scope.Digest {
		t.Fatal("mutable cache descriptor aliases origin proof")
	}
	for _, encoded := range [][]byte{{0}, {0x81, 0}, {0x80}, binary.AppendUvarint(nil, 1<<32), binary.AppendUvarint(nil, 23456), {1, 0}} {
		bad := cloneSpatialEntry(entry)
		bad.Leaf.OriginContexts.ASNDeltas = encoded
		if _, err := spatialCacheFiles(bad); !errors.Is(err, errSpatialCache) {
			t.Fatal("accepted malformed, duplicated or reserved origin membership", err)
		}
	}
	for _, mutate := range []func(*spatialCacheEntry){
		func(e *spatialCacheEntry) { e.Domain = "risk" },
		func(e *spatialCacheEntry) { e.Domain = "location" },
		func(e *spatialCacheEntry) { e.Leaf.Split = true },
		func(e *spatialCacheEntry) { e.Leaf.OriginContexts.Digest = [32]byte{} },
	} {
		bad := cloneSpatialEntry(entry)
		mutate(&bad)
		if _, err := spatialCacheFiles(bad); !errors.Is(err, errSpatialCache) {
			t.Fatal("accepted inconsistent origin proof", err)
		}
	}
}

func TestLeafOriginContextsRejectDroppedMembershipInSignedIndex(t *testing.T) {
	root, entry, files := hostileSpatialInputs(t)
	scope, err := newLeafOriginContexts([]uint32{3356, 13335}, map[uint32]intelligence.ASNContext{})
	if err != nil {
		t.Fatal(err)
	}
	entry.Leaf.OriginContexts = scope
	hostilePrimeSpatial(t, root, entry, files)
	cache := hostileOpenSpatial(t, root, 1<<20, func(uint64) bool { return true })
	index, _, _, _, err := cache.readGeneration(t.Context(), cache.root)
	if err != nil {
		t.Fatal(err)
	}
	// Replacing both the set and its matching context digest cannot remove
	// a local dependency from the original authenticated generation.
	index.Entries[0].Leaf.OriginContexts, err = newLeafOriginContexts([]uint32{3356}, map[uint32]intelligence.ASNContext{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.root, "index.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := cache.readGeneration(t.Context(), cache.root); !errors.Is(err, errSpatialCache) {
		t.Fatal("changed membership reopened under previous MAC", err)
	}
}

func TestSpatialPublicLeavesReuseAcrossASNContextChanges(t *testing.T) {
	state, policy, _, _, _ := intelligenceFixture(t)
	state.Sources = state.Sources[:1]
	state.Sources[0].Records = nil
	for _, origin := range []intelligence.OriginMapping{
		{Prefix: netip.MustParsePrefix("8.0.0.0/8"), Origins: []uint32{3356, 13335}},
		{Prefix: netip.MustParsePrefix("2600::/16"), Origins: []uint32{15169}},
	} {
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &origin})
	}
	for i := byte(1); i <= 24; i++ {
		observation := intelligence.Evidence{Scope: intelligence.Exact, Address: netip.AddrFrom4([4]byte{8, 8, 8, i}), Weight: 100, Signal: "abuse", Family: "sample", SourcePublishedAt: state.EvaluatedAt, Current: true}
		state.Sources[0].Records = append(state.Sources[0].Records, intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &observation})
	}
	side := intelligence.StoredSource{ID: "asn-side", Fingerprint: [32]byte{22}, ExpiresAt: state.Sources[0].ExpiresAt,
		Records: []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Scope: intelligence.ASN, ASN: 3356, Weight: 100, Signal: "abuse", Family: "asn-side", Current: true, SourcePublishedAt: state.EvaluatedAt}}}}
	opts := testOptions(t)
	opts.Limits = DefaultLimits()
	var first, previous [2]spatialCacheEntry
	for step, name := range []string{"initial", "added", "withdrawn"} {
		if step == 1 {
			state.Sources = append(state.Sources, side)
		} else if step == 2 {
			state.Sources = state.Sources[:1]
		}
		opts.Output = filepath.Join(opts.Workspace, "build-private", name)
		warm, err := BuildStreamedIntelligence(t.Context(), opts, partitionSpatialFixture(t, opts.Workspace, state), policy)
		if err != nil {
			t.Fatal(err)
		}
		coldOpts := testOptions(t)
		coldOpts.Limits = DefaultLimits()
		cold, err := BuildStreamedIntelligence(t.Context(), coldOpts, state, policy)
		if err != nil || cold.Pointer != warm.Pointer {
			t.Fatal("warm release differs from uncached output", name, err)
		}
		data, err := os.ReadFile(filepath.Join(opts.Workspace, ".atlas-private", "spatial-cache-v1", "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		var index spatialCacheIndex
		if err := json.Unmarshal(data, &index); err != nil {
			t.Fatal(err)
		}
		var current [2]spatialCacheEntry
		for _, e := range index.Entries {
			if e.Domain != "public" || e.Leaf == nil || e.Leaf.OriginContexts == nil {
				continue
			}
			asns, err := e.Leaf.OriginContexts.origins()
			switch {
			case err != nil:
				t.Fatal(err)
			case slices.Equal(asns, []uint32{3356, 13335}):
				current[0] = e
			case slices.Equal(asns, []uint32{15169}):
				current[1] = e
			default:
				t.Fatal("collected leaf lost or invented local ASN membership", asns)
			}
		}
		if current[0].Leaf == nil || current[1].Leaf == nil {
			t.Fatal("missing distinct IPv4/IPv6 public stream")
		}
		if step == 0 {
			first = current
		} else {
			if current[0].Key != previous[0].Key || current[1].Key != previous[1].Key ||
				current[0].Leaf.Stream == previous[0].Leaf.Stream || current[0].Leaf.OriginContexts.Digest == previous[0].Leaf.OriginContexts.Digest ||
				current[1].Leaf.Stream != previous[1].Leaf.Stream || current[1].Leaf.OriginContexts.Digest != previous[1].Leaf.OriginContexts.Digest {
				t.Fatal("same-clock source change did not distinguish affected and unrelated origins", name)
			}
			if step == 2 && current[0].Leaf.Stream != first[0].Leaf.Stream {
				t.Fatal("withdrawal failed to restore original public rows")
			}
		}
		previous = current
	}
}
