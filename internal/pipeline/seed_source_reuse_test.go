package pipeline

import (
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestSeedSourceReplayRequiresOriginalObjectsAndAllGroups(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	state, _, _, _, _ := intelligenceFixture(t)
	source := state.Sources[0]
	source.Records = nil
	var excluded intelligence.NormalizedRecord
	for _, input := range state.Sources {
		for _, r := range input.Records {
			if r.Kind == intelligence.RecordRelationship || r.Kind == intelligence.RecordUsage && r.Usage.ASN != 0 {
				excluded = r
			} else {
				source.Records = append(source.Records, r)
			}
		}
	}
	// A registered IPv6 name and a nested unnamed boundary each remain a
	// spatial record without introducing an ASN, a route, or a risk flag.
	for _, value := range []intelligence.NetworkNameRecord{
		{Prefix: netip.MustParsePrefix("2001:4860::/32"), Name: "TEST-NET", ModifiedAt: state.EvaluatedAt},
		{Prefix: netip.MustParsePrefix("2001:4860:1::/48")},
	} {
		source.Records = append(source.Records, intelligence.NormalizedRecord{
			Version: 3, Kind: intelligence.RecordNetworkName, NetworkName: &value,
		})
	}
	state.Sources = []intelligence.StoredSource{source}
	state = partitionSpatialFixture(t, root, state)
	source = state.Sources[0]
	newSpool := func() *bulkSpool {
		s, err := newBulkSpool(root, state.EvaluatedAt, state.PolicyHash, 1<<30, func() uint64 { return 0 })
		if err != nil {
			t.Fatal(err)
		}
		s.reuse, err = openSpatialCache(ctx, root, [32]byte{1}, 64<<20, func(uint64) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.reuse.Abort(); os.RemoveAll(s.root) })
		return s
	}
	cold := newSpool()
	roots, asns, err := cold.seedStable(ctx, root, state)
	if err != nil {
		t.Fatal(err)
	}
	expected := [6][]intelligence.RecordPartition{roots[0].parts, roots[1].parts, asns.parts, cold.coverage, cold.pathParts, cold.prefixParts}
	key, err := spatialReuseKey(seedSourceDomain, source.RecordPartitions)
	if err != nil {
		t.Fatal(err)
	}
	entry, hit, err := cold.reuse.Lookup(ctx, seedSourceDomain, key)
	if err != nil || !hit || !entry.SeedSource.Exact || !entry.SeedSource.DirectASN || len(entry.SeedSource.ASNs) < 2 {
		t.Fatal("source effects did not cover the fixture", err)
	}
	if err := cold.reuse.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cold.reuse.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	warm := newSpool()
	warm.riskParts = map[[32]byte]bool{}
	if err := warm.refresh(); err != nil {
		t.Fatal(err)
	}
	var categories [6][]intelligence.RecordPartition
	part := source.RecordPartitions[len(source.RecordPartitions)-1]
	groupKey, err := spatialReuseKey("seed", part)
	if err != nil {
		t.Fatal(err)
	}
	groupID := spatialCacheEntryKey{"seed", groupKey}
	group := warm.reuse.current[groupID]
	delete(warm.reuse.current, groupID)
	if hit, err := warm.replaySeedSource(ctx, root, source, key, &categories); hit || err != nil || len(warm.known) != 0 || len(categories[0]) != 0 {
		t.Fatal("partial source replay mutated global or category data", err)
	}
	warm.reuse.current[groupID] = group
	path := filepath.Join(root, ".atlas-private", "records-v2", hex.EncodeToString(part.SHA256[:])+".records")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[len(changed)-1] ^= 1
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if hit, err := warm.replaySeedSource(ctx, root, source, key, &categories); hit || err == nil {
		t.Fatal("source summary hid altered normalized bytes")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	hit, err = warm.replaySeedSource(ctx, root, source, key, &categories)
	if err != nil || !hit || !reflect.DeepEqual(expected, categories) || !reflect.DeepEqual(cold.known, warm.known) || !reflect.DeepEqual(cold.riskParts, warm.riskParts) || !warm.hasExact || !warm.hasASNDirect {
		t.Fatal("verified source replay changed category bytes or global state", err)
	}

	cap := seedSourceCapture{eligible: true}
	cap.observe(excluded)
	if cap.eligible {
		t.Fatal("mixed role or relationship source acquired a replay summary")
	}
}

func TestSeedSourceSummarySchemaAndOwnership(t *testing.T) {
	valid := spatialCacheEntry{Domain: seedSourceDomain, Key: [32]byte{1}, SeedSource: &seedSourceSummary{ASNs: []uint32{13335, 15169}, Risk: []byte{1, 2, 0}}}
	if _, err := spatialCacheFiles(valid); err != nil || valid.matchesIndexVersion(3) || !valid.matchesIndexVersion(4) {
		t.Fatal("versioned source summary schema", err)
	}
	cloned := cloneSpatialEntry(valid)
	cloned.SeedSource.Risk[0] = 3
	cloned.SeedSource.ASNs[0] = 1
	if valid.SeedSource.Risk[0] != 1 || valid.SeedSource.ASNs[0] != 13335 {
		t.Fatal("cloned source summary retained mutable aliases")
	}
	for _, summary := range []seedSourceSummary{
		{}, {Risk: []byte{4}}, {Risk: make([]byte, spatialCacheInputPartitions+1)},
		{Risk: []byte{0}, ASNs: []uint32{23456}}, {Risk: []byte{0}, ASNs: []uint32{15169, 13335}},
		{Risk: []byte{0}, ASNs: []uint32{13335, 13335}},
	} {
		entry := valid
		entry.SeedSource = &summary
		if _, err := spatialCacheFiles(entry); err == nil {
			t.Fatal("accepted invalid source summary")
		}
	}
	entry := valid
	entry.Domain = "public"
	if _, err := spatialCacheFiles(entry); err == nil {
		t.Fatal("accepted source summary for another cached operation")
	}
}
