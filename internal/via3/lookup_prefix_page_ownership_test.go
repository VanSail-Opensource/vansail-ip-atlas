package via3

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func prefixPageOwnershipFixture(t *testing.T) (*Release, []string, *int64) {
	t.Helper()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("8.8.8.0/24"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db88:abcd:ffff:ffff:ffff:ffff:ffff/128"),
		netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
	}
	for i := byte(1); i <= 124; i++ {
		prefixes = append(prefixes,
			netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 8, 0, i}), 32),
			netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 0, 1, 15: i}), 128))
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	want := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		want[i] = prefix.String()
	}
	if len(want) != 256 || len(want[len(want)-1]) != 43 {
		t.Fatal("fixture must exercise a full page and maximum-length IPv6 text")
	}
	input := CompileInput{
		Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600,
		Partitions: []PartitionInput{{Partition: "all", ASNRoutes: []uint32{13335}, Records: []PublicRecord{
			{Version: 3, Kind: 8, ASN: 13335, ASNAggregate: &ASNData{Prefixes: prefixes}},
		}}},
	}
	built, err := Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	objects := make(map[string][]byte, len(built.Objects))
	for _, object := range built.Objects {
		objects[object.Info.SHA256] = object.Bytes
	}
	now := input.Clock
	reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) {
		data, ok := objects[hash]
		if !ok {
			return nil, fail("missing_object")
		}
		return data, nil
	}, func() int64 { return now })
	if err != nil {
		t.Fatal(err)
	}
	return reader, want, &now
}

func TestPrefixPageOwnsMixedFamilyStringsAcrossQueriesAndEviction(t *testing.T) {
	reader, want, _ := prefixPageOwnershipFixture(t)
	first, err := reader.Prefixes(context.Background(), "AS13335", 0)
	if err != nil || first.ASN != 13335 || first.NextCursor != nil || !slices.Equal(first.Prefixes, want) {
		t.Fatalf("full mixed-family page differs: %v", err)
	}
	second, err := reader.Prefixes(context.Background(), "AS13335", 0)
	if err != nil || !slices.Equal(second.Prefixes, want) {
		t.Fatalf("repeated page differs: %v", err)
	}
	answer, err := reader.Lookup(context.Background(), "AS13335")
	if err != nil || len(answer.ASNs) != 1 || !slices.Equal(answer.ASNs[0].Prefixes, want) {
		t.Fatalf("lookup first page differs: %v", err)
	}
	// Strings may share immutable bytes, but every mutable slice element/header
	// belongs to its own returned answer, including the Lookup first-page view.
	first.Prefixes[0] = "caller mutation"
	first.Prefixes[len(first.Prefixes)-1] = "another mutation"
	first.Prefixes = append(first.Prefixes, "appended value")
	answer.ASNs[0].Prefixes[1] = "lookup mutation"
	if !slices.Equal(second.Prefixes, want) {
		t.Fatal("a caller-owned prefix slice or string header changed another answer")
	}
	// Drop every cache pin and overwrite the formerly decoded page payloads.
	// A retained answer must own its strings independently of these shard bytes.
	pages := 0
	for _, reference := range reader.references {
		shard := reference.shard
		if shard != nil && shard.Kind == 8 && len(shard.RowsMust(11)) != 0 {
			reader.evictReference(reference)
			if reference.shard != nil {
				t.Fatal("completed query unexpectedly pinned an evicted prefix page")
			}
			for i := range shard.Sections {
				clear(shard.Sections[i].Data)
			}
			pages++
		} else {
			reader.evictReference(reference)
		}
	}
	if pages != 1 || !slices.Equal(second.Prefixes, want) {
		t.Fatal("retained page strings depend on an evicted decoded object")
	}
	third, err := reader.Prefixes(context.Background(), "AS13335", 0)
	if err != nil || !slices.Equal(third.Prefixes, want) {
		t.Fatalf("mutations or eviction changed a subsequent page: %v", err)
	}
	third.Prefixes[2] = "third answer mutation"
	if !slices.Equal(second.Prefixes, want) {
		t.Fatal("reloaded page shares mutable answer headers")
	}
}

func TestPrefixPagePackingPreservesExpiryAndCancellation(t *testing.T) {
	reader, want, now := prefixPageOwnershipFixture(t)
	if page, err := reader.Prefixes(context.Background(), "AS13335", 0); err != nil || !slices.Equal(page.Prefixes, want) {
		t.Fatalf("warm prefix page: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.Prefixes(ctx, "AS13335", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached page ignored cancellation: %v", err)
	}
	if _, err := reader.Lookup(ctx, "AS13335"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached first-page lookup ignored cancellation: %v", err)
	}
	if _, err := reader.Prefixes(context.Background(), "AS13335", 1); ErrorCode(err) != "invalid_cursor" {
		t.Fatalf("full page fabricated another page: %v", err)
	}
	*now = reader.Manifest.ValidUntil
	if _, err := reader.Prefixes(context.Background(), "AS13335", 0); ErrorCode(err) != "expired" {
		t.Fatalf("cached page ignored release expiry: %v", err)
	}
	if _, err := reader.Lookup(context.Background(), "AS13335"); ErrorCode(err) != "expired" {
		t.Fatalf("cached first-page lookup ignored release expiry: %v", err)
	}
	if len(reader.usedReferences) != 0 || reader.activeBytes != 0 {
		t.Fatal("failed page query retained active decoded pins")
	}
}

func prefixMetadataPageFixture(t *testing.T, count int) Shard {
	t.Helper()
	rows := make([][]byte, count)
	for i := range rows {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}), 32)
		rows[i] = make([]byte, 24)
		copy(rows[i], PrefixKey(prefix, false, 0)[:20])
	}
	shard := newShard(8)
	shard.set(11, Vector(24, rows...))
	if err := Validate(shard); err != nil {
		t.Fatal(err)
	}
	shard.lookup = shardLookupMetadata(&shard, nil)
	return shard
}

func TestPrefixMetadataChargesActualBytesAndReleasesWithOwner(t *testing.T) {
	shard := prefixMetadataPageFixture(t, 256)
	base := decodedSize(&shard)
	r := &Release{}
	ref := &objectReference{}
	if err := r.admitReference(ref, base); err != nil {
		t.Fatal(err)
	}
	r.preparePrefixLabels(ref, &shard)
	ref.shard = &shard
	used := len(shard.lookup.prefixLabels) * 16
	for _, label := range shard.lookup.prefixLabels {
		used += len(label)
	}
	if len(shard.lookup.prefixLabels) != 256 || used >= 256*(16+43) || ref.prefixLabelBytes != used || ref.size != base+used || r.residentBytes != base+used || r.activeBytes != base+used || r.cacheBytes != 0 {
		t.Fatal("metadata reservation was not trimmed to its actual bounded allocation")
	}
	r.cacheReference(ref)
	assertSlotAccounting(t, r, []*objectReference{ref})
	if r.cacheBytes != base+used || r.cacheBytes > PublicCacheDecoded || r.residentBytes > PublicLiveDecoded {
		t.Fatal("metadata escaped cache/live accounting")
	}
	r.endQuery()
	assertSlotAccounting(t, r, []*objectReference{ref})
	if r.activeBytes != 0 || r.cacheBytes != base+used {
		t.Fatal("query completion changed cache ownership")
	}
	r.evictReference(ref)
	assertSlotAccounting(t, r, []*objectReference{ref})
	if ref.shard != nil || ref.prefixLabelBytes != 0 || ref.size != 0 || r.residentBytes != 0 {
		t.Fatal("eviction retained prefix metadata or its charge")
	}
}

func TestPrefixMetadataEligibilityAndObjectBudgetFallback(t *testing.T) {
	for _, mode := range []string{"empty", "oversized-page", "wrong-kind", "missing-index", "near-object-limit", "already-cached"} {
		t.Run(mode, func(t *testing.T) {
			count := 1
			if mode == "empty" {
				count = 0
			} else if mode == "oversized-page" {
				count = 257
			}
			shard := prefixMetadataPageFixture(t, count)
			if mode == "wrong-kind" {
				shard = newShard(5)
				if err := Validate(shard); err != nil {
					t.Fatal(err)
				}
				shard.lookup = shardLookupMetadata(&shard, nil)
			} else if mode == "missing-index" {
				shard.lookup = nil
			}
			base := decodedSize(&shard)
			if mode == "near-object-limit" {
				// Declared-size accounting fixture; no 32MiB allocation is needed.
				base = PublicObjectDecoded - 58
			}
			r := &Release{}
			ref := &objectReference{shard: &shard}
			if err := r.admitReference(ref, base); err != nil {
				t.Fatal(err)
			}
			if mode == "already-cached" {
				r.cacheReference(ref)
			}
			cacheBefore := r.cacheBytes
			r.preparePrefixLabels(ref, &shard)
			if shard.lookup != nil && shard.lookup.prefixLabels != nil || ref.prefixLabelBytes != 0 || ref.size != base || r.residentBytes != base || r.activeBytes != base || r.cacheBytes != cacheBefore {
				t.Fatal("ineligible metadata was installed or charged")
			}
			assertSlotAccounting(t, r, []*objectReference{ref})
		})
	}
}

func TestPrefixMetadataFullLiveArenaKeepsPublicPageExact(t *testing.T) {
	r, want, _ := prefixPageOwnershipFixture(t)
	var pageHash string
	for hash, ref := range r.references {
		if ref.info.Kind != 8 {
			continue
		}
		data, err := r.load(hash)
		if err != nil {
			t.Fatal(err)
		}
		shard, err := Read(context.Background(), data)
		if err != nil {
			t.Fatal(err)
		}
		if len(shard.RowsMust(11)) != 0 {
			pageHash = hash
		}
	}
	if pageHash == "" {
		t.Fatal("fixture lacks a prefix page")
	}
	load := r.load
	injected := false
	r.load = func(hash string) ([]byte, error) {
		data, err := load(hash)
		if err != nil || hash != pageHash || injected {
			return data, err
		}
		injected = true
		// Fill the live arena with bounded declared-size query pins, leaving
		// exactly enough room for the required page payload and no metadata.
		remaining := PublicLiveDecoded - r.residentBytes - int(u64(data, 36))
		for remaining > 0 {
			size := min(remaining, PublicObjectDecoded)
			placeholder := &objectReference{shard: &Shard{}}
			if err := r.admitReference(placeholder, size); err != nil {
				return nil, err
			}
			remaining -= size
		}
		return data, nil
	}
	page, err := r.Prefixes(context.Background(), "AS13335", 0)
	ref := r.references[pageHash]
	if err != nil || !slices.Equal(page.Prefixes, want) || !injected || ref.shard == nil || ref.shard.lookup.prefixLabels != nil || ref.prefixLabelBytes != 0 {
		t.Fatalf("full arena failed exact public formatting fallback: %v", err)
	}
	if r.activeBytes != 0 || len(r.usedReferences) != 0 || r.residentBytes > PublicLiveDecoded || r.cacheBytes > PublicCacheDecoded {
		t.Fatal("fallback leaked query pins or exceeded cache/live limits")
	}
	r.evictReference(ref)
	page, err = r.Prefixes(context.Background(), "AS13335", 0)
	if err != nil || !slices.Equal(page.Prefixes, want) || ref.shard == nil || len(ref.shard.lookup.prefixLabels) != 256 || ref.prefixLabelBytes == 0 {
		t.Fatalf("evicted fallback page did not rebuild optional metadata: %v", err)
	}
}

func TestPrefixMetadataReclaimedBeforeRejectingRequiredPayload(t *testing.T) {
	shard := prefixMetadataPageFixture(t, 256)
	base := decodedSize(&shard)
	r := &Release{}
	page := &objectReference{}
	if err := r.admitReference(page, base); err != nil {
		t.Fatal(err)
	}
	r.preparePrefixLabels(page, &shard)
	page.shard = &shard
	retained := append([]string(nil), shard.lookup.prefixLabels...)
	if len(retained) != 256 || page.prefixLabelBytes == 0 {
		t.Fatal("fixture lacks pinned metadata")
	}
	r.cacheReference(page)
	references := []*objectReference{page}
	// Leave one whole object free in the payload-only accounting. Optional
	// metadata alone must not turn that otherwise valid object into a failure.
	remaining := PublicLiveDecoded - PublicObjectDecoded - base
	for remaining > 0 {
		size := min(remaining, PublicObjectDecoded)
		ref := &objectReference{shard: &Shard{}}
		if err := r.admitReference(ref, size); err != nil {
			t.Fatal(err)
		}
		references = append(references, ref)
		remaining -= size
	}
	extra := &objectReference{shard: &Shard{}}
	if err := r.admitReference(extra, PublicObjectDecoded); err != nil {
		t.Fatalf("optional prefix metadata blocked a valid required payload: %v", err)
	}
	references = append(references, extra)
	assertSlotAccounting(t, r, references)
	if page.prefixLabelBytes != 0 || shard.lookup.prefixLabels != nil || page.size != base || r.residentBytes != PublicLiveDecoded || r.activeBytes != PublicLiveDecoded {
		t.Fatal("metadata reclamation did not preserve exact payload accounting")
	}
	for i, value := range retained {
		want := netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}), 32).String()
		if value != want {
			t.Fatal("reclamation changed an already returned immutable string")
		}
	}
	r.endQuery()
	assertSlotAccounting(t, r, references)
	if r.residentBytes != 0 {
		t.Fatal("reclaimed query retained a payload or metadata charge")
	}
}
