package pipeline

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

func TestStreamedOneASNMoreThanTwoHundredThousandPrefixes(t *testing.T) {
	ctx := context.Background()
	options := testOptions(t)
	options.Limits = DefaultLimits()
	_, policy := mappingFixture(t)
	store, err := intelligence.NewRecordStore(options.Workspace, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	writer := store.Writer(ctx)
	defer writer.Abort()
	const count = 200005
	prefixAt := func(i int) netip.Prefix {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + (i >> 16)), byte(i >> 8), byte(i), 0}), 24)
	}
	for i := 0; i < count; i++ {
		if err = writer.Append(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: prefixAt(i), Origins: []uint32{13335}}}); err != nil {
			t.Fatal(err)
		}
	}
	parts, err := writer.Finish()
	if err != nil {
		t.Fatal(err)
	}
	binding := sha256.Sum256([]byte("synthetic large-prefix engineering fixture"))
	state := intelligence.BuildState{Version: 2, PolicyHash: binding, EvaluatedAt: time.Unix(options.Clock, 0).UTC(), Sources: []intelligence.StoredSource{{ID: "synthetic-prefix-source", Fingerprint: binding, ExpiresAt: time.Unix(options.ValidUntil, 0).UTC(), RecordPartitions: parts}}}
	if _, err = BuildStreamedIntelligence(ctx, options, state, policy); err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(options.Output, func() int64 { return options.Clock })
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	cursor := uint32(0)
	for {
		page, err := reader.Prefixes(ctx, "AS13335", cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Prefixes) > 256 {
			t.Fatal("prefix page bound raised")
		}
		for _, prefix := range page.Prefixes {
			if prefix != prefixAt(total).String() {
				t.Fatalf("prefix %d changed: %s", total, prefix)
			}
			total++
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if total != count {
		t.Fatalf("prefix count truncated: %d", total)
	}
}
