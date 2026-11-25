package via3

import (
	"context"
	"math"
	"testing"
)

func TestRecordLookupRejectsOverflowAndOutOfRangeOrdinals(t *testing.T) {
	for _, width := range []int{1, 8, 64} {
		s := Shard{Sections: []Section{{ID: 3, Data: Vector(width, make([]byte, width), make([]byte, width))}}}
		for _, indexed := range []bool{false, true} {
			if indexed {
				s.lookup = shardLookupMetadata(&s, nil)
			}
			for _, ordinal := range []uint32{0, 1, 2, math.MaxUint32} {
				row := s.Record(ordinal)
				if ordinal < 2 && len(row) != width || ordinal >= 2 && row != nil {
					t.Fatalf("record width %d ordinal %d indexed %v", width, ordinal, indexed)
				}
			}
		}
	}
	if (&Shard{}).Record(0) != nil {
		t.Fatal("missing record section fabricated a row")
	}
}

func TestCountrySpellingsPreserveWireEnumAndMutableHeaderOwnership(t *testing.T) {
	for v := uint16(1); v <= 676; v++ {
		var first, second string
		a, b := countryInto(v, &first), countryInto(v, &second)
		if *a != *country(v) || *b != *a {
			t.Fatal("country enum spelling changed", v)
		}
		*a = "changed"
		if *b != *country(v) {
			t.Fatal("country value headers alias across answers")
		}
	}
	var absent string
	if countryInto(0, &absent) != nil {
		t.Fatal("unknown country fabricated a code")
	}
}

func TestRelationshipRoutingLoadsOnlyReferencedFactKind(t *testing.T) {
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	r.beginQuery()
	defer r.endQuery()
	before := r.Reads
	s, err := r.asnDestination(context.Background(), 13335, 12)
	if err != nil || s == nil || s.Kind != 12 {
		t.Fatalf("missing routed relationship shard: %v", err)
	}
	if r.Reads != before+1 {
		t.Fatal("relationship route loaded unrelated ASN facts")
	}
	for _, reference := range r.references {
		if reference.shard != nil && reference.info.Kind != 1 && reference.info.Kind != 12 {
			t.Fatal("relationship query pinned an unrelated fact kind")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.asnDestination(ctx, 13335, 12); err != context.Canceled {
		t.Fatal("cached relationship route ignored cancellation", err)
	}
}

func TestRelationshipRoutingPreservesAbsentKindAndOrigin(t *testing.T) {
	g := golden(t)
	r := memoryRelease(t, g, func() int64 { return g.Clock })
	for _, query := range []struct {
		asn  uint32
		kind uint16
	}{{13335, 2}, {42424242, 12}} {
		before := r.Reads
		s, err := r.asnDestination(context.Background(), query.asn, query.kind)
		if err != nil || s != nil || r.Reads != before {
			t.Fatal("missing route loaded or fabricated a fact", err)
		}
	}
}
