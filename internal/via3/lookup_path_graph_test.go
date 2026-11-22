package via3

import (
	"reflect"
	"slices"
	"testing"
)

func graphFixture(t *testing.T) (*Release, *objectReference, *Shard) {
	t.Helper()
	const asn = 13335
	var rows, segments [][]byte
	var ints []uint32
	add := func(eligible bool, kinds []byte, parts ...[]uint32) {
		row := make([]byte, 24)
		p32(row, 0, bits(29))
		p32(row, 4, asn)
		p32(row, 8, uint32(len(segments)))
		p16(row, 12, uint16(len(parts)))
		if eligible {
			row[14] = 1
		}
		row[15] = byte(len(rows))
		rows = append(rows, row)
		for i, part := range parts {
			seg := make([]byte, 12)
			seg[0] = kinds[i]
			p32(seg, 4, uint32(len(ints)))
			p32(seg, 8, uint32(len(part)))
			segments = append(segments, seg)
			ints = append(ints, part...)
		}
	}
	add(true, []byte{1, 1}, []uint32{asn, asn, 174}, []uint32{3356})
	add(true, []byte{1}, []uint32{asn, 174, 6939})
	add(false, []byte{2, 3, 4}, []uint32{174, asn}, []uint32{64501}, []uint32{64502})
	shard := newShard(11, rows...)
	shard.set(2, asnKeys(asn))
	shard.set(4, intVector(ints...))
	shard.set(9, Vector(12, segments...))
	if err := Validate(shard); err != nil {
		t.Fatal(err)
	}
	shard.lookup = shardLookupMetadata(&shard, nil)
	ref := &objectReference{shard: &shard}
	shard.lookup.owner = ref
	r := &Release{}
	if err := r.admitReference(ref, decodedSize(&shard)); err != nil {
		t.Fatal(err)
	}
	r.cacheReference(ref)
	return r, ref, &shard
}

func TestPathGraphPreservesSegmentsBudgetsAndIndependentAnswerStorage(t *testing.T) {
	const asn = 13335
	r, ref, s := graphFixture(t)
	base := r.residentBytes
	if r.pathGraph(s, asn) != nil {
		t.Fatal("first lookup performed an unrequested index build")
	}
	g := r.pathGraph(s, asn)
	if g == nil || s.lookup.graphIndex.bytes != graphTableBytes+g.bytes() || r.residentBytes != base+s.lookup.graphIndex.bytes {
		t.Fatal("missing or incorrectly charged graph")
	}
	strictBudget, indexedBudget := newAnswerBudget(), newAnswerBudget()
	want, err := s.appendOriginPaths([]PathAnswer{}, asn, strictBudget)
	if err != nil {
		t.Fatal(err)
	}
	got := g.appendPaths([]PathAnswer{}, asn, indexedBudget)
	if !reflect.DeepEqual(got, want) || *strictBudget != *indexedBudget {
		t.Fatal("indexed topology changed segments or budget")
	}
	pair := func(from, to uint64) uint64 { return from<<32 | to }
	expected := []uint64{pair(174, 3356), pair(174, 6939), pair(asn, 174)}
	if !slices.Equal(g.pairs, expected) {
		t.Fatal("projection incorrectly retained a prepend, non-eligible path, or duplicate")
	}
	for i, p := range got {
		if cap(p.Segments) != len(p.Segments) || cap(p.ASNs) != len(p.ASNs) {
			t.Fatal("unbounded caller-owned path range")
		}
		for _, segment := range p.Segments {
			if cap(segment.ASNs) != len(segment.ASNs) {
				t.Fatal("segment append could overwrite a neighbor")
			}
			segment.ASNs[0]++
		}
		if !slices.Equal(p.ASNs, want[i].ASNs) {
			t.Fatal("flat and structured path values alias")
		}
	}
	if !reflect.DeepEqual(g.appendPaths(nil, asn, newAnswerBudget()), want) {
		t.Fatal("caller mutated the retained numeric topology")
	}
	if g.fits(&answerBudget{paths: PublicPathASNs - len(g.values) + 1}) || g.fits(&answerBudget{bytes: PublicAnswerBytes - 16*len(g.values) - 128*len(g.segments) + 1}) {
		t.Fatal("index bypassed an answer limit")
	}
	limited := &answerBudget{paths: PublicPathASNs - 4}
	partial, err := s.appendOriginPaths(nil, asn, limited)
	if ErrorCode(err) != "resource_limit" || !reflect.DeepEqual(partial, want[:1]) {
		t.Fatal("fallback lost the preceding complete path", err)
	}
	if r.pathGraph(s, asn+8) != nil || ref.size != base+graphTableBytes {
		t.Fatal("colliding origin retained stale graph values")
	}
	r.releaseGraphMetadata(ref)
	if r.residentBytes != base || r.cacheBytes != base || r.activeBytes != base || ref.size != base || s.lookup.graphIndex != nil {
		t.Fatal("graph metadata charges survived removal")
	}
}

func TestRequiredPayloadReclaimsPinnedGraphBeforeBudgetFailure(t *testing.T) {
	r, ref, s := graphFixture(t)
	_ = r.pathGraph(s, 13335)
	g := r.pathGraph(s, 13335)
	if g == nil {
		t.Fatal("graph missing")
	}
	retained := s.lookup.graphIndex.bytes
	base := decodedSize(s)
	r.evictReference(ref)
	// Account for other pinned decoded bytes, leaving only the optional
	// graph's size available for a required immutable target after reclamation.
	r.residentBytes = PublicLiveDecoded
	target := &objectReference{}
	if err := r.admitReference(target, retained); err != nil {
		t.Fatal(err)
	}
	if s.lookup.graphIndex != nil || ref.size != base || target.size != retained || r.residentBytes != PublicLiveDecoded {
		t.Fatal("required payload failed to replace optional graph storage")
	}
	if r.pathGraph(s, 13335) != nil {
		t.Fatal("uncached shard reacquired optional graph storage")
	}
	if !slices.Equal(g.values, []uint32{13335, 13335, 174, 3356, 13335, 174, 6939, 174, 13335, 64501, 64502}) {
		t.Fatal("reclamation mutated the verified source values")
	}
}

func TestPathGraphRespectsEveryOptionalStorageLimit(t *testing.T) {
	for _, limit := range []string{"object", "cache", "live"} {
		t.Run(limit, func(t *testing.T) {
			r, ref, s := graphFixture(t)
			const asn = 13335
			if g := r.pathGraph(s, asn); g != nil {
				t.Fatal("first access installed graph")
			}
			switch limit {
			case "object":
				ref.size = PublicObjectDecoded - graphHeaderBytes
			case "cache":
				r.cacheBytes = PublicCacheDecoded - graphHeaderBytes
			case "live":
				r.residentBytes = PublicLiveDecoded - graphHeaderBytes
			}
			before := s.lookup.graphIndex.bytes
			if g := r.pathGraph(s, asn); g != nil || before != s.lookup.graphIndex.bytes {
				t.Fatal("exhausted optional budget retained graph")
			}
			got, err := s.appendOriginPaths(nil, asn, newAnswerBudget())
			if err != nil || len(got) != 3 {
				t.Fatal("failed to materialize paths from verified source after index declined", err)
			}
		})
	}
}
