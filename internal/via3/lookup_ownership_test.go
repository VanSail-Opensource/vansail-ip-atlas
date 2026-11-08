package via3

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"reflect"
	"testing"
)

func TestRuntimeLookupMetadataPreservesEveryPrefixDepth(t *testing.T) {
	g := golden(t)
	for _, object := range g.Objects {
		encoded, err := base64.StdEncoding.DecodeString(object.Base64)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := Read(context.Background(), encoded)
		if err != nil {
			t.Fatal(err)
		}
		indexed := raw
		indexed.lookup = shardLookupMetadata(&indexed, nil)
		for _, query := range []string{"203.0.113.1", "203.0.113.200", "203.0.114.1", "8.8.8.8", "2001:db8::1", "2001:db8:ffff::1", "::ffff:203.0.113.1"} {
			addr := netip.MustParseAddr(query)
			for depth := 0; depth <= addr.Unmap().BitLen(); depth++ {
				before, beforePrefix, beforeOK := raw.findPrefixWithin(addr, depth)
				after, afterPrefix, afterOK := indexed.findPrefixWithin(addr, depth)
				if beforeOK != afterOK || beforePrefix != afterPrefix || !bytes.Equal(before, after) {
					t.Fatalf("kind%d query%s depth%d changed with runtime metadata", raw.Kind, query, depth)
				}
			}
		}
	}
}

func TestRuntimeMetadataCannotRetainWithdrawnPrefix(t *testing.T) {
	row := make([]byte, 8)
	p32(row, 0, bits(5))
	row[4] = 1
	shard := newShard(5, row)
	shard.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	shard.lookup = shardLookupMetadata(&shard, nil)
	addr := netip.MustParseAddr("203.0.113.1")
	if _, _, ok := shard.FindPrefix(addr); !ok {
		t.Fatal("fixture did not resolve before withdrawal")
	}
	shard.set(1, Vector(32))
	if _, _, ok := shard.FindPrefix(addr); ok {
		t.Fatal("runtime metadata retained a withdrawn prefix")
	}
}

func TestDirectReferencePinsClearOnAllQueryExitsAndCacheEviction(t *testing.T) {
	g := golden(t)
	now := g.Clock
	reader := memoryRelease(t, g, func() int64 { return now })
	assertReleased := func() {
		t.Helper()
		if len(reader.usedReferences) != 0 {
			t.Fatal("query retained direct reference pins")
		}
		for _, reference := range reader.references {
			if reference.active != nil {
				t.Fatal("completed query retains decoded shard through a direct reference")
			}
		}
	}
	if _, err := reader.Lookup(context.Background(), "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	assertReleased()
	if _, err := reader.Prefixes(context.Background(), "AS13335", 99); ErrorCode(err) != "invalid_cursor" {
		t.Fatal(err)
	}
	assertReleased()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = reader.Lookup(ctx, "203.0.113.1")
	assertReleased()
	reader.beginQuery()
	shard, err := reader.reference(context.Background(), reader.router, 0)
	if err != nil {
		t.Fatal(err)
	}
	reference := reader.router.lookup.references[0]
	reader.evictCache(reference.hash)
	if again, err := reader.reference(context.Background(), reader.router, 0); err != nil || again != shard {
		t.Fatal("active reference lost its query pin on cache eviction", err)
	}
	if _, err := reader.reference(ctx, reader.router, 0); err != context.Canceled {
		t.Fatal("cancelled context exposed a directly pinned shard", err)
	}
	reader.endQuery()
	assertReleased()
	if reader.residents[reference.hash] != nil {
		t.Fatal("evicted shard remains resident after query pin release")
	}
	now = g.Manifest.ValidUntil
	if _, err := reader.Lookup(context.Background(), "203.0.113.1"); ErrorCode(err) != "expired" {
		t.Fatal(err)
	}
	assertReleased()
}

// Lookup returns caller-owned mutable containers and optional-value pointers.
// Mutating one answer must not change another answer or the verified release.
func TestLookupAnswersOwnMutableValues(t *testing.T) {
	g := golden(t)
	reader := memoryRelease(t, g, func() int64 { return g.Clock })
	for _, vector := range g.Vectors {
		first, err := reader.Lookup(context.Background(), vector.Q)
		if err != nil {
			t.Fatal(err)
		}
		second, err := reader.Lookup(context.Background(), vector.Q)
		if err != nil {
			t.Fatal(err)
		}
		mutateLookupValue(reflect.ValueOf(&first).Elem())
		if !reflect.DeepEqual(second, vector.Answer) {
			t.Fatalf("mutating %s answer changed a previous independent answer", vector.Q)
		}
		third, err := reader.Lookup(context.Background(), vector.Q)
		if err != nil || !reflect.DeepEqual(third, vector.Answer) {
			t.Fatalf("mutating %s answer changed the release: %v", vector.Q, err)
		}
	}
}

func mutateLookupValue(value reflect.Value) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			mutateLookupValue(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			mutateLookupValue(value.Field(i))
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			mutateLookupValue(value.Index(i))
		}
	case reflect.String:
		value.SetString("caller mutation")
	case reflect.Bool:
		value.SetBool(!value.Bool())
	case reflect.Uint8, reflect.Uint32:
		value.SetUint(value.Uint() + 1)
	case reflect.Int64:
		value.SetInt(value.Int() + 1)
	case reflect.Float64:
		value.SetFloat(value.Float() + 1)
	}
}

func TestLookupPathFlatAndSegmentValuesAreIndependent(t *testing.T) {
	g := golden(t)
	reader := memoryRelease(t, g, func() int64 { return g.Clock })
	answer, err := reader.Lookup(context.Background(), "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.BGP.Paths) == 0 {
		t.Fatal("fixture lacks retained paths")
	}
	for _, path := range answer.BGP.Paths {
		first := path.Segments[0].ASNs[0]
		path.ASNs[0]++
		if path.Segments[0].ASNs[0] != first {
			t.Fatal("flat ASNs alias mutable segment values")
		}
		for index := 1; index < len(path.Segments); index++ {
			next := path.Segments[index].ASNs[0]
			_ = append(path.Segments[index-1].ASNs, 1234)
			if path.Segments[index].ASNs[0] != next {
				t.Fatal("appending a segment overwrote another segment")
			}
		}
	}
}
