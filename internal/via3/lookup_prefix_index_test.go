package via3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

func prefixSearchFixture(count int, overlap bool) (Shard, []netip.Addr) {
	value := make([]byte, 8)
	p32(value, 0, bits(5))
	value[4] = 1
	shard := newShard(5, value)
	rows := make([][]byte, 0, count+2)
	queries := make([]netip.Addr, 0, count)
	if overlap {
		rows = append(rows, PrefixKey(netip.MustParsePrefix("2001::/32"), false, 0))
	}
	for i := 0; i < count; i++ {
		address := [16]byte{0x20, 0x01}
		binary.BigEndian.PutUint16(address[4:6], uint16(i))
		depth := 48 + i%81
		prefix := netip.PrefixFrom(netip.AddrFrom16(address), depth)
		rows = append(rows, PrefixKey(prefix, depth == 128 && i%2 == 0, 0))
		if depth < 128 {
			address[15] = 1
		}
		queries = append(queries, netip.AddrFrom16(address))
	}
	sort.Slice(rows, func(i, j int) bool { return keyCompare(rows[i], rows[j]) < 0 })
	shard.set(1, Vector(32, rows...))
	shard.set(8, prefixRows(key("2000::/3", false, 0)))
	return shard, queries
}

func TestPrefixAncestryIndexPreservesMixedDepthQueriesAndMaximumDepth(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		raw, queries := prefixSearchFixture(256, overlap)
		if err := Validate(raw); err != nil {
			t.Fatal("invalid mixed-depth fixture", err)
		}
		indexed := raw
		indexed.lookup = shardLookupMetadata(&indexed, nil)
		hasParent := false
		for _, parent := range indexed.lookup.prefixes[0].parents {
			hasParent = hasParent || parent != None
		}
		if hasParent != overlap {
			t.Fatal("ancestor proof differs from actual prefix population")
		}
		queries = append(queries, netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:ffff::"), netip.MustParseAddr("3000::1"))
		for _, query := range queries {
			for depth := 0; depth <= query.BitLen(); depth++ {
				before, beforePrefix, beforeOK := raw.findPrefixWithin(query, depth)
				after, afterPrefix, afterOK := indexed.findPrefixWithin(query, depth)
				if beforeOK != afterOK || beforePrefix != afterPrefix || !bytes.Equal(before, after) {
					t.Fatalf("overlap=%v address=%s depth=%d changed indexed result", overlap, query, depth)
				}
			}
		}
	}
}

func TestPrefixAncestryIndexKeepsFamiliesExactSpecificityAndInheritedFallback(t *testing.T) {
	var values [][]byte
	for kind := byte(1); kind <= 4; kind++ {
		value := make([]byte, 8)
		p32(value, 0, bits(5))
		value[4] = kind
		values = append(values, value)
	}
	raw := newShard(5, values...)
	raw.set(1, prefixRows(key("0.0.0.0/0", false, 0), key("203.0.113.1/32", false, 1), key("::/0", false, 2)))
	raw.set(8, prefixRows(key("203.0.113.1/32", true, 3), key("2001:db8::/32", false, 1)))
	if err := Validate(raw); err != nil {
		t.Fatal("invalid family/exact fixture", err)
	}
	indexed := raw
	indexed.lookup = shardLookupMetadata(&indexed, nil)
	for _, query := range []string{"203.0.113.1", "::ffff:203.0.113.1", "203.0.113.2", "2001:db8::1", "2002::1"} {
		address := netip.MustParseAddr(query)
		for depth := 0; depth <= address.Unmap().BitLen(); depth++ {
			a, ap, aok := raw.findPrefixWithin(address, depth)
			b, bp, bok := indexed.findPrefixWithin(address, depth)
			if aok != bok || ap != bp || !bytes.Equal(a, b) {
				t.Fatalf("family/exact precedence changed for %s depth %d", query, depth)
			}
		}
	}
}

func TestPrefixAncestryMetadataIsBoundedAndReleasedWithShard(t *testing.T) {
	shard, _ := prefixSearchFixture(1024, true)
	shard.lookup = shardLookupMetadata(&shard, nil)
	for section, id := range []uint16{1, 8} {
		rows, _ := shard.Rows(id)
		metadata := &shard.lookup.prefixes[section]
		if len(metadata.parents) != len(rows)/32 || cap(metadata.parents) != len(metadata.parents) {
			t.Fatal("ancestor allocation exceeds one u32 per validated prefix")
		}
		for ordinal, parent := range metadata.parents {
			if parent == None {
				continue
			}
			if int(parent) >= ordinal {
				t.Fatal("ancestor references a future or current row")
			}
			child := rows[ordinal*32 : (ordinal+1)*32]
			ancestor := rows[int(parent)*32 : (int(parent)+1)*32]
			childAddr, _ := keyAddr(child)
			parentAddr, _ := keyAddr(ancestor)
			if child[0] != ancestor[0] || ancestor[1] > child[1] || !netip.PrefixFrom(parentAddr, int(ancestor[1])).Contains(childAddr) {
				t.Fatal("parent index does not reference a containing prefix")
			}
		}

	}
	shard.set(1, Vector(32))
	if shard.lookup != nil {
		t.Fatal("replaced payload retained a stale derived prefix index")
	}
}

func TestPrefixAncestryEveryDepthAndFullLengthExactTie(t *testing.T) {
	for _, text := range []string{"0.0.0.0", "::"} {
		address := netip.MustParseAddr(text)
		var rows, values [][]byte
		for depth := 0; depth <= address.BitLen()+1; depth++ {
			exact := depth > address.BitLen()
			length := min(depth, address.BitLen())
			rows = append(rows, PrefixKey(netip.PrefixFrom(address, length), exact, uint32(depth)))
			value := make([]byte, 8)
			p32(value, 0, bits(5))
			value[4] = byte(1 + depth%7)
			values = append(values, value)
		}
		raw := newShard(5, values...)
		raw.set(1, Vector(32, rows...))
		if err := Validate(raw); err != nil {
			t.Fatal("invalid all-depth fixture", err)
		}
		indexed := raw
		indexed.lookup = shardLookupMetadata(&indexed, nil)
		for depth := 0; depth <= address.BitLen(); depth++ {
			for _, query := range []netip.Addr{address, address.Next()} {
				a, ap, aok := raw.findPrefixWithin(query, depth)
				b, bp, bok := indexed.findPrefixWithin(query, depth)
				if aok != bok || ap != bp || !bytes.Equal(a, b) {
					t.Fatalf("all-depth ancestor/tie changed at %s depth %d", query, depth)
				}
			}
		}
		for ordinal := range indexed.lookup.prefixes[0].parents {
			steps := 0
			for parent := uint32(ordinal); parent != None; parent = indexed.lookup.prefixes[0].parents[parent] {
				steps++
				if steps > address.BitLen()+2 {
					t.Fatal("ancestor walk exceeds address depth plus full-length tie")
				}
			}
		}
	}
}

func TestPrefixAncestryRandomizedIntervalsMatchRawReader(t *testing.T) {
	random := rand.New(rand.NewSource(40219))
	var local, inherited, values [][]byte
	var queries []netip.Addr
	seen := map[string]bool{}
	for i := 0; i < 768; i++ {
		var encoded [16]byte
		_, _ = random.Read(encoded[:])
		address := netip.AddrFrom16(encoded)
		if i%2 == 0 {
			address = netip.AddrFrom4([4]byte(encoded[12:]))
		}
		depth := random.Intn(address.BitLen() + 1)
		prefix := netip.PrefixFrom(address, depth).Masked()
		row := PrefixKey(prefix, depth == address.BitLen() && i%3 == 0, uint32(len(values)))
		identity := string(row[:20])
		if seen[identity] {
			continue
		}
		seen[identity] = true
		value := make([]byte, 8)
		p32(value, 0, bits(5))
		value[4] = byte(1 + len(values)%7)
		values = append(values, value)
		if i%3 == 0 {
			inherited = append(inherited, row)
		} else {
			local = append(local, row)
		}
		queries = append(queries, address, prefix.Addr(), prefix.Addr().Prev())
	}
	for _, rows := range [][][]byte{local, inherited} {
		sort.Slice(rows, func(i, j int) bool { return keyCompare(rows[i], rows[j]) < 0 })
	}
	raw := newShard(5, values...)
	raw.set(1, Vector(32, local...))
	raw.set(8, Vector(32, inherited...))
	if err := Validate(raw); err != nil {
		t.Fatal("invalid randomized fixture", err)
	}
	indexed := raw
	indexed.lookup = shardLookupMetadata(&indexed, nil)
	for _, query := range queries {
		if !query.IsValid() {
			continue
		}
		for _, depth := range []int{0, query.BitLen(), random.Intn(query.BitLen() + 1)} {
			a, ap, aok := raw.findPrefixWithin(query, depth)
			b, bp, bok := indexed.findPrefixWithin(query, depth)
			if aok != bok || ap != bp || !bytes.Equal(a, b) {
				t.Fatalf("randomized interval/family boundary changed at %s depth %d", query, depth)
			}
		}
	}
}

// This is the previous validated-reader search: cached section rows and absent
// depth skipping, but a whole address-ordered table search for each depth.
func legacyPrefixSearch(s *Shard, addr netip.Addr, maxBits int) ([]byte, netip.Prefix, bool) {
	addr = addr.Unmap()
	family := 0
	if addr.Is6() {
		family = 1
	}
	var key [32]byte
	for depth := maxBits; depth >= 0; depth-- {
		if s.lookup.depths[family][depth/64]&(1<<uint(depth%64)) == 0 {
			continue
		}
		prefix := netip.PrefixFrom(addr, depth).Masked()
		for _, exact := range []bool{true, false} {
			if exact && depth != addr.BitLen() {
				continue
			}
			fillPrefixKey(key[:], prefix, exact, 0)
			for _, id := range []uint16{1, 8} {
				rows, _ := s.Rows(id)
				i := sort.Search(len(rows)/32, func(i int) bool { return keyCompare(rows[i*32:(i+1)*32], key[:]) >= 0 })
				if i < len(rows)/32 && keyCompare(rows[i*32:(i+1)*32], key[:]) == 0 {
					return s.Record(u32(rows, i*32+20)), prefix, true
				}
			}
		}
	}
	return nil, netip.Prefix{}, false
}

func BenchmarkMixedIPv6PrefixIndex(b *testing.B) {
	for _, overlap := range []bool{false, true} {
		for _, indexed := range []bool{false, true} {
			b.Run(fmt.Sprintf("overlap=%v/ancestry=%v", overlap, indexed), func(b *testing.B) {
				shard, queries := prefixSearchFixture(4096, overlap)
				shard.lookup = shardLookupMetadata(&shard, nil)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					query := queries[i%len(queries)]
					var ok bool
					if indexed {
						_, _, ok = shard.findPrefix(query)
					} else {
						_, _, ok = legacyPrefixSearch(&shard, query, query.BitLen())
					}
					if !ok {
						b.Fatal("actual indexed lookup lost the query")
					}
				}
			})
		}
	}
}
