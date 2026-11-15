package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestCorpusLabelsOnlySelectedIndexRow(t *testing.T) {
	parent := via3.PrefixKey(netip.MustParsePrefix("8.8.0.0/16"), false, 0)
	child := via3.PrefixKey(netip.MustParsePrefix("8.8.8.0/24"), false, 1)
	host := via3.PrefixKey(netip.MustParsePrefix("8.8.8.1/32"), false, 2)
	exact := via3.PrefixKey(netip.MustParsePrefix("8.8.8.1/32"), true, 3)
	localParent := via3.PrefixKey(netip.MustParsePrefix("8.8.0.0/16"), false, 4)
	newShard := func(local, inherited [][]byte) *via3.Shard {
		return &via3.Shard{Kind: 4, Sections: []via3.Section{
			{ID: 1, Data: via3.Vector(32, local...)},
			{ID: 3, Data: via3.Vector(40, make([]byte, 40), make([]byte, 40), make([]byte, 40), make([]byte, 40), make([]byte, 40))},
			{ID: 8, Data: via3.Vector(32, inherited...)},
		}}
	}
	shard := newShard([][]byte{child, host, exact}, [][]byte{parent})
	for _, test := range []struct {
		name    string
		section uint16
		row     []byte
		address string
		want    bool
	}{
		{"inherited survives", 8, parent, "8.8.9.1", true},
		{"inherited shadowed", 8, parent, "8.8.8.1", false},
		{"child selected", 1, child, "8.8.8.2", true},
		{"child shadowed", 1, child, "8.8.8.1", false},
		{"host shadowed by exact", 1, host, "8.8.8.1", false},
		{"exact selected", 1, exact, "8.8.8.1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := corpusRowSelected(shard, test.section, test.row, netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("selected=%v want=%v", got, test.want)
			}
		})
	}
	shard = newShard([][]byte{localParent}, [][]byte{parent})
	if corpusRowSelected(shard, 8, parent, netip.MustParseAddr("8.8.9.1")) || !corpusRowSelected(shard, 1, localParent, netip.MustParseAddr("8.8.9.1")) {
		t.Fatal("local replacement mislabeled as inherited")
	}
}

func TestCorpusNetworkMOASUsesRecordOrdinalAndOriginCount(t *testing.T) {
	row := via3.PrefixKey(netip.MustParsePrefix("8.8.8.0/24"), false, 1)
	record := make([]byte, 40)
	binary.LittleEndian.PutUint32(record[4:8], 99) // Origin offset is not its count.
	binary.LittleEndian.PutUint32(record[8:12], 2)
	shard := &via3.Shard{Kind: 4, Sections: []via3.Section{{ID: 3, Data: via3.Vector(40, make([]byte, 40), record)}}}
	if !corpusNetworkMOAS(shard, row) {
		t.Fatal("second network record with two origins not detected")
	}
	binary.LittleEndian.PutUint32(row[20:24], 0)
	if corpusNetworkMOAS(shard, row) {
		t.Fatal("origin count read from wrong record")
	}
	binary.LittleEndian.PutUint32(row[20:24], 99)
	if corpusNetworkMOAS(shard, row) {
		t.Fatal("out of bounds record accepted")
	}
	shard.Kind = 2
	if corpusNetworkMOAS(shard, row) {
		t.Fatal("non-network record accepted")
	}
}

func TestCorpusPrefixRejectsNonCanonicalRows(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(row []byte) { row[19] = 1 },
		func(row []byte) { row[2] = 1 },
		func(row []byte) { row[2] = 2 },
		func(row []byte) { row[4] = 1 },
		func(row []byte) { row[24] = 1 },
	} {
		row := via3.PrefixKey(netip.MustParsePrefix("8.8.8.0/24"), false, 0)
		mutate(row)
		if _, _, err := corpusPrefix(row); err == nil {
			t.Fatal("malformed corpus row accepted")
		}
	}
}
