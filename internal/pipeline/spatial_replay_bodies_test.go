package pipeline

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestSpatialReplayBodiesReproduceCurrentCanonicalWriter(t *testing.T) {
	c := &compiler{}
	bodies := spatialReplayBodies{compiler: c}
	const limit = int64(1 << 20)
	for _, r := range sparseRunParityRows() {
		if r.Kind >= 8 && r.Kind != 9 {
			continue
		}
		for _, prefix := range []string{"8.8.8.8/32", "2001:4860::88/128"} {
			r.Prefix = netip.MustParsePrefix(prefix)
			want, err := c.newCanonicalRunFrame(r)
			if err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(compactRunMarker), want.row.data...)
			got, err := bodies.canonical(wire, limit)
			if err != nil || !got.ownedBy(c) || !equalEncoded(got.row, want.row) || got.row.key != want.row.key || got.row.logicalBytes != want.row.logicalBytes {
				t.Fatalf("kind %d replay differs: %v", r.Kind, err)
			}
			clear(wire)
			if !equalEncoded(got.row, want.row) {
				t.Fatalf("kind %d retained caller storage", r.Kind)
			}
		}
	}
}

func TestSpatialReplayBodiesVerifyEveryHeaderBodyAndBudget(t *testing.T) {
	c := &compiler{}
	bodies := spatialReplayBodies{compiler: c}
	r := via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Geo: &via3.GeoData{Country: "US", City: "Seattle"}}
	want, err := c.newCanonicalRunFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(compactRunMarker), want.row.data...)
	if _, err = bodies.canonical(wire, want.row.logicalBytes); err != nil {
		t.Fatal(err)
	}
	if len(bodies.kinds) != 1 {
		t.Fatal("canonical writer equality did not retain body")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"inherited", func(b []byte) []byte { b[len(compactRunMarker)+10] |= 2; return b }},
		{"reserved-header", func(b []byte) []byte { b[len(compactRunMarker)+13] = 1; return b }},
		{"partial-exact", func(b []byte) []byte { b[len(compactRunMarker)+10] |= 1; return b }},
		{"wrong-spatial-kind", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[len(compactRunMarker)+2:], 3); return b }},
		{"nonspatial", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[len(compactRunMarker)+2:], 10); return b }},
		{"unknown-field", func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"Extra":0}`)...) }},
		{"incomplete-json", func(b []byte) []byte { return b[:len(b)-1] }},
		{"unknown-version", func(b []byte) []byte { b[4]++; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := bodies.canonical(tc.mutate(bytes.Clone(wire)), 1<<20); err == nil {
				t.Fatal("accepted invalid frame after preparing matching body")
			}
		})
	}
	if _, err = bodies.canonical(wire, want.row.logicalBytes-1); err == nil {
		t.Fatal("cached body bypassed dense limit")
	}
	// A legal but noncanonical spelling must be rewritten on every occurrence.
	noncanonical := bytes.Replace(wire, []byte(`"Seattle"`), []byte(`"Seatt\u006ce"`), 1)
	for range 2 {
		got, err := bodies.canonical(noncanonical, 1<<20)
		if err != nil || !equalEncoded(got.row, want.row) {
			t.Fatal("legal alternate encoding changed the canonical row", err)
		}
	}
	r.Geo = &via3.GeoData{City: strings.Repeat("a", 950), Region: strings.Repeat("b", 950)}
	long, err := encodeCompactRunRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bodies.canonical(append([]byte(compactRunMarker), long.data...), 1<<20); err != nil {
		t.Fatal(err)
	}
	if len(bodies.kinds) != 1 {
		t.Fatal("retained a noncanonical or oversized input")
	}
}
