package pipeline

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestLeafPayloadReusePreservesHeaderAndStrictValidation(t *testing.T) {
	var cache leafPayloads
	const limit = 1 << 20
	encode := func(r via3.PublicRecord) []byte {
		row, err := encodeCompactRunRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(compactRunMarker), row.data...)
	}
	first := via3.PublicRecord{Version: 3, Kind: 6, Prefix: netip.MustParsePrefix("8.8.8.0/24"), Quality: &via3.QualityData{Reasons: 1}}
	second := first
	second.Prefix, second.Inherited = netip.MustParsePrefix("2001:db8::/32"), true
	firstBytes, secondBytes := encode(first), encode(second)
	one, row, err := cache.decode(firstBytes, limit)
	if err != nil || !reflect.DeepEqual(row, first) {
		t.Fatal("first strict decode differed", err)
	}
	two, row, err := cache.decode(secondBytes, limit)
	strict, want, expectedErr := decodeRunPayload(secondBytes, limit)
	if err != nil || expectedErr != nil || !reflect.DeepEqual(row, want) || !reflect.DeepEqual(two, strict) || one.key == two.key {
		t.Fatal("repeated payload changed a header or transport field", err, expectedErr)
	}
	if _, _, err = cache.decode(secondBytes, two.logicalBytes-1); err == nil {
		t.Fatal("cache hit bypassed logical byte limit")
	}
	malformed := bytes.Clone(secondBytes)
	malformed[len(compactRunMarker)+15] = 1
	if _, _, err = cache.decode(malformed, limit); err == nil {
		t.Fatal("cache hit bypassed canonical header checks")
	}
	malformed = bytes.Clone(secondBytes)
	binary.LittleEndian.PutUint16(malformed[len(compactRunMarker)+2:], 3)
	if _, _, err = cache.decode(malformed, limit); err == nil {
		t.Fatal("cached JSON accepted as another union kind")
	}
	malformed = append(bytes.Clone(secondBytes[:len(secondBytes)-1]), []byte(`,"Unreviewed":true}`)...)
	if _, _, err = cache.decode(malformed, limit); err == nil {
		t.Fatal("new member reused a previous body")
	}
	for i := 0; i < 512; i++ {
		r := via3.PublicRecord{Version: 3, Kind: 2, Prefix: first.Prefix, Geo: &via3.GeoData{City: fmt.Sprintf("City %d", i)}}
		frame := encode(r)
		_, decoded, err := cache.decode(frame, limit)
		if err != nil || !reflect.DeepEqual(r, decoded) || len(cache.values) > len(cache.keys) {
			t.Fatal("eviction changed facts or exceeded its bound", i, err)
		}
	}
}
