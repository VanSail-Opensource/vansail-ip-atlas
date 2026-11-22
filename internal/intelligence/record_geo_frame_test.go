package intelligence

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/netip"
	"reflect"
	"testing"
	"unicode/utf8"
)

func verifyGeoFrame(t testing.TB, data []byte) {
	t.Helper()
	got, gotErr := decodeRecordFrame(data)
	var want NormalizedRecord
	wantErr := jsonv2.Unmarshal(data, &want, json.DefaultOptionsV1(), jsonv2.RejectUnknownMembers(true))
	if wantErr == nil {
		wantErr = want.Validate()
	}
	wantOK := wantErr == nil && utf8.Valid(data)
	if (gotErr == nil) != wantOK || wantOK && !reflect.DeepEqual(got, want) {
		t.Fatalf("geo decode mismatch for %q: %#v/%v, %#v/%v", data, got, gotErr, want, wantErr)
	}
}

func TestWriterGeoFrameParity(t *testing.T) {
	record := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &GeoEvidence{
		Prefix: netip.MustParsePrefix("2001:db8:1234::/40"), Weight: 37.5, Family: "sample",
		PhysicalCountry: "FR", Region: "Île-de-France", City: "Paris", Current: true,
		Coordinates: &Coordinates{Latitude: 48.857, Longitude: -2.3514, Precision: 255},
	}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	owned := bytes.Clone(data)
	decoded, ok := decodeWriterGeo(owned)
	if !ok {
		t.Fatal("writer shape missed")
	}
	clear(owned)
	if !reflect.DeepEqual(decoded, record.Geo) {
		t.Fatal("decoded geography retained the mutable wire buffer")
	}
	for _, value := range [][]byte{
		data,
		bytes.Replace(data, []byte("true"), []byte("false"), 1),
		bytes.Replace(data, []byte(`{"Latitude":48.857,"Longitude":-2.3514,"Precision":255}`), []byte("null"), 1),
		bytes.Replace(data, []byte("2001:db8:1234::/40"), []byte("::ffff:192.0.2.1/120"), 1),
	} {
		if _, ok := decodeWriterGeo(value); !ok {
			t.Fatalf("writer shape missed %q", value)
		}
		verifyGeoFrame(t, value)
	}
	// Fallback must retain ordinary decoding of all valid wire variants and
	// normal rejection of malformed input, including unknown and trailing data.
	for _, change := range [][2]string{
		{"37.5", "0"}, {"37.5", "-0"}, {"37.5", "-0.002"}, {"37.5", "1e+4"},
		{"37.5", "01"}, {"37.5", "+1"}, {"37.5", "1."}, {"37.5", "."},
		{"37.5", "0x1p2"}, {"37.5", "1_2"}, {"37.5", "-"}, {"37.5", "NaN"},
		{"255", "256"}, {"255", "025"}, {"255", "+25"}, {"255", "-1"}, {"255", "1.0"},
		{"Paris", `P\u0061ris`}, {"Paris", `P\"aris`}, {"Paris", "P\x01aris"},
		{"Paris", "P\xffaris"}, {"Region", "region"}, {"Region", "Bogus"},
		{"2001:db8:1234::/40", ""}, {"2001:db8:1234::/40", "bad prefix"},
		{`"Weight":`, `"Weight":25,"Weight":`}, {`"Current":true`, `"Current":null`},
		{`"Current":true`, `"Current":true,"Unexpected":null`}, {"}}", "}} "}, {"}}", "}}x"},
	} {
		verifyGeoFrame(t, bytes.Replace(data, []byte(change[0]), []byte(change[1]), 1))
	}
	for n := range len(data) {
		verifyGeoFrame(t, data[:n])
		mutated := bytes.Clone(data)
		mutated[n] ^= 1
		verifyGeoFrame(t, mutated)
	}
}

func FuzzWriterGeoFrameParity(f *testing.F) {
	v := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &GeoEvidence{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"), City: "Sample", Weight: 60.5, Current: true,
		Coordinates: &Coordinates{Latitude: -43.1, Longitude: 122, Precision: 2},
	}}
	b, err := json.Marshal(v)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) <= 4096 {
			verifyGeoFrame(t, data)
		}
	})
}
