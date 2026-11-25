package intelligence

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"unicode/utf8"
)

func verifyRecordFrame(t testing.TB, data []byte) {
	t.Helper()
	got, gotErr := decodeRecordFrame(data)
	var want NormalizedRecord
	wantErr := jsonv2.Unmarshal(data, &want, json.DefaultOptionsV1(), jsonv2.RejectUnknownMembers(true))
	if wantErr == nil {
		wantErr = want.Validate()
	}
	wantOK := wantErr == nil && utf8.Valid(data)
	if (gotErr == nil) != wantOK || wantOK && !reflect.DeepEqual(got, want) {
		t.Fatalf("record decode mismatch for %q: %#v/%v, %#v/%v", data, got, gotErr, want, wantErr)
	}
}

func TestWriterFixedDecimalsRoundIdentically(t *testing.T) {
	for _, input := range []string{"-0", "-0.0", "999999999999999", "-0.000000000001", "0.1234567890123", "107.035", "-27.983921"} {
		reader := writerFrameReader{remaining: []byte(input + ",")}
		got := reader.number()
		want, err := strconv.ParseFloat(input, 64)
		if err != nil || string(reader.remaining) != "," || math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("fixed decimal %q: got %v, want %v", input, got, want)
		}
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
		verifyRecordFrame(t, value)
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
		verifyRecordFrame(t, bytes.Replace(data, []byte(change[0]), []byte(change[1]), 1))
	}
	for n := range len(data) {
		verifyRecordFrame(t, data[:n])
		mutated := bytes.Clone(data)
		mutated[n] ^= 1
		verifyRecordFrame(t, mutated)
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
			verifyRecordFrame(t, data)
		}
	})
}
