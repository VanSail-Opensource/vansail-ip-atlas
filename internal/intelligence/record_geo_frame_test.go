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

func TestCanonicalGeographicComparisonChecksWriterSpelling(t *testing.T) {
	base := GeoEvidence{Family: "source", Weight: 1, Prefix: netip.MustParsePrefix("2001:db8::/32"), PhysicalCountry: "FR", Region: "Île-de-France", City: "Paris", Coordinates: &Coordinates{48.85, 2.35, 3}, Current: true}
	for _, weight := range []float64{1, 0, math.Copysign(0, -1), .000001, 999999999999999900000} {
		v := base
		v.Weight = weight
		record := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &v}
		canonical, err := json.Marshal(record)
		if err != nil || !canonicalWriterGeo(canonical, &v) {
			t.Fatalf("writer spelling missed for %v: %v", weight, err)
		}
	}
	record := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &base}
	canonical, _ := json.Marshal(record)
	for _, pair := range [][2]string{{`"Weight":1`, `"Weight":1.0`}, {`"Weight":1`, `"Weight":1e0`}, {`"Latitude":48.85`, `"Latitude":48.850`}, {`{"Version":`, `{ "Version":`}, {`"Paris"`, `"Par\u0069s"`}, {`2001:db8::/32`, `2001:0db8::/32`}, {`"Current":true`, `"Current": true`}} {
		changed := bytes.Replace(canonical, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(canonical, changed) {
			t.Fatalf("test did not change %q", pair[0])
		}
		decoded, err := decodeRecordFrame(changed)
		if err != nil || canonicalWriterGeo(changed, decoded.Geo) {
			t.Fatalf("accepted alternate spelling %q: %v", pair[1], err)
		}
	}
	for _, city := range []string{"A&B", "<Paris>", "quote\"", "slash\\", "line\n", "A\u2028B", "A\u2029B"} {
		v := base
		v.City = city
		r := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &v}
		encoded, _ := json.Marshal(r)
		if canonicalWriterGeo(encoded, &v) {
			t.Fatal("escaped geographic label left the ordinary encoder", city)
		}
	}
}

func FuzzCanonicalGeographicWriterComparison(f *testing.F) {
	base := NormalizedRecord{Version: 3, Kind: RecordGeo, Geo: &GeoEvidence{Family: "family", Weight: 1, Prefix: netip.MustParsePrefix("1.2.3.0/24"), PhysicalCountry: "US", Current: true}}
	encoded, _ := json.Marshal(base)
	f.Add(encoded)
	f.Add(bytes.Replace(encoded, []byte(`"Weight":1`), []byte(`"Weight":1.0`), 1))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		r, err := decodeRecordFrame(data)
		if err != nil || r.Geo == nil || !canonicalWriterGeo(data, r.Geo) {
			return
		}
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(canonical, data) {
			t.Fatal("accepted bytes differ from standard writer")
		}
	})
}
