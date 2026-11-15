package pipeline

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestCompactRunRoundTripPreservesDenseBudgetAllKinds(t *testing.T) {
	rows := sparseRunParityRows()
	for _, p := range []string{"0.0.0.0/0", "8.8.8.8/32", "::/0", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff/128"} {
		for _, inherited := range []bool{false, true} {
			r := rows[0]
			r.Prefix, r.Inherited = netip.MustParsePrefix(p), inherited
			rows = append(rows, r)
		}
	}
	for _, r := range rows {
		if !r.Inherited {
			var err error
			r, err = normalize(r)
			if err != nil {
				t.Fatal(err)
			}
		}
		dense, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		row, err := encodeCompactRunRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		if row.logicalBytes != int64(len(dense)) || row.frameBytes() >= int64(len(dense)+4) {
			t.Fatal("dense logical budget changed", r.Kind, row.logicalBytes, len(dense))
		}
		var frame bytes.Buffer
		if err = writeRunFrame(&frame, row); err != nil {
			t.Fatal(err)
		}
		actual, decoded, err := decodeRunPayload(frame.Bytes()[4:], row.logicalBytes)
		if err != nil || !reflect.DeepEqual(decoded, r) || !equalEncoded(row, actual) || actual.logicalBytes != row.logicalBytes {
			t.Fatal("record or dense budget changed", r.Kind, err)
		}
		if _, _, err = decodeRunPayload(frame.Bytes()[4:], row.logicalBytes-1); err == nil {
			t.Fatal("original dense record limit bypassed")
		}
		for _, sparse := range []bool{false, true} {
			legacy, err := encodeRunRecord(r, sparse)
			if err != nil || equalEncoded(row, legacy) {
				t.Fatal("legacy conflict lost", err)
			}
		}
	}
}

func TestCompactRunRejectsMalformedHeaderAndUnion(t *testing.T) {
	r := sparseRunParityRows()[0]
	r.Prefix = netip.MustParsePrefix("8.8.8.0/24")
	row, err := encodeCompactRunRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		index int
		value byte
	}{
		{0, 4}, {2, 1}, {2, 14}, {4, 1}, {8, 1}, {10, 4}, {11, 5}, {12, 33}, {13, 1}, {16, 1}, {31, 1},
	} {
		data := append([]byte(nil), row.data...)
		data[mutation.index] = mutation.value
		if _, _, err = decodeCompactRunPayload(data, DefaultLimits().RecordBytes); err == nil {
			t.Fatal("malformed compact header accepted", mutation)
		}
	}
	for _, payload := range []string{"null", "[]", `{"Unknown":1}`, `{"City":true}`, `{"City":"x"} {}`, `{"City":`} {
		data := append(append([]byte(nil), row.data[:compactRunHeader]...), payload...)
		if _, _, err = decodeCompactRunPayload(data, DefaultLimits().RecordBytes); err == nil {
			t.Fatal("malformed union accepted", payload)
		}
	}
	for _, payload := range [][]byte{[]byte("ATCP"), []byte("ATCP\x02\x00\x00\x00"), []byte(compactRunMarker), append([]byte(compactRunMarker), row.data[:compactRunHeader]...)} {
		if _, _, err = decodeRunPayload(payload, DefaultLimits().RecordBytes); err == nil {
			t.Fatal("invalid marker/frame accepted")
		}
	}
	r.Coordinates = &via3.CoordinateData{}
	if _, err = encodeCompactRunRecord(r); err == nil {
		t.Fatal("extra union silently dropped")
	}
}

func TestCompactRunRetainsRawConflictsAndInheritedBytes(t *testing.T) {
	r := sparseRunParityRows()[0]
	row, err := encodeCompactRunRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{
		append([]byte(" \n"), row.data[compactRunHeader:]...),
		bytes.Replace(row.data[compactRunHeader:], []byte(`"City"`), []byte(`"city"`), 1),
	} {
		data := append(append([]byte(nil), row.data[:compactRunHeader]...), payload...)
		got, decoded, err := decodeCompactRunPayload(data, DefaultLimits().RecordBytes)
		if err != nil || !reflect.DeepEqual(decoded, r) || equalEncoded(row, got) || got.logicalBytes < row.logicalBytes {
			t.Fatal("raw JSON conflict was canonicalized or undercharged", err)
		}
	}
	r.Inherited = true
	copy, err := reencodeRunRecord(r, row)
	if err != nil || !copy.compact || copy.logicalBytes != row.logicalBytes-1 {
		t.Fatal("inherited dense budget changed", err)
	}
	_, decoded, err := decodeCompactRunPayload(copy.data, copy.logicalBytes)
	if err != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatal("inherited row changed", err)
	}
}
