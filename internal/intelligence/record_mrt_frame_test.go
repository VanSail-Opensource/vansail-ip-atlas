package intelligence

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func writerMRTRows() []NormalizedRecord {
	when := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	mrt := &MRTRouteIdentity{PeerIndex: 65535, PeerTable: 3, CapturedAt: when}
	for i := range mrt.PeerKey {
		mrt.PeerKey[i] = byte(255 - i)
	}
	prefix := netip.MustParsePrefix("2001:db8::/32")
	rows := []NormalizedRecord{
		{Version: 3, Kind: RecordOrigins, Origins: &OriginMapping{Prefix: prefix, Origins: []uint32{4294967295}}, MRTOriginatedAt: &when, MRT: mrt},
		{Version: 3, Kind: RecordPath, Path: &ScopedPath{Prefix: prefix, Observation: PathObservation{Origin: 33445, Family: "example", Current: true, Segments: []PathSegment{{Type: ASSequence, ASNs: []uint32{1, 2, 33445}}}}}, MRTOriginatedAt: &when, MRT: mrt},
	}
	for _, original := range rows {
		original.MRT, original.MRTOriginatedAt = nil, nil
		rows = append(rows, original)
	}
	return append(rows,
		NormalizedRecord{Version: 3, Kind: RecordVRP, VRP: &VRP{Prefix: prefix, MaxLength: 48, ASN: 13335, ValidUntil: when}},
		NormalizedRecord{Version: 3, Kind: RecordVRP, VRP: &VRP{Prefix: prefix, MaxLength: 64, ASN: 13335}},
	)
}

func TestWriterMRTRouteFramesMatchStrictDecoder(t *testing.T) {
	for _, expected := range writerMRTRows() {
		data, err := json.Marshal(expected)
		if err != nil {
			t.Fatal(err)
		}
		owned := bytes.Clone(data)
		actual, ok := decodeWriterRouting(owned)
		clear(owned)
		if !ok || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("writer frame failed independent ownership or exact decoding: %v", ok)
		}
		verifyRecordFrame(t, data)
		for n := range len(data) {
			verifyRecordFrame(t, data[:n])
			mutated := bytes.Clone(data)
			mutated[n] ^= 1
			verifyRecordFrame(t, mutated)
		}
		for _, pair := range [][2]string{
			{"[255,254,253", "[256,254,253"}, {"[255,254,253", "[255,253"},
			{"[255,254,253", "[255,254,253,0"}, {"65535", "65536"}, {"65535", "00"},
			{"65535", "-1"}, {"65535", "429496729600"}, {"65535", "1.0"}, {"65535", "1e+4"},
			{`"PeerTable":3`, `"PeerTable":3,"PeerTable":1`}, {`"PeerTable":3`, `"PeerTable":0`},
			{`"PathID":0`, `"PathID":1`}, {`"AddPath":false`, `"AddPath":true`},
			{`"PeerAmbiguous":false`, `"PeerAmbiguous":true`}, {`"Family":"example"`, `"Family":"exam\u0070le"`},
			{"08:00:00Z", "08:00:00.01Z"}, {"08:00:00Z", "08:00:00+01:00"}, {"08:00:00Z", "28:00:00Z"},
			{`"Origins":[4294967295]`, `"Origins":[1,2]`}, {`"Type":1`, `"Type":2`},
			{`"ASNs":[1,2,33445]`, `"ASNs":[]`}, {`"ASNs":[1,2,33445]`, `"ASNs":null`},
			{"2001:db8::/32", ""}, {"}}", `,"unknown":true}}`},
			{`"MaxLength":48`, `"MaxLength":256`}, {`"ASN":13335`, `"ASN":4294967296`},
			{`"ASN":13335`, `"ASN":0e0`}, {`"ValidUntil":`, `"XUnknown":`},
		} {
			verifyRecordFrame(t, bytes.Replace(data, []byte(pair[0]), []byte(pair[1]), 1))
		}
	}
}

func FuzzWriterMRTRouteFrameParity(f *testing.F) {
	for _, row := range writerMRTRows() {
		data, err := json.Marshal(row)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8192 {
			verifyRecordFrame(t, data)
		}
	})
}

func TestCanonicalRoutingWriterComparison(t *testing.T) {
	rows := writerMRTRows()[2:]
	for _, p := range []string{"203.0.113.128/24", "2001:0db8:1:2::/32", "::ffff:192.0.2.0/120"} {
		for _, values := range [][]uint32{nil, {}, {1}, {1, 2, 4294967295}} {
			rows = append(rows, NormalizedRecord{Version: 3, Kind: RecordOrigins, Origins: &OriginMapping{Prefix: netip.MustParsePrefix(p), Origins: values}})
		}
	}
	for _, row := range rows {
		data, err := json.Marshal(row)
		if err != nil || !canonicalWriterRouting(data, row) {
			t.Fatalf("did not recognize normalized writer output %s: %v", data, err)
		}
		for _, change := range [][2]string{
			{`{"Version":3,`, `{"Version":3, `}, {`{"Version":3,`, `{"Version":3,"Version":3,`},
			{`"Kind":3`, `"kind":3`}, {`2001:db8::`, `2001:0db8::`}, {`08:00:00Z`, `08:00:00+00:00`},
			{`08:00:00Z`, `08:00:00.0Z`}, {`"Family":"example"`, `"Family":"exam\u0070le"`},
		} {
			altered := bytes.Replace(data, []byte(change[0]), []byte(change[1]), 1)
			if !bytes.Equal(data, altered) && canonicalWriterRouting(altered, row) {
				t.Fatalf("accepted noncanonical writer output %s", altered)
			}
		}
	}
	for _, row := range writerMRTRows()[:2] {
		data, err := json.Marshal(row)
		if err != nil || canonicalWriterRouting(data, row) {
			t.Fatal("private MRT identity should use the standard writer", err)
		}
	}
}

func FuzzCanonicalRoutingWriterComparison(f *testing.F) {
	for _, row := range writerMRTRows() {
		data, err := json.Marshal(row)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		r, err := decodeRecordFrame(data)
		if err != nil || !canonicalWriterRouting(data, r) {
			return
		}
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(canonical, data) {
			t.Fatal("accepted bytes differ from standard writer")
		}
	})
}

func BenchmarkCanonicalRoutingWriterComparison(b *testing.B) {
	rows := writerMRTRows()[2:]
	data := make([][]byte, len(rows))
	for i, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			b.Fatal(err)
		}
		data[i] = encoded
	}
	b.Run("exact-shape", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			j := i % len(rows)
			if !canonicalWriterRouting(data[j], rows[j]) {
				b.Fatal("writer comparison failed")
			}
		}
	})
	b.Run("generic-json", func(b *testing.B) {
		b.ReportAllocs()
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		for i := 0; b.Loop(); i++ {
			j := i % len(rows)
			buffer.Reset()
			if err := encoder.Encode(rows[j]); err != nil || !bytes.Equal(data[j], buffer.Bytes()[:buffer.Len()-1]) {
				b.Fatal("writer comparison failed", err)
			}
		}
	})
}
