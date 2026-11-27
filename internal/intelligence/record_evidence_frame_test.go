package intelligence

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"
)

func ordinaryEvidenceFrame(data []byte) (NormalizedRecord, error) {
	var record NormalizedRecord
	if err := jsonv2.Unmarshal(data, &record, json.DefaultOptionsV1(), jsonv2.RejectUnknownMembers(true)); err != nil {
		return record, err
	}
	return record, record.Validate()
}

func testExactFrame(tb testing.TB, evidence Evidence) []byte {
	tb.Helper()
	data, err := json.Marshal(NormalizedRecord{Version: 3, Kind: RecordEvidence, Evidence: &evidence})
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestWriterExactEvidenceMatchesStrictDecode(t *testing.T) {
	stamp := time.Date(2026, 11, 16, 9, 10, 11, 0, time.UTC)
	for _, address := range []string{"192.0.2.1", "2001:db8::0201", "::ffff:192.0.2.1"} {
		for _, published := range []time.Time{{}, stamp, stamp.Add(-time.Hour)} {
			for _, weight := range []float64{math.Copysign(0, -1), 0, 3.891, 67.111111111111, 100} {
				for _, literal := range []bool{false, true} {
					x := Evidence{Family: "independent-fixture", Signal: "cloudflare_proxyip", Address: netip.MustParseAddr(address), Current: true,
						SourcePublishedAt: stamp, ItemPublishedAt: published, Weight: weight, SubscriptionLiteral: literal}
					data := testExactFrame(t, x)
					want, err := ordinaryEvidenceFrame(data)
					if err != nil {
						t.Fatal(err)
					}
					got, ok := decodeWriterExactEvidence(data)
					if !ok || math.Float64bits(got.Weight) != math.Float64bits(want.Evidence.Weight) || !reflect.DeepEqual(got, want.Evidence) {
						t.Fatal("writer fixture did not match the complete strict decoder")
					}
					clear(data)
					if !reflect.DeepEqual(got, want.Evidence) {
						t.Fatal("decoded evidence retained recycled frame memory")
					}
				}
			}
		}
	}
}

func TestWriterExactEvidenceRetainsStrictFallback(t *testing.T) {
	e := Evidence{Family: "fixture", Signal: "proxy", Address: netip.MustParseAddr("192.0.2.1"), Current: true, Weight: 67,
		SourcePublishedAt: time.Date(2026, 11, 16, 9, 10, 11, 0, time.UTC)}
	valid := testExactFrame(t, e)
	for label, edit := range map[string][2]string{
		"unfamiliar spelling": {`"Scope":0`, `"scope":0`},
		"escaped family":      {`"fixture"`, `"f\u0069xture"`},
		"fractional clock":    {`11Z"`, `11.01Z"`},
		"noncurrent evidence": {`"Current":true`, `"Current":false`},
		"canonical fallback":  {`"Weight":67`, `"Weight":6.7e1`},
		"duplicate member":    {`"Weight":67`, `"Weight":67,"Weight":75`},
		"unknown member":      {`"Weight":67`, `"Weight":67,"Unexpected":0`},
		"bad number":          {`"Weight":67`, `"Weight":067`},
		"out-of-range number": {`"Weight":67`, `"Weight":1e999`},
		"wrong type":          {`"Weight":67`, `"Weight":"67"`},
		"invalid clock":       {`11Z"`, `99Z"`},
		"zoned address":       {`"192.0.2.1"`, `"fe80::1%zone"`},
		"cross-union member":  {`}}`, `},"Origins":{}}`},
		"trailing content":    {`}}`, `}} {}`},
	} {
		t.Run(label, func(t *testing.T) {
			data := bytes.Replace(valid, []byte(edit[0]), []byte(edit[1]), 1)
			if _, ok := decodeWriterExactEvidence(data); ok {
				t.Fatal("frame did not defer to the general decoder")
			}
			want, wantErr := ordinaryEvidenceFrame(data)
			got, gotErr := decodeRecordFrame(data)
			if (wantErr == nil) != (gotErr == nil) || gotErr == nil && !reflect.DeepEqual(got, want) {
				t.Fatal("record decoder changed strict fallback behavior", gotErr, wantErr)
			}
		})
	}
	if _, err := decodeRecordFrame(bytes.Replace(valid, []byte("fixture"), []byte{0xff}, 1)); err == nil {
		t.Fatal("invalid UTF-8 reached the typed reader")
	}
}

func FuzzWriterExactEvidenceParity(f *testing.F) {
	e := Evidence{Family: "fixture", Signal: "proxy", Address: netip.MustParseAddr("192.0.2.1"), Current: true, Weight: 67,
		SourcePublishedAt: time.Date(2026, 11, 16, 9, 10, 11, 0, time.UTC)}
	f.Add(testExactFrame(f, e))
	e.Address, e.SubscriptionLiteral, e.ItemPublishedAt = netip.MustParseAddr("2001:db8::1"), true, e.SourcePublishedAt.Add(-2*time.Hour)
	f.Add(testExactFrame(f, e))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 || !utf8.Valid(data) {
			return
		}
		got, ok := decodeWriterExactEvidence(data)
		if !ok {
			return
		}
		want, err := ordinaryEvidenceFrame(data)
		if err != nil || math.Float64bits(got.Weight) != math.Float64bits(want.Evidence.Weight) || !reflect.DeepEqual(got, want.Evidence) {
			t.Fatal("typed reader accepted different evidence", err)
		}
	})
}

func BenchmarkWriterExactEvidence(b *testing.B) {
	frames := make([][]byte, 512)
	stamp := time.Date(2026, 11, 16, 9, 10, 11, 0, time.UTC)
	for i := range frames {
		address := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		if i%4 == 0 {
			address = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
		}
		x := Evidence{Family: "independent-fixture", Signal: []Signal{"abuse", "malware", "proxy", "scanner"}[i%4], Address: address, Current: true, Weight: 67, SourcePublishedAt: stamp}
		if i%3 == 0 {
			x.ItemPublishedAt = stamp.Add(-time.Duration(i) * time.Second)
		}
		frames[i] = testExactFrame(b, x)
	}
	for _, tc := range []struct {
		name string
		run  func([]byte) (NormalizedRecord, error)
	}{{"strict-json", ordinaryEvidenceFrame}, {"record-decoder", decodeRecordFrame}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				r, err := tc.run(frames[i%len(frames)])
				if err != nil || !r.Evidence.Current {
					b.Fatal("record not decoded", err)
				}
				i++
			}
		})
	}
}
