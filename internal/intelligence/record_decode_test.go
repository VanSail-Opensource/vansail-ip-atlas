package intelligence

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
)

// Keep the former complete-frame decoder as an independent compatibility
// oracle. This includes v1 duplicate/member-name behavior, union validation,
// explicit UTF-8 rejection and the existing one-MiB framing limit.
func decodeRecordWithPreviousDecoder(data []byte) (NormalizedRecord, error) {
	var record NormalizedRecord
	if len(data) == 0 || len(data) > 1<<20 || !utf8.Valid(data) {
		return record, errors.New("invalid old record frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	if err := record.Validate(); err != nil {
		return record, err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return record, errors.New("old private record trailing data")
	}
	return record, nil
}

func TestPrivateRecordFrameDecoderCompatibility(t *testing.T) {
	geo := `{"Version":3,"Kind":4,"Geo":{"Family":"fixture","Weight":80,"Prefix":"2001:db8::/48","PhysicalCountry":"US","Region":"Region","City":"Café","Coordinates":{"Latitude":1.125,"Longitude":-2.25,"Precision":3},"Current":true}}`
	identity := `{"Version":3,"Kind":9,"ASNIdentity":{"ASN":13335,"Name":"Example","Current":true}}`
	cases := []struct{ name, data string }{
		{"geo-coordinates", geo},
		{"evidence", `{"Version":3,"Kind":1,"Evidence":{"Address":"1.1.1.1","SourcePublishedAt":"2026-11-15T00:00:00Z","Weight":75,"Current":true}}`},
		{"coverage", `{"Version":3,"Kind":2,"Coverage":{"Prefix":"1.1.1.0/24","PublishedAt":"2026-11-15T00:00:00Z","Current":true}}`},
		{"origins", `{"Version":3,"Kind":3,"Origins":{"Prefix":"1.1.1.0/24","Origins":[13335,13335,15169]}}`},
		{"usage", `{"Version":3,"Kind":5,"Usage":{"Prefix":"1.1.1.0/24","Evidence":{"Family":"fixture","Type":"hosting","Current":true}}}`},
		{"asn-usage", `{"Version":3,"Kind":5,"Usage":{"ASN":13335,"ObservedAt":"2026-11-15T00:00:00Z","Evidence":{"Current":true}}}`},
		{"vrp", `{"Version":3,"Kind":6,"VRP":{"Prefix":"1.1.1.0/24","MaxLength":24,"ASN":13335,"ValidUntil":"2026-11-16T00:00:00Z"}}`},
		{"path", `{"Version":3,"Kind":7,"Path":{"Prefix":"1.1.1.0/24","Observation":{"Origin":13335,"Segments":[{"Type":1,"ASNs":[13335,15169]}],"Family":"fixture","Current":true}},"MRTOriginatedAt":"2026-11-15T00:00:00Z","MRT":{"PeerTable":1,"CapturedAt":"2026-11-15T00:00:00Z"}}`},
		{"relationship", `{"Version":3,"Kind":8,"Relationship":{"From":13335,"To":15169,"Relation":1}}`},
		{"asn-identity", identity},
		{"lowercase-fields", strings.NewReplacer("Version", "version", "Kind", "kind", "Geo", "geo", "Coordinates", "coordinates").Replace(geo)},
		{"uppercase-fields", strings.NewReplacer("Version", "VERSION", "Kind", "KIND", "City", "CITY").Replace(geo)},
		{"duplicate-last-version", strings.Replace(geo, `"Version":3`, `"Version":0,"Version":3`, 1)},
		{"duplicate-case-version", strings.Replace(geo, `"Version":3`, `"VERSION":0,"version":3`, 1)},
		{"duplicate-last-city", strings.Replace(geo, `"City":"Café"`, `"City":"First","City":"Second"`, 1)},
		{"duplicate-merged-object", `{"Version":3,"Kind":4,"Geo":{"Prefix":"1.1.1.0/24","City":"First"},"Geo":{"PhysicalCountry":"US"}}`},
		{"duplicate-replaced-array", `{"Version":3,"Kind":3,"Origins":{"Prefix":"1.1.1.0/24","Origins":[13335],"Origins":[15169]}}`},
		{"empty-array", `{"Version":3,"Kind":3,"Origins":{"Prefix":"1.1.1.0/24","Origins":[]}}`},
		{"null-array", `{"Version":3,"Kind":3,"Origins":{"Prefix":"1.1.1.0/24","Origins":null}}`},
		{"null-scalar", strings.Replace(identity, `"Name":"Example"`, `"Name":null`, 1)},
		{"escaped-surrogate", strings.Replace(identity, "Example", `\ud800`, 1)},
		{"escaped-surrogate-pair", strings.Replace(identity, "Example", `\ud83d\ude00`, 1)},
		{"trailing-whitespace", geo + " \t\r\n"},
		{"unknown-member", strings.TrimSuffix(geo, "}") + `,"Unknown":1}`},
		{"unknown-nested-geo", strings.Replace(geo, `"Family":"fixture"`, `"Unknown":1,"Family":"fixture"`, 1)},
		{"unknown-nested-coordinate", strings.Replace(geo, `"Latitude":1.125`, `"Unknown":1,"Latitude":1.125`, 1)},
		{"unknown-nested-path", `{"Version":3,"Kind":7,"Path":{"Observation":{"Segments":[{"Type":1,"ASNs":[],"Unknown":true}]}}}`},
		{"trailing-object", geo + `{}`},
		{"trailing-null", geo + ` null`},
		{"trailing-garbage", geo + ` x`},
		{"truncated", strings.TrimSuffix(geo, "}")},
		{"empty", ""},
		{"null-root", "null"},
		{"array-root", "[]"},
		{"wrong-union", strings.Replace(geo, `"Kind":4`, `"Kind":3`, 1)},
		{"extra-union", strings.TrimSuffix(geo, "}") + `,"Origins":{}}`},
		{"null-union", `{"Version":3,"Kind":4,"Geo":null}`},
		{"version-overflow", strings.Replace(geo, `"Version":3`, `"Version":65536`, 1)},
		{"kind-overflow", strings.Replace(geo, `"Kind":4`, `"Kind":256`, 1)},
		{"negative-kind", strings.Replace(geo, `"Kind":4`, `"Kind":-1`, 1)},
		{"fractional-integer", strings.Replace(geo, `"Version":3`, `"Version":3.0`, 1)},
		{"exponent-integer", strings.Replace(geo, `"Version":3`, `"Version":3e0`, 1)},
		{"string-integer", strings.Replace(geo, `"Version":3`, `"Version":"3"`, 1)},
		{"float-overflow", strings.Replace(geo, "1.125", "1e1000", 1)},
		{"invalid-prefix", strings.Replace(geo, "2001:db8::/48", "invalid", 1)},
		{"invalid-time", `{"Version":3,"Kind":1,"Evidence":{"SourcePublishedAt":"invalid"}}`},
		{"invalid-usage-union", `{"Version":3,"Kind":5,"Usage":{"ASN":13335,"Prefix":"1.1.1.0/24","ObservedAt":"2026-11-15T00:00:00Z"}}`},
		{"mrt-invalid-kind", strings.TrimSuffix(geo, "}") + `,"MRTOriginatedAt":"2026-11-15T00:00:00Z"}`},
		{"invalid-utf8", strings.Replace(identity, "Example", string([]byte{0xff}), 1)},
		{"frame-at-limit", strings.Replace(identity, "Example", strings.Repeat("x", (1<<20)-len(identity)+len("Example")), 1)},
		{"frame-over-limit", strings.Replace(identity, "Example", strings.Repeat("x", (1<<20)-len(identity)+len("Example")+1), 1)},
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(1<<20), zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(test.data)
			want, oldErr := decodeRecordWithPreviousDecoder(data)
			raw := binary.LittleEndian.AppendUint32([]byte(recordHeader), uint32(len(data)))
			raw = append(raw, data...)
			for _, compressed := range []bool{false, true} {
				root := t.TempDir()
				encoded := raw
				descriptor := RecordPartition{Records: 1}
				if compressed {
					encoded = append([]byte(compressedRecordHeader), encoder.EncodeAll(raw, nil)...)
					descriptor.Codec, descriptor.DecodedBytes = "zstd-v1", int64(len(raw))
				}
				part := putRecordFixture(t, root, encoded, descriptor)
				var got []NormalizedRecord
				err := WalkStoredSource(context.Background(), root, StoredSource{RecordPartitions: []RecordPartition{part}}, func(record NormalizedRecord) error {
					got = append(got, record)
					return nil
				})
				if (err == nil) != (oldErr == nil) {
					t.Fatalf("compressed=%t acceptance differs: old=%v, new=%v", compressed, oldErr, err)
				}
				if oldErr == nil && (len(got) != 1 || !reflect.DeepEqual(got[0], want)) {
					t.Fatalf("compressed=%t decoded record differs from previous decoder", compressed)
				}
				if oldErr != nil && len(got) != 0 {
					t.Fatalf("compressed=%t invalid frame reached the sink", compressed)
				}
			}
		})
	}
}
