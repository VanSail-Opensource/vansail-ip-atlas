package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestDirectFrameDecodePreservesStrictStreamSemantics(t *testing.T) {
	var cases [][]byte
	for _, row := range fusedFixture() {
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, data, append(append([]byte(" \n"), data...), '\t'))
	}
	for _, data := range []string{
		`null`,
		`{"version":3,"kind":2,"geo":{"Country":"US"}}`,
		`{"Version":3,"Kind":2,"Geo":{"Country":"US"},"Geo":{"City":"Merged"}}`,
		`{"Version":3,"Version":2,"Kind":2}`,
		`{"Version":65536,"Kind":2}`,
		`{"Version":3,"Kind":2,"unexpected":true}`,
		`{"Version":3,"Kind":2,"Geo":{"Country":"US","unexpected":true}}`,
		`{"Version":3,"Kind":2} {}`,
		`{"Version":3,"Kind":2} null`,
		`{"Version":3,"Kind":2`,
		`{"Version":3,"Kind":2,"Geo":{"City":"bad` + string([]byte{0xff}) + `byte"}}`,
	} {
		cases = append(cases, []byte(data))
	}
	for i, data := range cases {
		var old via3.PublicRecord
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		oldErr := d.Decode(&old)
		if oldErr == nil {
			if err := d.Decode(new(json.RawMessage)); err != io.EOF {
				oldErr = io.ErrUnexpectedEOF
			}
		}
		got, err := decode(data)
		if (err == nil) != (oldErr == nil) || err == nil && !reflect.DeepEqual(got, old) {
			t.Fatalf("frame %d changed decoding: got %+v/%v, previous %+v/%v", i, got, err, old, oldErr)
		}
	}
}

func TestRunReaderRetainsIndependentValidatedRecord(t *testing.T) {
	rows := []via3.PublicRecord{
		{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("8.8.8.0/24"), Geo: &via3.GeoData{Country: "US", City: "First"}},
		{Version: 3, Kind: 5, Prefix: netip.MustParsePrefix("9.9.9.0/24"), Usage: &via3.UsageData{}},
	}
	var frames bytes.Buffer
	for _, row := range rows {
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&frames, binary.LittleEndian, uint32(len(data))); err != nil {
			t.Fatal(err)
		}
		frames.Write(data)
	}
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, frames.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := openRun(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer r.file.Close()
	if err := r.next(); err != nil {
		t.Fatal(err)
	}
	first := r.record
	firstFrame := r.row.data
	if r.row.key != identity(first) || first.Geo == nil || first.Geo.City != "First" {
		t.Fatal("reader did not retain its validated record")
	}
	if err := r.next(); err != nil {
		t.Fatal(err)
	}
	if r.record.Geo != nil || r.record.Usage == nil || r.row.key != identity(r.record) || first.Geo.City != "First" || first.Prefix != rows[0].Prefix {
		t.Fatal("next frame reused or contaminated the retained record")
	}
	decoded, err := decode(firstFrame)
	if err != nil || decoded.Geo == nil || decoded.Geo.City != "First" {
		t.Fatal("next frame reused retained bytes", err)
	}
	if err := r.next(); err != io.EOF {
		t.Fatal("unexpected trailing frame", err)
	}
}

func TestRunReaderRejectsMalformedFrameBeforeReuse(t *testing.T) {
	for _, data := range []string{
		`{"version":3,"kind":2,"unexpected":true}`,
		`{"version":3,"kind":2} {}`,
		`{"version":3,"kind":2`,
	} {
		var frames bytes.Buffer
		if err := binary.Write(&frames, binary.LittleEndian, uint32(len(data))); err != nil {
			t.Fatal(err)
		}
		frames.WriteString(data)
		path := filepath.Join(t.TempDir(), "run")
		if err := os.WriteFile(path, frames.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := openRun(path, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.next(); err == nil {
			t.Fatalf("invalid private frame accepted: %s", data)
		}
		r.file.Close()
	}
}

func TestSplitSkipsOnlyProvenEmptyScopes(t *testing.T) {
	geo := func(prefix string) via3.PublicRecord {
		return via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(prefix), Geo: &via3.GeoData{Country: "US"}}
	}
	asn := func(n uint32) via3.PublicRecord {
		return via3.PublicRecord{Version: 3, Kind: 8, ASN: n, ASNAggregate: &via3.ASNData{Name: "Network"}}
	}
	for _, tc := range []struct {
		name string
		root scope
		rows []via3.PublicRecord
		want [2]scope
	}{
		{"IPv4 cluster", scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}, []via3.PublicRecord{geo("8.8.0.0/24"), geo("8.8.1.0/24")}, [2]scope{{prefix: netip.MustParsePrefix("8.8.0.0/23")}, {prefix: netip.MustParsePrefix("128.0.0.0/1")}}},
		{"IPv4 cell ceiling", scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}, []via3.PublicRecord{geo("8.8.8.1/32"), geo("8.8.8.2/32")}, [2]scope{{prefix: netip.MustParsePrefix("8.8.8.0/24")}, {prefix: netip.MustParsePrefix("128.0.0.0/1")}}},
		{"IPv6 cluster", scope{prefix: netip.MustParsePrefix("::/0")}, []via3.PublicRecord{geo("2001:db8::/48"), geo("2001:db8:1::/48")}, [2]scope{{prefix: netip.MustParsePrefix("2001:db8::/47")}, {prefix: netip.MustParsePrefix("8000::/1")}}},
		{"ASN cluster", scope{asn: true, first: 0, last: ^uint32(0)}, []via3.PublicRecord{asn(64500), asn(64501)}, [2]scope{{asn: true, first: 64500, last: 64501}, {asn: true, first: 1 << 31, last: ^uint32(0)}}},
		{"ancestor coverage", scope{prefix: netip.MustParsePrefix("8.0.0.0/8")}, []via3.PublicRecord{geo("8.0.0.0/8"), geo("8.8.8.0/24")}, [2]scope{{prefix: netip.MustParsePrefix("8.0.0.0/9")}, {prefix: netip.MustParsePrefix("8.128.0.0/9")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}, scratch: t.TempDir()}
			path := c.next()
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range tc.rows {
				data, err := json.Marshal(row)
				if err != nil {
					t.Fatal(err)
				}
				if err := c.writeRecord(file, data); err != nil {
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			left, right, err := tc.root.children()
			if err != nil {
				t.Fatal(err)
			}
			scopes := [2]scope{left, right}
			paths, err := c.split(path, &scopes)
			if err != nil {
				t.Fatal(err)
			}
			if scopes != tc.want {
				t.Fatalf("unexpected scopes: got %+v, want %+v", scopes, tc.want)
			}
			counts := [2]int{}
			for i, path := range paths {
				if path == "" {
					continue
				}
				r, err := openRun(path, c.options.Limits.RecordBytes)
				if err != nil {
					t.Fatal(err)
				}
				var measured partitionSize
				for {
					if err := r.next(); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					counts[i]++
					measured.records++
					measured.bytes += r.row.logicalBytes + 512
					if tc.name == "ancestor coverage" && r.record.Prefix == tc.root.prefix && !r.record.Inherited {
						t.Fatal("broad prefix lost inherited coverage")
					}
				}
				r.file.Close()
				if c.partitionSizes[path] != measured {
					t.Fatalf("split totals differ from completed frames: got %+v, want %+v", c.partitionSizes[path], measured)
				}
				if err := c.remove(path); err != nil {
					t.Fatal(err)
				}
				if _, ok := c.partitionSizes[path]; ok {
					t.Fatal("removed run retained totals")
				}
			}
			wantCounts := [2]int{2, 0}
			if tc.name == "ancestor coverage" {
				wantCounts = [2]int{2, 1}
			}
			if counts != wantCounts {
				t.Fatal("split lost or duplicated rows", counts)
			}
		})
	}
}

func TestClassifyTotalsMatchCompletedFrames(t *testing.T) {
	c := &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}, scratch: t.TempDir()}
	runs, err := c.sort(producer(fusedFixture()))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := c.merge(runs)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := c.classify(merged)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if path == "" {
			t.Fatal("fixture must cover IPv4, IPv6 and ASN runs")
		}
		r, err := openRun(path, c.options.Limits.RecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		var measured partitionSize
		for {
			if err := r.next(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			measured.records++
			measured.bytes += r.row.logicalBytes + 512
		}
		r.file.Close()
		if c.partitionSizes[path] != measured {
			t.Fatalf("classification totals differ from completed frames: got %+v, want %+v", c.partitionSizes[path], measured)
		}
	}
}

func TestPartitionTotalsNeverBypassFrameOrLeafValidation(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		limits := DefaultLimits()
		limits.PartitionRecords = 1
		c := &compiler{ctx: context.Background(), options: Options{Limits: limits}, scratch: t.TempDir()}
		path := c.next()
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if malformed {
			if err := c.writeRecord(file, []byte(`{"Version":3,"Kind":2,"unexpected":true}`)); err != nil {
				t.Fatal(err)
			}
			// The known oversized path must still strictly decode its frames
			// during splitting before it can create an accepted child.
			c.rememberPartitionSize(path, partitionSize{records: 2})
		} else {
			for _, country := range []string{"US", "DE"} {
				data, err := json.Marshal(via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("8.8.8.0/24"), Geo: &via3.GeoData{Country: country}})
				if err != nil {
					t.Fatal(err)
				}
				if err := c.writeRecord(file, data); err != nil {
					t.Fatal(err)
				}
			}
			// A missing or underestimated total cannot admit an oversized
			// indivisible leaf; the ordinary record/byte scan still applies.
			c.rememberPartitionSize(path, partitionSize{records: 1})
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := c.partition(path, scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}); err == nil {
			t.Fatalf("partition totals bypassed validation; malformed=%t", malformed)
		}
	}
}
