package admission

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"

	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func ipapiTestSource(v6 bool) Source {
	s := bulkSource("city-range-csv", "dbip-city-eight-columns-v1")
	s.ID = "unit-ipapi"
	s.Format = "zip"
	s.MaxCompressedBytes = 1 << 20
	s.MaxAge = 720 * time.Hour
	s.Parser = Parser{"ipapi-free-city-csv", ipapiCSVSchema, 1}
	s.URL = "https://ipapi.is/data/geolocationDatabaseIPv4.csv.zip"
	if v6 {
		s.URL = "https://ipapi.is/data/geolocationDatabaseIPv6.csv.zip"
	}
	s.Publication = Publication{"embedded", s.URL, "zip.csv.extended_timestamp"}
	return s
}
func dbipTestSource() Source {
	s := bulkSource("city-range-csv", "dbip-city-eight-columns-v1")
	s.ID = "unit-dbip"
	s.Format = "csv-gz"
	s.MaxCompressedBytes = 1 << 20
	s.MaxAge = 720 * time.Hour
	s.Publication = Publication{"snapshot_metadata", dbipPublisherPage, "csv.sha1-md5.month"}
	return s
}
func ipapiTestRow(accuracy string) string {
	return "4,8.8.8.0,8.8.8.255,NA,US,United States,Example,City,private-postal,private-zone,37.1,-122.2," + accuracy + ",private-provider"
}

func TestIPAPIFreeCSVContract(t *testing.T) {
	for _, accuracy := range []string{"1", "2", "3", "4", "5"} {
		t.Run(accuracy, func(t *testing.T) {
			var rows []intelligence.NormalizedRecord
			s := ipapiTestSource(false)
			stats, err := parseIPAPIFreeCSVStats(context.Background(), strings.NewReader(ipapiHeader+"\n"+ipapiTestRow(accuracy)+"\n"), s, 100, func(r intelligence.NormalizedRecord) error { rows = append(rows, r); return r.Validate() })
			if err != nil || len(rows) != 1 || stats.Rows != 1 {
				t.Fatal(stats, rows, err)
			}
			g := rows[0].Geo
			if g.PhysicalCountry != "US" || g.Family != s.Family || g.Prefix.String() != "8.8.8.0/24" {
				t.Fatal(g)
			}
			if accuracy <= "2" {
				if g.City != "City" || g.Region != "Example" || g.Coordinates == nil || g.Coordinates.Precision != 3 {
					t.Fatal(g)
				}
			} else if g.City != "" || g.Coordinates != nil || accuracy >= "4" && g.Region != "" {
				t.Fatal("publisher uncertainty overstated", g)
			}
			data, _ := json.Marshal(rows)
			for _, forbidden := range []string{"private-postal", "private-zone", "private-provider", "continent", "timezone", "zip"} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Fatal("discarded column retained")
				}
			}
		})
	}
}
func TestIPAPIFreeCSVRejectsMalformedAndBoundedInputs(t *testing.T) {
	base := ipapiTestRow("1")
	for _, row := range []string{strings.Replace(base, "4,8.8.8.0", "6,8.8.8.0", 1), strings.Replace(base, "8.8.8.255", "2001:4860::1", 1), strings.Replace(base, "8.8.8.255", "8.8.7.255", 1), strings.Replace(base, ",US,", ",USA,", 1), strings.Replace(base, ",37.1,", ",NaN,", 1), strings.Replace(base, ",37.1,", ",91,", 1), strings.Replace(base, ",1,private-provider", ",0,private-provider", 1), strings.Replace(base, ",City,", ",\xff,", 1), "\"unterminated" + strings.Repeat("x", 1<<20)} {
		if err := parseIPAPIFreeCSV(context.Background(), strings.NewReader(ipapiHeader+"\n"+row+"\n"), ipapiTestSource(false), 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
			t.Fatal("accepted malformed row")
		}
	}
	if err := parseIPAPIFreeCSV(context.Background(), strings.NewReader(ipapiHeader+"\n"+base+"\n"+base+"\n"), ipapiTestSource(false), 1, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
		t.Fatal("row bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parseIPAPIFreeCSV(ctx, strings.NewReader(ipapiHeader+"\n"+base+"\n"), ipapiTestSource(false), 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
		t.Fatal("cancellation ignored")
	}
	s := ipapiTestSource(true)
	v6 := strings.ReplaceAll(base, "4,8.8.8.0,8.8.8.255", "6,2001:4860::,2001:4860::ffff")
	if err := parseIPAPIFreeCSV(context.Background(), strings.NewReader(ipapiHeader+"\n"+v6+"\n"), s, 100, func(r intelligence.NormalizedRecord) error {
		if r.Geo.Prefix.String() != "2001:4860::/112" {
			t.Fatal(r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func dbipTestPage(csv []byte, month time.Time) []byte {
	a, b := sha1.Sum(csv), md5.Sum(csv)
	return []byte(fmt.Sprintf(`<dl><dt>Format</dt><dd>CSV</dd><dt>Release</dt><dd>%s</dd><dt>Number of records</dt><dd>1</dd><dt>SHA1SUM</dt><dd>%x</dd><dt>MD5SUM</dt><dd>%x</dd></dl><a href="https://download.db-ip.com/free/dbip-city-lite-%s.csv.gz">Download</a>`, month.Format("January 2006"), a, b, month.Format("2006-01")))
}
func geoTestFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "capture")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func TestDBIPPublisherPageAndPayloadBinding(t *testing.T) {
	csv := []byte("8.8.8.0,8.8.8.255,NA,US,Example,City,37.1,-122.2\n")
	month := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	page := dbipTestPage(csv, month)
	plan, err := resolveDBIPMonthlyPage(page, month.Add(200*time.Hour))
	if err != nil || !plan.Published.Equal(month) {
		t.Fatal(plan, err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(csv)
	gz.Close()
	proof, err := verifyDBIPGzip(context.Background(), geoTestFile(t, compressed.Bytes()), int64(compressed.Len()), dbipTestSource(), plan)
	if err != nil || proof.DecodedSHA256 != sha256.Sum256(csv) || proof.PageSHA256 != sha256.Sum256(page) || proof.DecodedBytes != int64(len(csv)) {
		t.Fatal(proof, err)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), page...), page...), bytes.Replace(page, []byte("2026-11.csv.gz"), []byte("2026-10.csv.gz"), 1), bytes.Replace(page, []byte("<dd>1</dd>"), []byte("<dd>1</dd><dt>Format</dt><dd>CSV</dd>"), 1), bytes.Replace(page, []byte("https://download.db-ip.com"), []byte("https://example.invalid"), 1)} {
		if _, err := resolveDBIPMonthlyPage(bad, month.Add(200*time.Hour)); err == nil {
			t.Fatal("ambiguous/unbound discovery accepted")
		}
	}
	plan.Rows++
	if _, err := verifyDBIPGzip(context.Background(), geoTestFile(t, compressed.Bytes()), int64(compressed.Len()), dbipTestSource(), plan); err == nil {
		t.Fatal("publisher row count not enforced")
	}
	plan.Rows--
	plan.SHA1[0] ^= 1
	if _, err := verifyDBIPGzip(context.Background(), geoTestFile(t, compressed.Bytes()), int64(compressed.Len()), dbipTestSource(), plan); err == nil {
		t.Fatal("publisher checksum not enforced")
	}
	next := dbipTestPage(csv, month.AddDate(0, 1, 0))
	if plan, err := resolveDBIPMonthlyPage(next, month.AddDate(0, 1, 8)); err != nil || !strings.Contains(plan.AssetURL, "2026-12") {
		t.Fatal("monthly resolver pinned old URL", plan, err)
	}
}

// This small ZIP uses the exact observed container structure: stored data,
// complete local headers and distinct UTC timestamp extras, without descriptors.
func ipapiTestZIP(t *testing.T, csv, notice []byte, published time.Time) []byte {
	t.Helper()
	var out bytes.Buffer
	type entry struct {
		name   string
		data   []byte
		offset uint32
		crc    uint32
	}
	entries := []entry{{name: "geolocationDatabaseIPv4.csv", data: csv}, {name: ipapiNoticeName, data: notice}}
	wall := published.Add(2 * time.Hour)
	date := uint16(wall.Year()-1980)<<9 | uint16(wall.Month())<<5 | uint16(wall.Day())
	clock := uint16(wall.Hour())<<11 | uint16(wall.Minute())<<5 | uint16(wall.Second()/2)
	extra := func(local bool) []byte {
		size := 5
		if local {
			size = 9
		}
		b := make([]byte, 4+size)
		binary.LittleEndian.PutUint16(b, 0x5455)
		binary.LittleEndian.PutUint16(b[2:], uint16(size))
		b[4] = 3
		binary.LittleEndian.PutUint32(b[5:], uint32(published.Unix()))
		if local {
			binary.LittleEndian.PutUint32(b[9:], uint32(published.Unix()))
		}
		return b
	}
	for i := range entries {
		v := &entries[i]
		v.offset = uint32(out.Len())
		v.crc = crc32.ChecksumIEEE(v.data)
		h := make([]byte, 30)
		binary.LittleEndian.PutUint32(h, 0x04034b50)
		binary.LittleEndian.PutUint16(h[4:], 20)
		binary.LittleEndian.PutUint16(h[10:], clock)
		binary.LittleEndian.PutUint16(h[12:], date)
		binary.LittleEndian.PutUint32(h[14:], v.crc)
		binary.LittleEndian.PutUint32(h[18:], uint32(len(v.data)))
		binary.LittleEndian.PutUint32(h[22:], uint32(len(v.data)))
		binary.LittleEndian.PutUint16(h[26:], uint16(len(v.name)))
		binary.LittleEndian.PutUint16(h[28:], uint16(len(extra(true))))
		out.Write(h)
		out.WriteString(v.name)
		out.Write(extra(true))
		out.Write(v.data)
	}
	directory := out.Len()
	for _, v := range entries {
		h := make([]byte, 46)
		binary.LittleEndian.PutUint32(h, 0x02014b50)
		binary.LittleEndian.PutUint16(h[4:], 20)
		binary.LittleEndian.PutUint16(h[6:], 20)
		binary.LittleEndian.PutUint16(h[12:], clock)
		binary.LittleEndian.PutUint16(h[14:], date)
		binary.LittleEndian.PutUint32(h[16:], v.crc)
		binary.LittleEndian.PutUint32(h[20:], uint32(len(v.data)))
		binary.LittleEndian.PutUint32(h[24:], uint32(len(v.data)))
		binary.LittleEndian.PutUint16(h[28:], uint16(len(v.name)))
		binary.LittleEndian.PutUint16(h[30:], uint16(len(extra(false))))
		binary.LittleEndian.PutUint32(h[42:], v.offset)
		out.Write(h)
		out.WriteString(v.name)
		out.Write(extra(false))
	}
	h := make([]byte, 22)
	binary.LittleEndian.PutUint32(h, 0x06054b50)
	binary.LittleEndian.PutUint16(h[8:], 2)
	binary.LittleEndian.PutUint16(h[10:], 2)
	binary.LittleEndian.PutUint32(h[12:], uint32(out.Len()-directory))
	binary.LittleEndian.PutUint32(h[16:], uint32(directory))
	out.Write(h)
	return out.Bytes()
}
func TestIPAPIZIPUTCClockCRCAndNotice(t *testing.T) {
	notice, err := os.ReadFile("testdata/ipapi-free-license.txt")
	if err != nil {
		t.Fatal(err)
	}
	if hashString(sha256.Sum256(notice)) != approvedIPAPINoticeSHA256 {
		t.Fatal("invalid test hash")
	}
	csv := []byte(ipapiHeader + "\n" + ipapiTestRow("1") + "\n")
	clock := time.Date(2026, 10, 19, 1, 32, 23, 0, time.UTC)
	data := ipapiTestZIP(t, csv, notice, clock)
	source := ipapiTestSource(false)
	f := geoTestFile(t, data)
	proof, err := verifyIPAPIArchive(context.Background(), f, int64(len(data)), source, clock.Add(500*time.Hour))
	if err != nil || !proof.UpstreamClock.Equal(clock) || proof.DecodedSHA256 != sha256.Sum256(csv) || proof.LicenseSHA256 != sha256.Sum256(notice) {
		t.Fatal(proof, err)
	}
	rows := 0
	if err := parseIPAPIArchive(context.Background(), geoTestFile(t, data), int64(len(data)), source, 100, func(r intelligence.NormalizedRecord) error { rows++; return r.Validate() }); err != nil || rows != 1 {
		t.Fatal(rows, err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{{"CRC", func(b []byte) []byte { at := bytes.Index(b, csv); b[at] ^= 1; return b }}, {"DOS-only", func(b []byte) []byte {
		for at := 0; at+4 < len(b); at++ {
			if binary.LittleEndian.Uint16(b[at:]) == 0x5455 {
				b[at] = 0x56
			}
		}
		return b
	}}, {"UTC-mismatch", func(b []byte) []byte { at := bytes.Index(b, []byte{0x55, 0x54, 9, 0, 3}); b[at+5]++; return b }}, {"local-name", func(b []byte) []byte { b[30] = 'x'; return b }}, {"truncated", func(b []byte) []byte { return b[:len(b)-1] }}, {"unexpected-member", func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte(ipapiNoticeName), []byte(strings.Repeat("x", len(ipapiNoticeName))))
	}}} {
		t.Run(test.name, func(t *testing.T) {
			bad := test.mutate(append([]byte(nil), data...))
			if _, err := verifyIPAPIArchive(context.Background(), geoTestFile(t, bad), int64(len(bad)), source, clock.Add(500*time.Hour)); err == nil {
				t.Fatal("unverified archive accepted")
			}
		})
	}
	bad := ipapiTestZIP(t, csv, append(notice, 'x'), clock)
	if _, err := verifyIPAPIArchive(context.Background(), geoTestFile(t, bad), int64(len(bad)), source, clock.Add(500*time.Hour)); err == nil {
		t.Fatal("changed rights notice accepted")
	}
}

func certifyGeoTestSource(t *testing.T, engine *Engine, source Source) {
	t.Helper()
	implementation, err := implementationHash(context.Background(), engine.workspace)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, source.Parser.Version, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(implementation)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engine.workspace, "fixtures", "source-certification", "adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestIPAPIIntakeDecodedReplayExpiryAndWithdrawal(t *testing.T) {
	csv := []byte(ipapiHeader + "\n" + ipapiTestRow("1") + "\n")
	engine, original, fetch, now, policyHash := prepared(t, csv, "csv")
	source := ipapiTestSource(false)
	source.ID = original.ID
	source.Admission = "active"
	source.Rights = original.Rights
	source.Fixture = original.Fixture
	source.Fixture.Parser = source.Parser.ID
	source.Fixture.Schema = source.Parser.Schema
	source.Fixture.PayloadFormat = "decoded-csv"
	certifyGeoTestSource(t, engine, source)
	notice, err := os.ReadFile("testdata/ipapi-free-license.txt")
	if err != nil {
		t.Fatal(err)
	}
	oldClock := now.Add(-21 * 24 * time.Hour)
	fetch.assets = map[string][]byte{source.URL: ipapiTestZIP(t, csv, notice, oldClock)}
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil || result.Decision.State != "current" || result.Snapshot.GeoProof == nil || !result.Snapshot.PublishedAt.Equal(oldClock) || fetch.calls != 1 {
		t.Fatal(result.Decision, err)
	}
	plan, err := intelligence.Reconcile(intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, policyHash)
	if err != nil || len(plan.State.Sources) != 1 {
		t.Fatal(plan, err)
	}
	fetch.assets[source.URL] = ipapiTestZIP(t, csv, notice, now)
	repeated, err := engine.Ingest(context.Background(), source, now.Add(time.Hour), policyHash)
	if err != nil || repeated.Snapshot == nil || !repeated.Snapshot.PublishedAt.Equal(oldClock) || !repeated.Snapshot.GeoProof.UpstreamClock.Equal(now) {
		t.Fatal("archive repack renewed CSV", repeated.Decision, err)
	}
	expired, err := engine.Ingest(context.Background(), source, oldClock.Add(source.MaxAge), policyHash)
	if err != nil || expired.Snapshot != nil || expired.Decision.State != "stale" {
		t.Fatal("old decoded data survived expiry", expired.Decision, err)
	}
	source.Admission = "retired"
	withdrawn, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || withdrawn.Snapshot != nil {
		t.Fatal(withdrawn.Decision, err)
	}
	retracted, err := intelligence.Reconcile(plan.State, []intelligence.SourcePolicy{withdrawn.Policy}, nil, now, policyHash)
	if err != nil || len(retracted.State.Sources) != 0 {
		t.Fatal("withdrawn geo influence survived", err)
	}
}

func TestDBIPIntakeResolvesCurrentPublisherAsset(t *testing.T) {
	csv := []byte("8.8.8.0,8.8.8.255,NA,US,Example,City,37.1,-122.2\n")
	engine, original, fetch, now, policyHash := prepared(t, csv, "csv")
	source := dbipTestSource()
	source.ID = original.ID
	source.Admission = "active"
	source.Rights = original.Rights
	source.Fixture = original.Fixture
	source.Fixture.Parser = source.Parser.ID
	source.Fixture.Schema = source.Parser.Schema
	source.Fixture.PayloadFormat = "decoded-csv"
	certifyGeoTestSource(t, engine, source)
	month := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(csv)
	gz.Close()
	page := dbipTestPage(csv, month)
	asset := "https://download.db-ip.com/free/dbip-city-lite-2026-11.csv.gz"
	fetch.assets = map[string][]byte{dbipPublisherPage: page, asset: compressed.Bytes()}
	result, err := engine.IngestPartitioned(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil || len(result.Snapshot.RecordPartitions) == 0 || result.Snapshot.GeoProof == nil || result.Snapshot.GeoProof.AssetURL != asset || !result.Snapshot.PublishedAt.Equal(month) || fetch.calls != 2 {
		t.Fatal(result.Decision, err)
	}
	if err := validateStoredGeoSource(source, intelligence.StoredSource{Receipt: &intelligence.SourceReceipt{GeoProof: result.Snapshot.GeoProof, PublishedAt: result.Snapshot.PublishedAt}}, now); err != nil {
		t.Fatal(err)
	}
	fetch.assets[dbipPublisherPage] = []byte("publisher schema changed")
	result, err = engine.IngestPartitioned(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot != nil || fetch.calls != 3 {
		t.Fatal("discovery silently used old URL", result.Decision, err)
	}
}
