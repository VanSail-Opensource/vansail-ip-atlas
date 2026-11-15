package admission

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func rpkiClientClock() time.Time { return time.Date(2026, 11, 9, 2, 38, 6, 0, time.UTC) }
func rpkiClientFixture() string {
	clock := rpkiClientClock()
	return fmt.Sprintf(`{"metadata":{"buildtime":%q,"vrps":4,"uniquevrps":3,"tals":5,"invalidtals":0,"buildmachine":"private-host","operational":{"counter":1}},"roas":[{"asn":13335,"prefix":"1.0.0.0/24","maxLength":24,"ta":"apnic","expires":%d},{"asn":65037,"prefix":"1.9.12.0/24","maxLength":24,"ta":"apnic","expires":%d},{"asn":0,"prefix":"2001:db8::/32","maxLength":48,"ta":"ripe","expires":%d}],"bgpsec_keys":[],"nonfunc_cas":[],"aspas":[]}`,
		clock.Format(time.RFC3339), clock.Add(time.Hour).Unix(), clock.Add(2*time.Hour).Unix(), clock.Add(3*time.Hour).Unix())
}
func rpkiClientLimits() intelligence.ParseLimits {
	return intelligence.ParseLimits{Bytes: 4 << 20, Records: 100, LineBytes: 1 << 20}
}

func TestRPKIClientFullProofPrivateExpiryAndAuthorizationASNs(t *testing.T) {
	var records []intelligence.NormalizedRecord
	metadata, err := parseRPKIClientPayload(context.Background(), strings.NewReader(rpkiClientFixture()), rpkiClientLimits(), rpkiClientClock(), func(record intelligence.NormalizedRecord) error {
		if err := record.Validate(); err != nil {
			return err
		}
		records = append(records, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Rows != 3 || metadata.RetainedRows != 3 || metadata.ExpiredAtIntakeRows != 0 || !metadata.BuiltAt.Equal(rpkiClientClock()) || !metadata.CoverageValidUntil.Equal(rpkiClientClock().Add(time.Hour)) {
		t.Fatalf("wrong private completeness/expiry: %+v", metadata)
	}
	if len(records) != 3 || records[1].VRP.ASN != 65037 || records[2].VRP.ASN != 0 || !records[1].VRP.ValidUntil.Equal(rpkiClientClock().Add(2*time.Hour)) {
		t.Fatal("authorization values or private expiry were discarded")
	}
	index, err := intelligence.NewVRPIndex([]intelligence.VRP{*records[1].VRP}, true)
	if err != nil {
		t.Fatal(err)
	}
	if index.Validate(netip.MustParsePrefix("1.9.12.0/24"), 13335) != intelligence.RPKIInvalid {
		t.Fatal("private-ASN authorization must invalidate a mismatching public origin")
	}
}

func TestRPKIClientExpiredAuthorizationsRemainDatedSnapshotObservations(t *testing.T) {
	for _, elapsed := range []time.Duration{90 * time.Minute, 4 * time.Hour} {
		now := rpkiClientClock().Add(elapsed)
		count := 0
		metadata, err := parseRPKIClientPayload(context.Background(), strings.NewReader(rpkiClientFixture()), rpkiClientLimits(), now, func(record intelligence.NormalizedRecord) error {
			count++
			if !rpkiClientClock().Before(record.VRP.ValidUntil) {
				t.Fatal("VRP was already expired at the actual publisher observation")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		expired := 1
		if elapsed == 4*time.Hour {
			expired = 3
		}
		if count != 3 || metadata.Rows != 3 || metadata.RetainedRows != 3 || metadata.ExpiredAtIntakeRows != expired || !metadata.CoverageValidUntil.Equal(rpkiClientClock().Add(time.Hour)) || !metadata.BuiltAt.Equal(rpkiClientClock()) {
			t.Fatal("historical rows, original observation clock or authorization deadline changed")
		}
	}
}

func TestRPKIClientRejectsUnknownDuplicateCorruptAndIncompleteProof(t *testing.T) {
	base := rpkiClientFixture()
	bad := map[string]string{
		"unknown-root":         strings.Replace(base, `"bgpsec_keys":[]`, `"surprise":[]`, 1),
		"duplicate-root":       strings.Replace(base, `"aspas":[]`, `"roas":[]`, 1),
		"count":                strings.Replace(base, `"uniquevrps":3`, `"uniquevrps":2`, 1),
		"partial-tals":         strings.Replace(base, `"tals":5`, `"tals":4`, 1),
		"invalid-tals":         strings.Replace(base, `"invalidtals":0`, `"invalidtals":1`, 1),
		"missing-clock":        strings.Replace(base, `"buildtime":`, `"time":`, 1),
		"clock-case":           strings.Replace(base, `"buildtime":`, `"BuildTime":`, 1),
		"expiry-at-build":      strings.Replace(base, fmt.Sprint(rpkiClientClock().Add(time.Hour).Unix()), fmt.Sprint(rpkiClientClock().Unix()), 1),
		"future-clock":         strings.Replace(base, rpkiClientClock().Format(time.RFC3339), rpkiClientClock().Add(25*time.Hour).Format(time.RFC3339), 1),
		"duplicate-metadata":   strings.Replace(base, `"vrps":4`, `"vrps":4,"VRPS":4`, 1),
		"unknown-vrp":          strings.Replace(base, `"asn":13335`, `"new":1,"asn":13335`, 1),
		"folded-vrp-field":     strings.Replace(base, `"asn":13335`, `"ASN":13335`, 1),
		"duplicate-vrp":        strings.Replace(base, `"asn":13335`, `"asn":13335,"asn":13336`, 1),
		"null-asn":             strings.Replace(base, `"asn":13335`, `"asn":null`, 1),
		"fraction-asn":         strings.Replace(base, `"asn":13335`, `"asn":13335.0`, 1),
		"noncanonical-prefix":  strings.Replace(base, `"1.0.0.0/24"`, `"1.0.0.1/24"`, 1),
		"invalid-maxlength":    strings.Replace(base, `"maxLength":24`, `"maxLength":33`, 1),
		"unknown-ta":           strings.Replace(base, `"ta":"apnic"`, `"ta":"unknown"`, 1),
		"trailing":             base + `{}`,
		"truncated":            base[:len(base)-1],
		"trailing-root-comma":  base[:len(base)-1] + `,}`,
		"trailing-array-comma": strings.Replace(base, `"aspas":[]`, `"aspas":[null,]`, 1),
	}
	for name, input := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRPKIClientPayload(context.Background(), strings.NewReader(input), rpkiClientLimits(), rpkiClientClock(), nil); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

type rpkiRepeatedReader struct {
	value           []byte
	repeats, offset int
}

func (r *rpkiRepeatedReader) Read(output []byte) (int, error) {
	if r.repeats == 0 {
		return 0, io.EOF
	}
	written := 0
	for written < len(output) && r.repeats > 0 {
		n := copy(output[written:], r.value[r.offset:])
		written += n
		r.offset += n
		if r.offset == len(r.value) {
			r.offset = 0
			r.repeats--
		}
	}
	return written, nil
}

func TestRPKIClientStreamsBeyondGeneric64MiBWithoutGrowingOneValue(t *testing.T) {
	base := rpkiClientFixture()
	marker := `"nonfunc_cas":[]`
	at := strings.Index(base, marker)
	const repeats = 8193
	reader := io.MultiReader(strings.NewReader(base[:at]+`"nonfunc_cas":[`), &rpkiRepeatedReader{value: []byte(`"` + strings.Repeat("x", 8192) + `",`), repeats: repeats}, strings.NewReader(`"last"]`+base[at+len(marker):]))
	limits := intelligence.ParseLimits{Bytes: 128 << 20, Records: 20000, LineBytes: 1 << 20}
	metadata, err := parseRPKIClientPayload(context.Background(), reader, limits, rpkiClientClock(), nil)
	if err != nil || metadata.Rows != 3 {
		t.Fatalf("bounded >64MiB stream rejected: %v", err)
	}
	if err := intelligence.ParseVRPJSON(context.Background(), strings.NewReader(`{"roas":[]}`), limits, func(intelligence.VRP) error { return nil }); err == nil {
		t.Fatal("generic allocation envelope was widened")
	}
}

type rpkiCountReader struct {
	reader io.Reader
	bytes  int
}

func (r *rpkiCountReader) Read(output []byte) (int, error) {
	n, e := r.reader.Read(output)
	r.bytes += n
	return n, e
}

func TestRPKIClientBoundsValuesBeforeJSONAllocationAndHonorsCancellation(t *testing.T) {
	reader := &rpkiCountReader{reader: io.MultiReader(strings.NewReader(`{"roas":[{"prefix":"`), &rpkiRepeatedReader{value: []byte("x"), repeats: 64 << 20})}
	limits := intelligence.ParseLimits{Bytes: 70 << 20, Records: 100, LineBytes: 1 << 20}
	if _, err := parseRPKIClientPayload(context.Background(), reader, limits, rpkiClientClock(), nil); err == nil {
		t.Fatal("unbounded scalar accepted")
	}
	if reader.bytes > (1<<20)+(128<<10) {
		t.Fatalf("read beyond bounded scalar window: %d", reader.bytes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseRPKIClientPayload(ctx, strings.NewReader(rpkiClientFixture()), rpkiClientLimits(), rpkiClientClock(), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	stop := errors.New("stop sink")
	if _, err := parseRPKIClientPayload(context.Background(), strings.NewReader(rpkiClientFixture()), rpkiClientLimits(), rpkiClientClock(), func(intelligence.NormalizedRecord) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("sink error lost: %v", err)
	}
}

func TestRPKIClientEmbeddedFileProofIsSourceSpecificAndConsumesCompleteInput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "payload.json")
	body := rpkiClientFixture()
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	source := Source{URL: "https://console.rpki-client.org/rpki.json", Format: "json", Category: "rpki", MaxCompressedBytes: 4 << 20, MaxAge: 720 * time.Hour,
		Parser: Parser{ID: "rpki-client-json", Schema: "rpki-client-payloads-json-v1", Version: 1}, Publication: Publication{Kind: "embedded", Locator: "https://console.rpki-client.org/rpki.json", Field: "metadata.buildtime"}}
	metadata, err := verifyRPKIClientFile(context.Background(), file, int64(len(body)), source, rpkiClientClock())
	if err != nil || metadata.Rows != 3 {
		t.Fatal(err)
	}
	source.Publication.Locator = "https://example.org/metadata"
	if _, err = verifyRPKIClientFile(context.Background(), file, int64(len(body)), source, rpkiClientClock()); err == nil {
		t.Fatal("unbound publisher accepted")
	}
}

func TestObservedRPKIClientCompletePayload(t *testing.T) {
	path := os.Getenv("ATLAS_RPKI_OBSERVED_FILE")
	if path == "" {
		t.Skip("private observed bulk payload is not provided")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	limits := intelligence.ParseLimits{Bytes: info.Size(), Records: 100_000_000, LineBytes: 1 << 20}
	metadata, err := parseRPKIClientPayload(context.Background(), file, limits, rpkiClientClock(), func(record intelligence.NormalizedRecord) error { return record.Validate() })
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Rows != 1032481 || metadata.RetainedRows != 1032481 || metadata.ExpiredAtIntakeRows != 0 || !metadata.CoverageValidUntil.Equal(time.Date(2026, 11, 9, 4, 19, 22, 0, time.UTC)) {
		t.Fatalf("observed source changed: %+v", metadata)
	}
	t.Logf("Observed complete publisher payload: %d bytes, %d rows, deadline %s", info.Size(), metadata.Rows, metadata.CoverageValidUntil.Format(time.RFC3339))
}

func TestRPKIClientCompressedFixtureRetainsOriginalSchemaAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observed.json.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zipped := gzip.NewWriter(file)
	if _, err = io.WriteString(zipped, rpkiClientFixture()); err != nil {
		t.Fatal(err)
	}
	if err = zipped.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	source := Source{Format: "json-gz", MaxCompressedBytes: 4 << 20}
	err = parsePayloadTo(context.Background(), file, info.Size(), source, rpkiClientJSON, rpkiClientClock(), 100, func(record intelligence.NormalizedRecord) error {
		count++
		if record.VRP == nil || !rpkiClientClock().Before(record.VRP.ValidUntil) {
			return errors.New("fixture lost private expiry")
		}
		return record.Validate()
	})
	if err != nil || count != 3 {
		t.Fatalf("compressed fixture differs from original schema: count=%d err=%v", count, err)
	}
}

func FuzzRPKIClientPayload(f *testing.F) {
	f.Add([]byte(rpkiClientFixture()))
	f.Add([]byte(`{"metadata":{},"roas":[]}`))
	f.Add([]byte(`{"roas":[{"prefix":"\\"`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 2<<20 {
			t.Skip()
		}
		count := 0
		limits := intelligence.ParseLimits{Bytes: 2 << 20, Records: 10000, LineBytes: 1 << 20}
		metadata, err := parseRPKIClientPayload(context.Background(), strings.NewReader(string(payload)), limits, rpkiClientClock(), func(record intelligence.NormalizedRecord) error {
			count++
			if record.VRP == nil || record.VRP.ValidUntil.IsZero() {
				t.Fatal("missing authorization expiry")
			}
			return record.Validate()
		})
		if err == nil && (metadata.BuiltAt.IsZero() || metadata.RetainedRows != count || metadata.Rows != count || !metadata.BuiltAt.Before(metadata.CoverageValidUntil)) {
			t.Fatal("successful parse lacks complete private proof")
		}
	})
}
