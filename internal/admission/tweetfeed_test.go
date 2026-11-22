package admission

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func tweetTestSource() Source {
	return Source{ID: "tweetfeed-week", Family: "ffraud-original", Category: "abuse", Coverage: "positive_only", Scope: "exact_ip", URL: tweetFeedCSV, Format: "csv", MaxCompressedBytes: tweetFeedByteLimit, MaxAge: 720 * time.Hour, Weight: 35,
		Publication: Publication{"snapshot_metadata", tweetFeedManifest, "artifacts.week.csv.updated_at"}, Parser: Parser{"tweetfeed-week-csv", "tweetfeed-six-column-ioc-v1", 1}, Fields: []string{"date", "user", "type", "value", "tags", "tweet_url"}, Signals: []string{"fraud"}, PublicFields: []string{"reason_flags"}, FieldMappings: map[string][]string{"value": {"reason_flags"}, "tags": {"reason_flags"}}}
}

const tweetTestDate = "2026-11-01 12:00:00"
const tweetTestRow = tweetTestDate + ",reporter,ip,1.1.1.1,#phishing,https://example.invalid/post\r\n"

func TestTweetFeedReadsOnlyExplicitLiteralIPReports(t *testing.T) {
	s := tweetTestSource()
	if _, ok := selectAdapter(s); !ok || !publicationSupported(s) {
		t.Fatal("weekly source dispatch unavailable")
	}
	published := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	body := strings.Builder{}
	for _, v := range []string{
		"url,\"https://1.1.1.1/folder,extra\",#phishing", "domain,example.invalid,#phishing",
		"md5,bad,#phishing", "sha256,bad,#phishing", "ip,1.1.1.2,#scam", "ip,1.1.1.2,#phishing-kit",
		"ip,1.1.1.2,#notphishing", "ip,127.0.0.1,#phishing", "ip,1.1.1.2,",
		"ip,1.1.1.1,#foo #PhIsHiNg #phishing",
	} {
		fmt.Fprintf(&body, "%s,reporter,%s,https://example.invalid/post\r\n", tweetTestDate, v)
	}
	count := 0
	err := parseRiskPayload(context.Background(), strings.NewReader(body.String()), s, published, 200, func(r intelligence.NormalizedRecord) error {
		count++
		e := r.Evidence
		if r.Kind != intelligence.RecordEvidence || e.Family != ffraudFixtureSource().Family || e.Signal != "fraud" || e.Scope != intelligence.Exact || e.Address != netip.MustParseAddr("1.1.1.1") || e.Weight != 0 || !e.SourcePublishedAt.Equal(published) || e.ItemPublishedAt.Format(time.DateTime) != tweetTestDate || e.ItemPublishedAt.Location() != time.UTC || !e.Current || e.SubscriptionLiteral {
			t.Fatal("altered weekly risk semantics")
		}
		if wire, _ := json.Marshal(r); strings.Contains(string(wire), "reporter") || strings.Contains(string(wire), "invalid") || strings.Contains(string(wire), "#") {
			t.Fatal("publisher metadata escaped normalization")
		}
		return r.Validate()
	})
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestTweetFeedRejectsIncompleteOrChangedRows(t *testing.T) {
	s := tweetTestSource()
	clock := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	for _, bad := range []string{
		"", strings.TrimSpace(tweetTestRow), tweetTestRow + "\r\n",
		strings.Replace(tweetTestRow, "1.1.1.1", "1.1.1.1:443", 1), strings.Replace(tweetTestRow, "1.1.1.1", "fe80::1%eth0", 1),
		strings.Replace(tweetTestRow, "1.1.1.1", "server.invalid", 1), strings.Replace(tweetTestRow, "reporter", "re\x00porter", 1),
		strings.Replace(tweetTestRow, tweetTestDate, "2026-11-03 00:00:00", 1), strings.Replace(tweetTestRow, ",ip,", ",ipset,", 1),
		strings.Replace(tweetTestRow, "2026-11-01", "2026-13-01", 1), "date,user,type,value,tags,tweet_url\n" + tweetTestRow,
		strings.Replace(tweetTestRow, "reporter", "reporter,extra", 1), strings.Repeat(tweetTestRow, 2),
		strings.Replace(tweetTestRow, "#phishing", "#fake", 1), strings.Replace(tweetTestRow, "reporter", strings.Repeat("x", 320<<10), 1),
	} {
		if err := parseRiskPayload(context.Background(), strings.NewReader(bad), s, clock, 1, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
			t.Fatal("invalid complete positive risk feed accepted")
		}
	}
	stop := errors.New("sink stopped")
	if err := parseRiskPayload(context.Background(), strings.NewReader(tweetTestRow), s, clock, 1, func(intelligence.NormalizedRecord) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("sink error lost", err)
	}
	for _, mutate := range []func(*Source){func(s *Source) { s.Family = "another-community" }, func(s *Source) { s.URL = "https://example.invalid/week.csv" }, func(s *Source) { s.Publication.Field = "generated_at" }, func(s *Source) { s.Signals = []string{"abuse"} }, func(s *Source) { s.Coverage = "complete" }, func(s *Source) { s.Parser.Version++ }} {
		bad := s
		mutate(&bad)
		if _, ok := selectAdapter(bad); ok {
			t.Fatal("changed weekly evidence contract accepted")
		}
	}
}

func TestTweetFeedManifestBindsRowsDigestAndClock(t *testing.T) {
	b := []byte(tweetTestRow)
	hash := sha256.Sum256(b)
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	artifact := fmt.Sprintf(`{"name":"week.csv","path":"week.csv","format":"csv","window":"week","bytes":%d,"rows":1,"sha256":"%s","updated_at":"2026-11-03T00:00:00Z"}`, len(b), hashString(hash))
	manifest := `{"schema_version":1,"generated_at":"2026-11-04T00:00:00Z","artifacts":[` + artifact + `]}`
	p := t.TempDir()
	asset := filepath.Join(p, "asset")
	meta := filepath.Join(p, "manifest")
	if err := os.WriteFile(asset, b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, doc string
		valid     bool
	}{
		{"valid", manifest, true}, {"different clock type", strings.Replace(manifest, "updated_at", "fetched_at", 1), false},
		{"renewed manifest only", strings.Replace(manifest, "2026-11-04", "2026-11-07", 1), true},
		{"duplicate record", strings.Replace(manifest, artifact, artifact+","+artifact, 1), false}, {"changed hash", strings.Replace(manifest, hashString(hash), strings.Repeat("0", 64), 1), false},
		{"different size", strings.Replace(manifest, fmt.Sprintf(`"bytes":%d`, len(b)), `"bytes":2`, 1), false}, {"wrong row count", strings.Replace(manifest, `"rows":1`, `"rows":2`, 1), false},
		{"different path", strings.Replace(manifest, `"path":"week.csv"`, `"path":"month.csv"`, 1), false}, {"later artifact", strings.Replace(manifest, "2026-11-04", "2026-11-02", 1), false},
		{"non-UTC artifact", strings.Replace(manifest, "2026-11-03T00:00:00Z", "2026-11-03T00:00:00", 1), false}, {"future generation", strings.Replace(manifest, "2026-11-04", "2026-12-02", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(meta, []byte(tc.doc), 0600); err != nil {
				t.Fatal(err)
			}
			actual, err := verifyTweetFeedFile(context.Background(), meta, asset, hash, int64(len(b)), now)
			if tc.valid {
				if err != nil || actual.Format(time.RFC3339) != "2026-11-03T00:00:00Z" {
					t.Fatal(actual, err)
				}
			} else if err == nil {
				t.Fatal("mismatched weekly file accepted")
			}
		})
	}
	engine, original, fetch, clock, binding := prepared(t, b, "csv")
	s := tweetTestSource()
	s.Rights, s.Admission, s.Fixture = original.Rights, "active", original.Fixture
	s.Fixture.Parser, s.Fixture.Schema = s.Parser.ID, s.Parser.Schema
	certifyGeoTestSource(t, engine, s)
	fetch.assets = map[string][]byte{tweetFeedCSV: b, tweetFeedManifest: []byte(manifest)}
	res, err := engine.Ingest(context.Background(), s, clock, binding)
	if err != nil || res.Snapshot == nil || len(res.Snapshot.Records) != 1 || !res.Snapshot.PublishedAt.Equal(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)) || fetch.calls != 2 {
		t.Fatal("weekly source did not complete normal admission", res.Decision, err)
	}
	updated, err := intelligence.Reconcile(intelligence.BuildState{}, []intelligence.SourcePolicy{res.Policy}, []intelligence.SourceSnapshot{*res.Snapshot}, clock, binding)
	if err != nil || len(updated.State.Sources) != 1 {
		t.Fatal("weekly observation failed reconcile", err)
	}
	oldest := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if !updated.State.Sources[0].ExpiresAt.Equal(oldest.Add(720 * time.Hour)) {
		t.Fatal("report expiry extended")
	}
	next, err := intelligence.Reconcile(updated.State, []intelligence.SourcePolicy{res.Policy}, nil, clock.Add(time.Hour), binding)
	if err != nil || len(next.State.Sources) != 0 {
		t.Fatal("withdrawn file retained", err)
	}
}

// Replays a complete, private original CSV and publisher manifest. A mismatch
// can be a real CDN generation race; never substitute the HTTP response time.
func TestTweetFeedPrivateCompleteCapture(t *testing.T) {
	dir := os.Getenv("ATLAS_TWEETFEED_OBSERVED_DIRECTORY")
	if dir == "" {
		t.Skip("private CSV and publisher manifest not provided")
	}
	ctx := context.Background()
	payload := filepath.Join(dir, "week.csv")
	digest, size, err := hashFile(ctx, payload, tweetFeedByteLimit)
	if err != nil {
		t.Fatal(err)
	}
	published, err := verifyTweetFeedFile(ctx, filepath.Join(dir, "manifest.json"), payload, digest, size, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	unique := make(map[netip.Addr]bool)
	var first, last time.Time
	var count int
	rows, err := scanTweetFeed(ctx, file, published, tweetFeedRowLimit, func(record intelligence.NormalizedRecord) error {
		if err := record.Validate(); err != nil {
			return err
		}
		e := record.Evidence
		unique[e.Address] = true
		if first.IsZero() || e.ItemPublishedAt.Before(first) {
			first = e.ItemPublishedAt
		}
		if e.ItemPublishedAt.After(last) {
			last = e.ItemPublishedAt
		}
		count++
		return nil
	})
	if err != nil || count == 0 {
		t.Fatal(count, err)
	}
	t.Logf("Exact week.csv digest %x, bytes %d, all %d input rows, %d dated reports, %d distinct public IPs, observation range %s to %s, published %s", digest, size, rows, count, len(unique), first.Format(time.RFC3339), last.Format(time.RFC3339), published.Format(time.RFC3339))
}
