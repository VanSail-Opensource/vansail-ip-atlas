package admission

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

func rootZoneFixture(t *testing.T) ([]byte, Source) {
	t.Helper()
	b, err := os.ReadFile("../../fixtures/source-certification/observed-dns-root-zone.txt")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := os.Open("../../configs/sources.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	sources, err := DecodeCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sources {
		if s.ID == "iana-root-anycast" && rootZoneSource(s) {
			return b, s
		}
	}
	t.Fatal("reviewed DNS root source missing")
	return nil, Source{}
}

func TestRootZoneAddressProjectionRejectsAmbiguity(t *testing.T) {
	body, s := rootZoneFixture(t)
	if _, ok := selectAdapter(s); !ok || !publicationSupported(s) {
		t.Fatal("DNS root adapter unavailable")
	}
	seen := map[string]bool{}
	ctx := context.Background()
	noise := []byte("example.invalid. 518400 IN A 1.1.1.1\n")
	withNoise := append(append([]byte(nil), body...), noise...)
	proof, err := parseRootZone(ctx, bytes.NewReader(withNoise), 26, func(r intelligence.NormalizedRecord) error {
		if err := r.Validate(); err != nil {
			return err
		}
		u := r.Usage
		if u == nil || !u.Prefix.IsSingleIP() || !u.ObservedAt.Equal(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)) || u.Evidence.Anycast == nil || !*u.Evidence.Anycast || u.Evidence.Type != "" || u.Evidence.Assignment != "" || u.Evidence.DirectedBroadcast != nil || u.Evidence.Family != s.Family || !u.Evidence.Current {
			return fmt.Errorf("unexpected root anycast observation")
		}
		seen[u.Prefix.String()] = true
		return nil
	})
	if err != nil || len(seen) != 26 || seen["1.1.1.1/32"] || proof.until.Sub(proof.day) != 144*time.Hour {
		t.Fatal("DNS identity, TTL or scope changed", err)
	}
	lines := strings.Split(string(body), "\n")
	var oneNS, oneGlue string
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		if f[0] == "." && f[3] == "NS" {
			oneNS = l + "\n"
		}
		if f[3] == "A" {
			oneGlue = l + "\n"
		}
	}
	if oneNS == "" || oneGlue == "" {
		t.Fatal("fixture incomplete")
	}
	orig := string(body)
	for label, bad := range map[string]string{
		"missing delegation": strings.Replace(orig, oneNS, "", 1), "missing glue": strings.Replace(orig, oneGlue, "", 1), "duplicate glue": orig + oneGlue, "extra identity": orig + ". 518400 IN NS unrelated.invalid.\n",
		"invalid address": strings.Replace(orig, oneGlue, strings.Fields(oneGlue)[0]+" 518400 IN A 1.1.1.1:53\n", 1), "nonpublic address": strings.Replace(orig, oneGlue, strings.Fields(oneGlue)[0]+" 518400 IN A 127.0.0.1\n", 1),
		"zero TTL": strings.Replace(orig, oneNS, ". 0 IN NS "+strings.Fields(oneNS)[4]+"\n", 1), "trailing partial row": strings.TrimRight(orig, "\n"), "untrusted directive": orig + "$INCLUDE external.zone\n",
		"mismatched serial": strings.Replace(orig, "2026112200", "2026112300", 1),
	} {
		t.Run(label, func(t *testing.T) {
			count := 0
			_, err := parseRootZone(ctx, strings.NewReader(bad), 26, func(intelligence.NormalizedRecord) error { count++; return nil })
			if err == nil || count != 0 {
				t.Fatal("ambiguous or incomplete source emitted data", count, err)
			}
		})
	}
}

func addRootZoneTestAssets(t *testing.T, fetch *fixtureFetch, body []byte) {
	t.Helper()
	sum := md5.Sum(body)
	fetch.assets[rootZoneURL] = body
	fetch.assets[rootZoneURL+".gz"] = gzipMRTFixture(t, body)
	fetch.assets[rootZoneURL+".md5"] = []byte(hex.EncodeToString(sum[:]) + "\n")
}

func TestRootZoneProductionQualificationUsesAll26ExactObservations(t *testing.T) {
	ctx := context.Background()
	engine, catalog, now, binding, fresh := prepareCoreQualification(t, true)
	scan, _, err := VerifySourceRecordsForTier1(ctx, engine.workspace, catalog, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	fused, err := scan.Qualify(ctx, engine.workspace, catalog, now, binding)
	if err != nil || !reflect.DeepEqual(fresh.Report(), fused.Report()) || !reflect.DeepEqual(fresh.validation.statistics, fused.validation.statistics) {
		t.Fatal("DNS root source changed qualification between full and combined scans", err)
	}
	stat := fused.validation.statistics["iana-root-anycast"]
	retained := scan.records["iana-root-anycast"].rootAddresses
	if !retained.complete() || stat.Records != 26 || stat.Kinds[intelligence.RecordUsage-1] != 26 || stat.Usage || stat.Exact || len(stat.Signals) != 0 {
		t.Fatal("DNS source population or capabilities changed", stat)
	}
	body, _ := rootZoneFixture(t)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && (fields[3] == "A" || fields[3] == "AAAA") && !retained[netip.MustParseAddr(fields[4])] {
			t.Fatal("genuine anycast address omitted")
		}
	}
	if err := fused.RevalidateCurrent(ctx, engine.workspace, catalog, now, binding); err != nil {
		t.Fatal(err)
	}
}

func TestRootZoneCompleteAdmissionAndWithdrawal(t *testing.T) {
	b, s := rootZoneFixture(t)
	ctx := context.Background()
	e, orig, fetch, _, binding := prepared(t, b, "csv")
	s.Fixture = orig.Fixture
	s.Fixture.Parser = s.Parser.ID
	s.Fixture.Schema = s.Parser.Schema
	s.Fixture.TestedAt = "2026-11-22T06:00:00Z"
	certifyGeoTestSource(t, e, s)
	now := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	addRootZoneTestAssets(t, fetch, b)
	gzipBytes := fetch.assets[rootZoneURL+".gz"]
	res, err := e.IngestPartitioned(ctx, s, now, binding)
	if err != nil || res.Snapshot == nil || fetch.calls != 3 || res.Snapshot.PublishedAt.Format(time.RFC3339) != "2026-11-22T00:00:00Z" || res.Snapshot.ContentValidUntil.Format(time.RFC3339) != "2026-11-28T00:00:00Z" {
		t.Fatal("complete DNS source intake failed", res.Decision, err)
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, e.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{res.Policy}, []intelligence.SourceSnapshot{*res.Snapshot}, now, binding)
	if err != nil || len(plan.State.Sources) != 1 || !plan.State.Sources[0].ExpiresAt.Equal(res.Snapshot.ContentValidUntil) {
		t.Fatal("DNS TTL lost", err)
	}
	if err = intelligence.SavePartitionedState(ctx, e.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err = e.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	state, report, validation, err := validateSourceSet(ctx, e.workspace, []Source{s}, now, binding)
	if err != nil || validation == nil {
		t.Fatal("DNS root authenticated source revalidation failed", err)
	}
	if _, _, err = validation.revalidate(ctx, e.workspace, []Source{s}, now, binding); err != nil {
		t.Fatal("cached verification changed DNS source", err)
	}
	if report.RequireProduction() == nil {
		t.Fatal("root identity observation fabricated other capabilities")
	}
	if _, _, err = RevalidateStoredSources(ctx, e.workspace, []Source{s}, state, res.Snapshot.ContentValidUntil, binding); err == nil {
		t.Fatal("DNS data survived its original TTL")
	}
	second, err := intelligence.ReconcilePartitioned(ctx, e.workspace, plan.State, []intelligence.SourcePolicy{res.Policy}, nil, now.Add(time.Hour), binding)
	if err != nil || len(second.State.Sources) != 0 {
		t.Fatal("withdrawn root zone retained", err)
	}
	for name, asset := range map[string][]byte{"edition mismatch": gzipMRTFixture(t, append(append([]byte{}, b...), byte('\n'))), "second member": append(append([]byte{}, gzipBytes...), gzipBytes...), "truncated": gzipBytes[:len(gzipBytes)-3]} {
		t.Run(name, func(t *testing.T) {
			fetch.assets[rootZoneURL+".gz"] = asset
			bad, err := e.Ingest(ctx, s, now, binding)
			if err != nil || bad.Snapshot != nil {
				t.Fatal("invalid DNS distribution accepted", err)
			}
		})
	}
	fetch.assets[rootZoneURL+".gz"] = gzipBytes
	fetch.assets[rootZoneURL+".md5"] = []byte(strings.Repeat("0", 32) + "\n")
	bad, err := e.Ingest(ctx, s, now, binding)
	if err != nil || bad.Snapshot != nil {
		t.Fatal("incorrect published checksum accepted", err)
	}
}

type datedRootZoneFetch struct {
	*fixtureFetch
	modified map[string]time.Time
}

func (f datedRootZoneFetch) Fetch(ctx context.Context, url, dest string, bound int64) (acquire.Result, error) {
	r, err := f.fixtureFetch.Fetch(ctx, url, dest, bound)
	r.LastModified = f.modified[url]
	return r, err
}

func TestRootZonePublisherCopyRecoversOnlyAnIdenticalCurrentEdition(t *testing.T) {
	body, source := rootZoneFixture(t)
	engine, original, fetch, _, binding := prepared(t, body, "csv")
	source.Fixture = original.Fixture
	source.Fixture.Parser, source.Fixture.Schema = source.Parser.ID, source.Parser.Schema
	source.Fixture.TestedAt = "2026-11-22T06:00:00Z"
	certifyGeoTestSource(t, engine, source)
	clock := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	addRootZoneTestAssets(t, fetch, body)
	older := bytes.ReplaceAll(body, []byte("2026112200"), []byte("2026112102"))
	newer := bytes.ReplaceAll(body, []byte("2026112200"), []byte("2026112201"))
	compressed := fetch.assets[rootZoneURL+".gz"]
	archived := gzipMRTFixture(t, older)
	sameSerialDifferentBytes := gzipMRTFixture(t, append(bytes.Clone(body), []byte("unrelated.invalid. 7200 IN A 8.8.8.8\n")...))
	fetch.assets[rootZoneAlternateGzipURL] = compressed
	changed := map[string]time.Time{}
	engine.fetch = datedRootZoneFetch{fetch, changed}
	check := func(t *testing.T, at time.Time, want bool, wantCalls int) Result {
		t.Helper()
		start := fetch.calls
		r, err := engine.IngestPartitioned(t.Context(), source, at, binding)
		if err != nil || (r.Snapshot != nil) != want || fetch.calls-start != wantCalls {
			t.Fatalf("snapshot=%t decision=%+v calls=%d error=%v", r.Snapshot != nil, r.Decision, fetch.calls-start, err)
		}
		return r
	}
	baseline := check(t, clock, true, 3)
	fetch.assets[rootZoneURL+".gz"] = archived
	fresh := check(t, clock.Add(time.Hour), true, 4)
	if fresh.Snapshot.PayloadHash != baseline.Snapshot.PayloadHash || !fresh.Snapshot.PublishedAt.Equal(baseline.Snapshot.PublishedAt) || !fresh.Snapshot.ContentValidUntil.Equal(baseline.Snapshot.ContentValidUntil) {
		t.Fatal("mirror changed original identity or lifetime")
	}
	check(t, baseline.Snapshot.ContentValidUntil, false, 4)
	delete(fetch.assets, rootZoneURL+".gz")
	check(t, clock, true, 4)
	for _, tc := range []struct {
		name               string
		primary, alternate []byte
		calls              int
	}{
		{"both old", archived, archived, 4},
		{"newer primary cannot roll back", gzipMRTFixture(t, newer), compressed, 3},
		{"equivocal primary serial", sameSerialDifferentBytes, compressed, 3},
		{"corrupt primary", compressed[:len(compressed)-4], compressed, 3},
		{"equivocal alternate serial", archived, sameSerialDifferentBytes, 4},
		{"short alternate", archived, compressed[:len(compressed)-4], 4},
		{"second member", archived, append(bytes.Clone(compressed), compressed...), 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetch.assets[rootZoneURL+".gz"], fetch.assets[rootZoneAlternateGzipURL] = tc.primary, tc.alternate
			check(t, clock, false, tc.calls)
		})
	}
	fetch.assets[rootZoneURL+".gz"], fetch.assets[rootZoneAlternateGzipURL] = archived, compressed
	for _, tc := range []struct {
		url   string
		calls int
	}{{rootZoneURL, 1}, {rootZoneURL + ".md5", 2}, {rootZoneAlternateGzipURL, 4}} {
		changed[tc.url] = clock.Add(time.Second)
		check(t, clock, false, tc.calls)
		delete(changed, tc.url)
	}
	// A later observed file modification can withhold a current claim. An
	// earlier modification or retrieval clock cannot extend the SOA lifetime.
	fetch.assets[rootZoneURL+".md5"] = []byte(strings.Repeat("0", 32) + "\n")
	check(t, clock, false, 2)
}

func TestRootZonePrivateCompleteCapture(t *testing.T) {
	dir := os.Getenv("ATLAS_DNS_ROOT_OBSERVED_DIRECTORY")
	if dir == "" {
		t.Skip("private original root zone capture not supplied")
	}
	b, err := os.ReadFile(filepath.Join(dir, "root.zone"))
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{}
	for _, suffix := range []string{".gz", ".md5"} {
		assets[rootZoneURL+suffix], err = os.ReadFile(filepath.Join(dir, "root.zone"+suffix))
		if err != nil {
			t.Fatal(err)
		}
	}
	alternate, alternateErr := os.ReadFile(filepath.Join(dir, "zones", "root.zone.gz"))
	if alternateErr == nil {
		assets[rootZoneAlternateGzipURL] = alternate
	} else if !os.IsNotExist(alternateErr) {
		t.Fatal(alternateErr)
	}
	root := t.TempDir()
	file := filepath.Join(root, "payload")
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	fetch := &fixtureFetch{assets: assets}
	engine := Engine{fetch: fetch}
	z, err := engine.verifyRootZone(context.Background(), file, sha256.Sum256(b), int64(len(b)), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reported := 0
	_, err = parseRootZone(context.Background(), bytes.NewReader(b), 26, func(r intelligence.NormalizedRecord) error { reported++; return r.Validate() })
	if err != nil || reported != 26 {
		t.Fatal(reported, err)
	}
	t.Logf("Verified %d original text bytes (%x), %d corroboration fetches, SOA %s, %d exact anycast addresses, content valid through %s", len(b), sha256.Sum256(b), fetch.calls, z.serial, reported, z.until.Format(time.RFC3339))
}
