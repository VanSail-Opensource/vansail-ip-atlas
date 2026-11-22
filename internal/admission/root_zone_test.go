package admission

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	gzipBytes := gzipMRTFixture(t, b)
	md := md5.Sum(b)
	fetch.assets = map[string][]byte{rootZoneURL: b, rootZoneURL + ".gz": gzipBytes, rootZoneURL + ".md5": []byte(hex.EncodeToString(md[:]) + "\n")}
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
	root := t.TempDir()
	file := filepath.Join(root, "payload")
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	engine := Engine{fetch: &fixtureFetch{assets: assets}}
	z, err := engine.verifyRootZone(context.Background(), file, sha256.Sum256(b), int64(len(b)), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reported := 0
	_, err = parseRootZone(context.Background(), bytes.NewReader(b), 26, func(r intelligence.NormalizedRecord) error { reported++; return r.Validate() })
	if err != nil || reported != 26 {
		t.Fatal(reported, err)
	}
	t.Logf("Verified %d full text bytes (%x), independent gzip %d bytes, SOA %s, %d exact anycast addresses, content valid through %s", len(b), sha256.Sum256(b), len(assets[rootZoneURL+".gz"]), z.serial, reported, z.until.Format(time.RFC3339))
}
