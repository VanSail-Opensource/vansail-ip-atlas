package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

func azureTestSource() Source {
	return Source{ID: "azure-appservice-public", Family: "microsoft-azure-appservice", Category: "infrastructure", Scope: "exact_ip", Coverage: "positive_only", Format: "json", URL: azureEditionBase + "ServiceTags_Public_20261116.json", Publication: Publication{"snapshot_metadata", azureDetails, "download.filename.date"}, MaxCompressedBytes: azureLimit, MaxAge: 30 * 24 * time.Hour, Weight: 80, Parser: Parser{"azure-appservice-service-tag", "azure-service-tags-json-v1", 1}, Signals: []string{"hosting"}, PublicFields: []string{"reason_flags"}, Fields: []string{"name", "id", "properties.systemService", "properties.addressPrefixes"}, FieldMappings: map[string][]string{"properties.addressPrefixes": {"reason_flags"}}}
}

func azureTestBody(t *testing.T, changes int, prefixes ...string) []byte {
	t.Helper()
	tag := func(name string, ps []string) map[string]any {
		return map[string]any{"name": name, "id": name, "properties": map[string]any{"changeNumber": 1, "region": "", "regionId": 0, "platform": "Azure", "systemService": "AzureAppService", "networkFeatures": []string{"API"}, "addressPrefixes": ps}}
	}
	b, err := json.Marshal(map[string]any{"cloud": "Public", "changeNumber": changes, "values": []any{tag("AppService", prefixes), tag("AppServiceManagement", []string{"8.8.4.4/32"})}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func azureTestPage(day time.Time, size int) []byte {
	name := azureFilename(day)
	return []byte(fmt.Sprintf(`<script>window.__DLCDetails__={"dlcDetailsView":{"error":"","downloadTitle":"Azure IP Ranges and Service Tags – Public Cloud","downloadFile":[{"name":%q,"url":%q,"version":%q,"size":%q,"datePublished":%q}]}}</script>`, name, azureEditionBase+name, day.Format("2006.01.02"), fmt.Sprint(size), day.Add(time.Hour).Format("1/2/2006 3:04:05 PM")))
}

type azureTestFetcher struct {
	*fixtureFetch
	modified map[string]time.Time
}

func (f azureTestFetcher) Fetch(ctx context.Context, url, dest string, bound int64) (acquire.Result, error) {
	r, e := f.fixtureFetch.Fetch(ctx, url, dest, bound)
	r.LastModified = f.modified[url]
	return r, e
}

func TestAzureGlobalServiceOnlyAndExactScopes(t *testing.T) {
	s := azureTestSource()
	ctx := context.Background()
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	base := azureTestBody(t, 4, "1.1.1.1/32", "8.8.8.0/24", "2606:4700:4700::1111/128", "2001:4860::/32")
	if impl, ok := selectAdapter(s); !ok || impl != azureAppService || !publicationSupported(s) {
		t.Fatal("service adapter unavailable")
	}
	var parsed []netip.Addr
	err := parseAzureService(ctx, bytes.NewReader(base), s, now, 2, func(r intelligence.NormalizedRecord) error {
		if !intelligence.AzureHostObservation(r) || !r.Evidence.SourcePublishedAt.Equal(now) {
			t.Fatal("incorrect Azure observation")
		}
		parsed = append(parsed, r.Evidence.Address)
		return r.Validate()
	})
	if err != nil || len(parsed) != 2 || parsed[0].String() != "1.1.1.1" || parsed[1].String() != "2606:4700:4700::1111" {
		t.Fatal("service projection", err)
	}
	for _, change := range [][2]string{{`"Public"`, `"Moon"`}, {`"platform":"Azure"`, `"platform":"Other"`}, {`"name":"AppService"`, `"name":"AppService.West"`}, {`"region":""`, `"region":"west"`}, {`"regionId":0`, `"regionId":2`}, {`"systemService":"AzureAppService"`, `"systemService":"Network"`}, {`"cloud":"Public"`, `"cloud":"Public","cloud":"Public"`}, {`"1.1.1.1/32"`, `"10.0.0.1/32"`}, {`"8.8.8.0/24"`, `"8.8.8.3/24"`}, {`"8.8.8.0/24"`, `"1.1.1.1/32"`}} {
		if _, e := readAzureEdition(ctx, bytes.NewReader(bytes.Replace(base, []byte(change[0]), []byte(change[1]), 1))); e == nil {
			t.Error("malformed edition accepted", change[0])
		}
	}
}

func TestAzureEditionListingBindsPermittedDateFilenameAndHost(t *testing.T) {
	day := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	page := azureTestPage(day, 12345)
	if got, n, e := azureListing(page, day.Add(2*24*time.Hour)); e != nil || !day.Equal(got) || n != 12345 {
		t.Fatal("valid listing", e)
	}
	for _, change := range [][2]string{{azureEditionBase, "https://example.invalid/"}, {"2026.11.16", "2026.11.15"}, {"</script>", "{} </script>"}, {"12345", "017"}, {"window.__DLCDetails__", "window.dx"}, {"ServiceTags_Public_", "ServiceTags_Private_"}, {"11/16/2026", "12/16/2026"}, {`"size":"12345"`, `"size":"12345","size":"12345"`}} {
		if _, _, e := azureListing(bytes.Replace(page, []byte(change[0]), []byte(change[1]), 1), day.Add(2*24*time.Hour)); e == nil {
			t.Error("unbound listing accepted", change[0])
		}
	}
}

func TestAzureWeeklyIntersectionIncludesDelayAndIndependentRevalidation(t *testing.T) {
	ctx := context.Background()
	s := azureTestSource()
	day := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	now := day.Add(6 * 24 * time.Hour)
	curr := azureTestBody(t, 10, "1.1.1.1/32", "8.8.8.8/32", "9.9.9.0/24")
	prior := azureTestBody(t, 9, "1.1.1.1/32", "4.2.2.2/32")
	older := azureTestBody(t, 8, "1.1.1.1/32")
	engine, original, fetch, _, binding := prepared(t, curr, "json")
	s.Rights, s.Fixture, s.Admission = original.Rights, original.Fixture, "active"
	s.Fixture.Parser, s.Fixture.Schema = s.Parser.ID, s.Parser.Schema
	certifyGeoTestSource(t, engine, s)
	prev := day.Add(-7 * 24 * time.Hour)
	old := prev.Add(-7 * 24 * time.Hour)
	aged := azureTestFetcher{fetch, map[string]time.Time{}}
	fetch.assets = map[string][]byte{azureDetails: azureTestPage(day, len(curr))}
	for _, v := range []struct {
		d    time.Time
		data []byte
	}{{day, curr}, {prev, prior}, {old, older}} {
		u := azureEditionBase + azureFilename(v.d)
		fetch.assets[u] = v.data
		aged.modified[u] = v.d.Add(24 * time.Hour)
	}
	engine.fetch = aged
	res, e := engine.Ingest(ctx, s, now, binding)
	if e != nil || res.Snapshot == nil {
		t.Fatal("complete service admission", res.Decision, e)
	}
	sn := res.Snapshot
	if !sn.PublishedAt.Equal(day) || len(sn.AzureProof.Editions) != 2 || len(sn.Records) != 1 || sn.Records[0].Evidence.Address.String() != "1.1.1.1" {
		t.Fatal("weekly selection changed")
	}
	// A late re-publication cannot establish seven days of prior allocation.
	aged.modified[azureEditionBase+azureFilename(prev)] = now.Add(-6 * 24 * time.Hour)
	ten, e := engine.fetchAzureService(ctx, filepath.Join(t.TempDir(), "payload"), s, now)
	if e != nil || len(ten.Editions) != 3 {
		t.Fatal("immature week did not require earlier supporting edition", e)
	}
	immature := ten.Editions[2].LastModified
	ten.Editions[2].LastModified = now
	if _, e := ten.Eligible(now, day, ten.Editions[0].PayloadHash); e == nil {
		t.Fatal("immature preceding editions accepted")
	}
	ten.Editions[2].LastModified = immature
	delete(aged.modified, azureEditionBase+azureFilename(prev))
	if _, e := engine.fetchAzureService(ctx, filepath.Join(t.TempDir(), "payload"), s, now); e == nil {
		t.Fatal("unknown prior availability accepted")
	}
	pol := []intelligence.SourcePolicy{res.Policy}
	if plan, e := intelligence.Reconcile(intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{*sn}, now, binding); e != nil || len(plan.State.Sources) != 1 {
		t.Fatal("eligible snapshot did not reconcile", e)
	}
	missing := *sn
	missing.AzureProof = nil
	if plan, e := intelligence.Reconcile(intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{missing}, now, binding); e != nil || len(plan.State.Sources) != 0 {
		t.Fatal("unproven service admission", e)
	}
	state, e := intelligence.ReconcilePartitioned(ctx, engine.workspace, intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{*sn}, now, binding)
	if e != nil {
		t.Fatal(e)
	}
	_, full, e := RevalidateStoredSources(ctx, engine.workspace, []Source{s}, state.State, now, binding)
	if e != nil || len(full) != 1 {
		t.Fatal("full service revalidation", e)
	}
	stored := state.State.Sources[0]
	fused := newSourceRecordScan(s, stored.RecordClocks(), now)
	if e := intelligence.WalkStoredSource(ctx, engine.workspace, stored, fused.accept); e != nil {
		t.Fatal(e)
	}
	_, fromFused, e := revalidateStoredSources(ctx, engine.workspace, []Source{s}, state.State, now, binding, nil, map[string]*sourceRecordScan{s.ID: fused})
	if e != nil || len(fromFused) != 1 || fromFused[0].azureHostHash != full[0].azureHostHash {
		t.Fatal("fused service revalidation", e)
	}
	mutated := *sn
	obs := *sn.Records[0].Evidence
	obs.Address = netip.MustParseAddr("8.8.8.8")
	mutated.Records = []intelligence.NormalizedRecord{{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &obs}}
	if _, e := intelligence.Reconcile(intelligence.BuildState{}, pol, []intelligence.SourceSnapshot{mutated}, now, binding); e == nil {
		t.Fatal("current-only host supported by retained proof")
	}
	scan := newSourceRecordScan(s, intelligence.SourceRecordClocks{ID: s.ID, PublishedAt: day, ExpiresAt: day.Add(s.MaxAge)}, now)
	if err := scan.accept(sn.Records[0]); err != nil {
		t.Fatal(err)
	}
	if err := scan.accept(sn.Records[0]); err == nil {
		t.Fatal("duplicate proved address")
	}
	if _, e := azureSeedDay(strings.Replace(s.URL, "download.microsoft.com", "example.invalid", 1)); e == nil {
		t.Fatal("unapproved seed accepted")
	}
}
