package admission

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

func rotationSource(raw, format string) Source {
	return Source{URL: raw, Format: format, MRTArchivePolicy: "latest-complete-v1", Parser: Parser{"mrt-table-dump-v2", "mrt-table-dump-v2-unicast-v1", 1}, Category: "bgp", Scope: "path", Publication: Publication{"embedded", raw, "mrt_frame_capture_timestamp"}}
}

type rotationFetch struct {
	*fixtureFetch
	requests    []string
	failures    map[string]error
	corruptHash bool
}

func (f *rotationFetch) Fetch(ctx context.Context, raw, destination string, bound int64) (acquire.Result, error) {
	f.requests = append(f.requests, raw)
	if err := f.failures[raw]; err != nil {
		return acquire.Result{}, err
	}
	r, err := f.fixtureFetch.Fetch(ctx, raw, destination, bound)
	if f.corruptHash && err == nil {
		r.SHA256 = "invalid"
	}
	return r, err
}

func preparedRotatingMRT(t *testing.T) (*Engine, []Source, *rotationFetch, time.Time, [32]byte) {
	t.Helper()
	e, sources, fetch, epoch, binding := preparedMRTCoordinator(t)
	now := epoch.Add(30 * time.Minute)
	sources[0].URL = "https://data.ris.ripe.net/rrc18/2026.10/bview.20261001.0000.gz"
	sources[0].Format = "mrt-gz"
	sources[1].URL = "https://archive.routeviews.org/route-views.wide/bgpdata/2026.10/RIBS/rib.20261001.0000.bz2"
	sources[1].Format = "mrt-bz2"
	// bzip2 of coordinatorMRTFixture(2026-11-08T00:00Z, 300, 3).
	wide, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWSH0rg0AACB1TXgSAkCABEAABBBAAABIQAIAAKAAVDU0MjRpoyCVPKamnpNNDJZzDQophaQVV5dHpr0YEoLJrHjKoIRYrR9wPSMxNx8XckU4UJAh9K4N")
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{gzipMRTFixture(t, coordinatorMRTFixture(epoch, 200, 2)), wide}
	code, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	var reviews []certification
	for i := range sources {
		s := &sources[i]
		s.MRTArchivePolicy = latestCompleteMRTPolicy
		s.Publication.Locator = s.URL
		s.Fixture.TestedAt = now.Format(time.RFC3339)
		s.Fixture.SHA256 = hashString(sha256.Sum256(payloads[i]))
		if err := os.WriteFile(filepath.Join(e.workspace, s.Fixture.Path), payloads[i], 0600); err != nil {
			t.Fatal(err)
		}
		reviews = append(reviews, certification{s.ID, s.Parser.ID, s.Parser.Schema, 1, s.Fixture.SHA256, s.Fixture.TestedAt, hashString(code)})
		urls, err := mrtRIBCandidates(*s, now)
		if err != nil {
			t.Fatal(err)
		}
		fetch.assets[urls[0]] = payloads[i]
	}
	data, _ := json.Marshal(ledger{1, reviews})
	if err := os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	wrapper := &rotationFetch{fixtureFetch: fetch, failures: map[string]error{}}
	e.fetch = wrapper
	return e, sources, wrapper, now, binding
}

func TestMRTColdRotationBindsActualArchivesWithoutChangingCatalog(t *testing.T) {
	e, sources, fetch, now, binding := preparedRotatingMRT(t)
	before, _ := json.Marshal(sources)
	r, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || len(fetch.requests) != 2 {
		t.Fatal(r, err, fetch.requests)
	}
	for i, item := range r.Results {
		if item.Snapshot == nil || item.Decision.State != "current" {
			t.Fatal("complete rotating archive rejected", item.Decision)
		}
		p := item.Snapshot.MRTProof
		if p.BaseArchiveURL != fetch.requests[i] || !p.BaseArchiveSelectedAt.Equal(now) || !validMRTArchiveBinding(sources[i], p, now) || !item.Snapshot.PublishedAt.Equal(now.Add(-30*time.Minute)) {
			t.Fatal("actual archive/capture binding lost", p)
		}
	}
	after, _ := json.Marshal(sources)
	if string(before) != string(after) {
		t.Fatal("rotation mutated catalog identity")
	}
	sealMRTResult(t, e, r, now, binding)
	state, err := intelligence.VerifyPrivateStateSeal(context.Background(), e.workspace, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevalidateStoredSources(context.Background(), e.workspace, sources, state, now, binding); err != nil {
		t.Fatal("rotated receipt does not revalidate", err)
	}
}

func TestMRTColdRotationFallbackOnlyOn404AndOnlyOneSlot(t *testing.T) {
	for _, scenario := range []string{"404", "both404", "transport", "truncated", "capture-outside-slot", "future-capture", "bad-hash", "stale-capture"} {
		t.Run(scenario, func(t *testing.T) {
			e, sources, fetch, now, binding := preparedRotatingMRT(t)
			urls, _ := mrtRIBCandidates(sources[0], now)
			location, _ := mrtArchiveURL(urls[1])
			fetch.assets[urls[1]] = gzipMRTFixture(t, coordinatorMRTFixture(location.from, 200, 2))
			switch scenario {
			case "404":
				fetch.failures[urls[0]] = acquire.ErrNotFound
			case "both404":
				fetch.failures[urls[0]], fetch.failures[urls[1]] = acquire.ErrNotFound, acquire.ErrNotFound
			case "transport":
				fetch.failures[urls[0]] = acquire.ErrFetch
			case "truncated":
				fetch.assets[urls[0]] = fetch.assets[urls[0]][:len(fetch.assets[urls[0]])-1]
			case "capture-outside-slot":
				fetch.assets[urls[0]] = fetch.assets[urls[1]]
			case "future-capture":
				fetch.assets[urls[0]] = gzipMRTFixture(t, coordinatorMRTFixture(now.Add(time.Minute), 200, 2))
			case "bad-hash":
				fetch.corruptHash = true
			case "stale-capture":
				fetch.assets[urls[0]] = gzipMRTFixture(t, coordinatorMRTFixture(now.Add(-721*time.Hour), 200, 2))
			}
			r, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "404" {
				if len(fetch.requests) != 3 || fetch.requests[0] != urls[0] || fetch.requests[1] != urls[1] || r.Results[0].Snapshot == nil || r.Results[1].Snapshot == nil || r.Results[0].Snapshot.MRTProof.BaseArchiveURL != urls[1] || !r.Results[0].Snapshot.PublishedAt.Equal(location.from) {
					t.Fatal("404 fallback lost exact older capture", r, fetch.requests)
				}
				if e.mrt.bytes != r.CompressedBytes {
					t.Fatal("header-only404 consumed or reset body budget")
				}
			} else {
				want := 1
				if scenario == "both404" {
					want = 2
				}
				if len(fetch.requests) != want || r.Results[0].Snapshot != nil || r.Results[1].Snapshot != nil {
					t.Fatal("failed complete archive was skipped or leaked partial source", r, fetch.requests)
				}
			}
		})
	}
}

func TestMRTArchiveProofCannotChangeCollectorSlotOrSelectionClock(t *testing.T) {
	e, sources, _, now, binding := preparedRotatingMRT(t)
	r, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || r.Results[0].Snapshot == nil {
		t.Fatal(r, err)
	}
	for _, mutate := range []func(*intelligence.MRTSourceProof){
		func(p *intelligence.MRTSourceProof) { p.BaseArchiveURL = "" },
		func(p *intelligence.MRTSourceProof) {
			p.BaseArchiveURL = "https://data.ris.ripe.net/rrc00/2026.11/bview.20261108.0000.gz"
		},
		func(p *intelligence.MRTSourceProof) {
			p.BaseArchiveURL = "https://data.ris.ripe.net/rrc18/2026.11/bview.20261107.0800.gz"
		},
		func(p *intelligence.MRTSourceProof) { p.BaseArchiveSelectedAt = now.Add(time.Hour) },
		func(p *intelligence.MRTSourceProof) { p.CapturedAt = now.Add(-time.Hour) },
		func(p *intelligence.MRTSourceProof) { p.CaptureUntil = now.Add(8 * time.Hour) },
		func(p *intelligence.MRTSourceProof) { p.Collector[0] ^= 1 },
	} {
		p := *r.Results[0].Snapshot.MRTProof
		mutate(&p)
		if validMRTArchiveBinding(sources[0], &p, now) {
			t.Fatal("altered actual archive binding accepted")
		}
	}
}

func TestRotatedMRTBaseKeepsActualArchiveThroughReplay(t *testing.T) {
	e, sources, fetch, epoch, binding, plans := preparedReplayCoordinator(t)
	oldBase := sources[0].URL
	newBase := "https://data.ris.ripe.net/rrc18/2026.11/bview.20261108.0000.gz"
	fetch.assets[newBase] = fetch.assets[oldBase]
	sources[0].URL = "https://data.ris.ripe.net/rrc18/2026.10/bview.20261001.0000.gz"
	sources[0].Publication.Locator = sources[0].URL
	sources[0].MRTArchivePolicy = latestCompleteMRTPolicy
	updateURL := "https://data.ris.ripe.net/rrc18/2026.11/updates.20261108.0000.gz"
	fetch.assets[updateURL] = fetch.assets[plans[sources[0].ID][0]]
	plans[sources[0].ID] = []string{updateURL}
	now := epoch.Add(30 * time.Minute)
	base, err := e.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || base.Results[0].Snapshot == nil {
		t.Fatal(base, err)
	}
	sealMRTResult(t, e, base, now, binding)
	delete(fetch.assets, newBase)
	delete(fetch.assets, sources[1].URL)
	r, err := e.IngestMRT(context.Background(), sources, now.Add(6*time.Minute), binding, MRTIntakeOptions{Enabled: true, ReplayArchives: plans})
	if err != nil || r.Mode != "replayed_updates" || r.Results[0].Snapshot == nil {
		t.Fatal("rotated source could not replay actual collector", r, err)
	}
	p := r.Results[0].Snapshot.MRTProof
	if p.BaseArchiveURL != newBase || !p.BaseArchiveSelectedAt.Equal(now) || !p.Through.Equal(epoch.Add(5*time.Minute)) || !validMRTArchiveBinding(sources[0], p, now.Add(6*time.Minute)) {
		t.Fatal("replay relabeled actual base", p)
	}
	if !reflect.DeepEqual(base.Results[0].Snapshot.MRTProof.BasePayloadHash, p.BasePayloadHash) || !base.Results[0].Snapshot.PublishedAt.Equal(r.Results[0].Snapshot.PublishedAt) {
		t.Fatal("replay renewed original payload clock")
	}
}

func TestMRTArchive404SentinelIsStillAnAcquisitionFailure(t *testing.T) {
	if !errors.Is(acquire.ErrNotFound, acquire.ErrFetch) {
		t.Fatal("404 broke failure classification")
	}
}

func TestCatalogProjectsAndRejectsMRTArchiveRotationPolicy(t *testing.T) {
	const catalog = `schema_version: 3
sources:
- id: test-rotation
  evidence_family: test-rotation
  category: bgp
  admission: candidate
  scope: path
  coverage: {kind: mapping, scope: path}
  download:
    url: https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0800.gz
    format: mrt-gz
    max_compressed_mib: 128
    mrt_archive_policy: latest-complete-v1
  refresh: {max_stale: 720h}
  publication_proof:
    kind: embedded
    locator: https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0800.gz
    field: mrt_frame_capture_timestamp
  parser: {id: mrt-table-dump-v2, schema: mrt-table-dump-v2-unicast-v1, version: 1}
`
	sources, err := DecodeCatalog(strings.NewReader(catalog))
	if err != nil || len(sources) != 1 || sources[0].MRTArchivePolicy != latestCompleteMRTPolicy {
		t.Fatal("explicit archive policy lost", sources, err)
	}
	for _, bad := range []string{strings.ReplaceAll(catalog, "rrc18", "rrc00"), strings.Replace(catalog, "latest-complete-v1", "latest", 1), strings.Replace(catalog, "format: mrt-gz", "format: mrt-bz2", 1), strings.Replace(catalog, "category: bgp", "category: asn", 1)} {
		if _, err := DecodeCatalog(strings.NewReader(bad)); err == nil {
			t.Fatal("unreviewed catalog rotation accepted")
		}
	}
}

func TestLatestCompleteMRTArchivesKeepCollectorAndBoundPublicationLag(t *testing.T) {
	for _, row := range []struct{ seed, format, clock, latest, fallback string }{
		{"https://archive.routeviews.org/route-views.wide/bgpdata/2026.11/RIBS/rib.20261115.1200.bz2", "mrt-bz2", "2026-12-01T00:29:59Z", "https://archive.routeviews.org/route-views.wide/bgpdata/2026.11/RIBS/rib.20261130.2200.bz2", "https://archive.routeviews.org/route-views.wide/bgpdata/2026.11/RIBS/rib.20261130.2000.bz2"},
		{"https://archive.routeviews.org/route-views.wide/bgpdata/2026.11/RIBS/rib.20261115.1200.bz2", "mrt-bz2", "2026-12-01T00:30:00Z", "https://archive.routeviews.org/route-views.wide/bgpdata/2026.12/RIBS/rib.20261201.0000.bz2", "https://archive.routeviews.org/route-views.wide/bgpdata/2026.11/RIBS/rib.20261130.2200.bz2"},
		{"https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0800.gz", "mrt-gz", "2027-01-01T00:30:00Z", "https://data.ris.ripe.net/rrc18/2027.01/bview.20270101.0000.gz", "https://data.ris.ripe.net/rrc18/2026.12/bview.20261231.1600.gz"},
		{"https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0800.gz", "mrt-gz", "2026-11-15T16:29:59+08:00", "https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0000.gz", "https://data.ris.ripe.net/rrc18/2026.11/bview.20261114.1600.gz"},
	} {
		now, _ := time.Parse(time.RFC3339, row.clock)
		source := rotationSource(row.seed, row.format)
		urls, err := mrtRIBCandidates(source, now)
		if err != nil || len(urls) != 2 || urls[0] != row.latest || urls[1] != row.fallback || source.URL != row.seed || source.Publication.Locator != row.seed {
			t.Fatal("bounded latest archive plan changed configured identity", urls, err)
		}
	}
}

func TestMRTArchiveRotationRejectsUnreviewedControls(t *testing.T) {
	seed := "https://data.ris.ripe.net/rrc18/2026.11/bview.20261115.0800.gz"
	for _, change := range []func(*Source){
		func(s *Source) { s.MRTArchivePolicy = "latest" },
		func(s *Source) {
			s.URL = "https://data.ris.ripe.net/rrc00/2026.11/bview.20261115.0800.gz"
			s.Publication.Locator = s.URL
		},
		func(s *Source) {
			s.URL = "https://archive.routeviews.org/route-views3/bgpdata/2026.11/RIBS/rib.20261115.1200.bz2"
			s.Format = "mrt-bz2"
			s.Publication.Locator = s.URL
		},
		func(s *Source) { s.URL += "?x=1"; s.Publication.Locator = s.URL },
		func(s *Source) {
			s.URL = "https://data.ris.ripe.net:443/rrc18/2026.11/bview.20261115.0800.gz"
			s.Publication.Locator = s.URL
		},
		func(s *Source) {
			s.URL = "https://data.ris.ripe.net/rrc18/2026.10/bview.20261115.0800.gz"
			s.Publication.Locator = s.URL
		},
		func(s *Source) {
			s.URL = "https://data.ris.ripe.net/rrc18/2026.11/updates.20261115.0800.gz"
			s.Publication.Locator = s.URL
		},
		func(s *Source) { s.Format = "mrt-bz2" },
		func(s *Source) { s.Parser.ID = "mrt-bgp4mp" },
		func(s *Source) { s.Category = "asn" },
		func(s *Source) { s.Publication.Locator += "x" },
	} {
		source := rotationSource(seed, "mrt-gz")
		change(&source)
		if _, err := mrtRIBCandidates(source, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)); err == nil {
			t.Fatal("unreviewed archive controls accepted")
		}
	}
	source := rotationSource(seed, "mrt-gz")
	source.MRTArchivePolicy = ""
	urls, err := mrtRIBCandidates(source, time.Now())
	if err != nil || len(urls) != 1 || urls[0] != seed {
		t.Fatal("fixed source silently opted into rotation", urls, err)
	}
}
