package admission

import (
	"bytes"
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func caidaTestSource() Source {
	return Source{ID: "caida-asrel2", Family: "caida-asrel", Category: "bgp", Admission: "active", Format: "text-bz2", MaxCompressedBytes: 16 << 20, MaxAge: 720 * time.Hour,
		Parser: Parser{"caida-relationships", "asn-asn-relation-pipe-v1", 1}, Publication: Publication{"embedded", intelligence.CAIDASerial2Index, "topology_observation_date"},
		Discovery: &Discovery{Mode: "latest-timestamped-asset", IndexURL: intelligence.CAIDASerial2Index, FilenamePattern: caidaFilenamePattern, Ordering: "filename-date-desc-then-url-bytes", RequiresExactFile: true, NoGuessing: true},
		Scope:     "asn_edge", Coverage: "mapping", Fields: []string{"as_relationship"}, PublicFields: []string{"as_relationships"}, FieldMappings: map[string][]string{"as_relationship": {"as_relationships"}}}
}

const caidaTestBody = "# source:topology|BGP|20261105|routeviews|eqix\n# source:topology|BGP|20261101|ripe|rrc00\n# source:topology|looking-glass|20261103|mlp|lg8714\n# input clique: 174 209\n# IXP ASes: 1200\n1|54043|-1|bgp\n174|209|0|bgp,mlp\n"

func TestCAIDAEarliestInputClockAndDirectedRelations(t *testing.T) {
	var got []intelligence.NormalizedRecord
	proof, err := parseCAIDASerial2(context.Background(), strings.NewReader(caidaTestBody), 100, func(record intelligence.NormalizedRecord) error { got = append(got, record); return record.Validate() })
	first := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if err != nil || !proof.FirstObservedAt.Equal(first) || !proof.LastObservedAt.Equal(first.Add(4*24*time.Hour)) || proof.Rows != 2 || proof.Headers != 3 || proof.BGPHeaders != 2 || len(got) != 2 {
		t.Fatal(proof, got, err)
	}
	if *got[0].Relationship != (intelligence.RelationshipRecord{From: 1, To: 54043, Relation: intelligence.Customer}) || got[1].Relationship.Relation != intelligence.Peer {
		t.Fatal("direction or peer semantics changed", got)
	}
	older := strings.Replace(caidaTestBody, "looking-glass|20261103", "looking-glass|20261030", 1)
	proof, err = parseCAIDASerial2(context.Background(), strings.NewReader(older), 100, func(intelligence.NormalizedRecord) error { return nil })
	if err != nil || !proof.FirstObservedAt.Equal(first.Add(-48*time.Hour)) {
		t.Fatal("newer BGP inputs renewed older looking-glass input", proof, err)
	}
}

func TestCAIDARejectsHostileHeadersAndTail(t *testing.T) {
	for name, body := range map[string]string{
		"missing clock":      "1|54043|-1|bgp\n",
		"looking glass only": strings.ReplaceAll(caidaTestBody, "|BGP|", "|looking-glass|"),
		"invalid date":       strings.Replace(caidaTestBody, "20261101", "20260230", 1),
		"undated field":      strings.Replace(caidaTestBody, "20261101", "", 1),
		"unknown topology":   strings.Replace(caidaTestBody, "|BGP|", "|unknown|", 1),
		"unknown header":     "# Last-Modified: 2026-11-15\n" + caidaTestBody,
		"duplicate":          "# source:topology|BGP|20261105|routeviews|eqix\n" + caidaTestBody,
		"late header":        caidaTestBody + "# source:topology|BGP|20261115|ripe|rrc01\n",
		"unknown provenance": strings.Replace(caidaTestBody, "|bgp\n", "|unknown\n", 1),
		"missing column":     strings.Replace(caidaTestBody, "|bgp\n", "\n", 1),
		"bad final row":      caidaTestBody + "1|bad|-1|bgp\n",
		"partial final line": strings.TrimSuffix(caidaTestBody, "\n"),
		"UTF8":               strings.Replace(caidaTestBody, "# input clique: ", "# input clique: \xff", 1),
		"large header":       "# input clique: " + strings.Repeat("1", 1<<20) + "\n" + caidaTestBody,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCAIDASerial2(context.Background(), strings.NewReader(body), 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
				t.Fatal("hostile body accepted")
			}
		})
	}
	if _, err := parseCAIDASerial2(context.Background(), strings.NewReader(caidaTestBody), 1, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
		t.Fatal("record budget ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseCAIDASerial2(ctx, strings.NewReader(caidaTestBody), 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
		t.Fatal("cancellation ignored")
	}
	want := errors.New("sink failed")
	if _, err := parseCAIDASerial2(context.Background(), strings.NewReader(caidaTestBody), 100, func(intelligence.NormalizedRecord) error { return want }); !errors.Is(err, want) {
		t.Fatal("sink failure lost", err)
	}
}

func caidaTestIndex(body string) []byte { return []byte("<html>" + body + "</html>") }

func TestCAIDAIndexSelectsExactNewestWithoutClockSubstitution(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	index := `<a href="20261101.as-rel2.txt.bz2">old display date</a><a href="20261001.as-rel2.txt.bz2">new display date</a>`
	url, err := resolveCAIDASerial2Index(caidaTestIndex(index), now)
	if err != nil || url != intelligence.CAIDASerial2Index+"20261101.as-rel2.txt.bz2" {
		t.Fatal(url, err)
	}
	for _, name := range []string{"20261201.as-rel2.txt.bz2", "20261102.as-rel2.txt.bz2", "20260230.as-rel2.txt.bz2", "../20261101.as-rel2.txt.bz2", "https://evil.test/20261101.as-rel2.txt.bz2", "20261101.as-rel2.txt.bz2?x=1", "20261101.as-rel2.txt.bz2"} {
		if _, err := resolveCAIDASerial2Index(caidaTestIndex(index+`<a href="`+name+`">x</a>`), now); err == nil {
			t.Fatal("bad or duplicate candidate accepted", name)
		}
	}
	for _, body := range [][]byte{[]byte("<html>" + index), caidaTestIndex(index + `<a href='20261201.as-rel2.txt.bz2'>x</a>`), caidaTestIndex(index + `<a href=20261201.as-rel2.txt.bz2>x</a>`), caidaTestIndex(index + `<A href="20261201.as-rel2.txt.bz2">x</A>`), caidaTestIndex(index + `<a href="20261201.as&#45;rel2.txt.bz2">x</a>`), caidaTestIndex(strings.Repeat("x", 1<<20))} {
		if _, err := resolveCAIDASerial2Index(body, now); err == nil {
			t.Fatal("incomplete, oversized or changed index schema accepted")
		}
	}
	s := caidaTestSource()
	if !publicationSupported(s) {
		t.Fatal("valid discovery contract rejected")
	}
	for _, mutate := range []func(*Source){func(s *Source) { s.URL = intelligence.CAIDASerial2Index + "20261101.as-rel2.txt.bz2" }, func(s *Source) { s.Discovery.NoGuessing = false }, func(s *Source) { s.Discovery.IndexURL = "https://evil.test/" }, func(s *Source) { s.Publication.Field = "filename" }} {
		s = caidaTestSource()
		mutate(&s)
		if publicationSupported(s) {
			t.Fatal("unbound discovery contract accepted")
		}
	}
}

func TestCAIDACatalogProjectsStableDiscoveryControls(t *testing.T) {
	body := `schema_version: 3
sources:
- id: caida-asrel2
  evidence_family: caida-asrel
  category: bgp
  admission: candidate
  scope: asn_edge
  download: {url: null, format: text-bz2, max_compressed_mib: 16}
  refresh: {max_stale: 720h}
  parser: {id: caida-relationships, schema: asn-asn-relation-pipe-v1, version: 1}
  publication_proof: {kind: embedded, locator: 'https://publicdata.caida.org/datasets/as-relationships/serial-2/', field: topology_observation_date}
  discovery:
    mode: latest-timestamped-asset
    index_url: https://publicdata.caida.org/datasets/as-relationships/serial-2/
    filename_pattern: '^[0-9]{8}\.as-rel2\.txt\.bz2$'
    ordering: filename-date-desc-then-url-bytes
    requires_exact_file: true
    no_guessing: true
  fields: [as_relationship]
  field_mappings: {as_relationship: as_relationships}
  public_fields: [as_relationships]
  coverage: {kind: mapping, scope: asn_edge}
`
	catalog, err := DecodeCatalog(strings.NewReader(body))
	if err != nil || len(catalog) != 1 || !caidaSource(catalog[0]) || catalog[0].URL != "" {
		t.Fatal(catalog, err)
	}
	before, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, month := range []string{"20261001", "20261101"} {
		if _, err := resolveCAIDASerial2Index(caidaTestIndex(`<a href="`+month+`.as-rel2.txt.bz2">x</a>`), time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := json.Marshal(catalog)
	if !bytes.Equal(before, after) {
		t.Fatal("monthly discovery mutated configured catalog identity")
	}
}

func caidaObservedFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../fixtures/source-certification/observed-caida-asrel2.txt.bz2")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCAIDAObservedHeaderAndCompleteArchive(t *testing.T) {
	data := caidaObservedFixture(t)
	decoded, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := parseCAIDASerial2(context.Background(), bytes.NewReader(decoded), 100, func(r intelligence.NormalizedRecord) error { return r.Validate() })
	if err != nil || proof.Headers != 173 || proof.BGPHeaders != 170 || proof.Rows != 5 || proof.FirstObservedAt.Format(time.RFC3339) != "2026-11-01T00:00:00Z" || proof.LastObservedAt.Format(time.RFC3339) != "2026-11-05T00:00:00Z" {
		t.Fatal(proof, err)
	}
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for name, body := range map[string][]byte{"valid": data, "truncated": data[:len(data)-1], "trailing": append(append([]byte{}, data...), 0), "concatenated": append(append([]byte{}, data...), data...)} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "payload")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			proof, err := verifyCAIDAFile(context.Background(), path, int64(len(body)), caidaTestSource(), intelligence.CAIDASerial2Index+"20261101.as-rel2.txt.bz2", sha256.Sum256([]byte("index")), sha256.Sum256(body), now)
			if (err == nil) != (name == "valid") {
				t.Fatal(proof, err)
			}
		})
	}
}

func TestCAIDAIngestPartitionedBindsDiscoveryAndEarliestClock(t *testing.T) {
	data := caidaObservedFixture(t)
	e, base, fetch, _, binding := prepared(t, data, "text-bz2")
	s := caidaTestSource()
	s.Fixture, s.Rights = base.Fixture, base.Rights
	s.Fixture.Parser, s.Fixture.Schema = s.Parser.ID, s.Parser.Schema
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	code, err := implementationHash(context.Background(), e.workspace)
	if err != nil {
		t.Fatal(err)
	}
	ledgerBytes, _ := json.Marshal(ledger{1, []certification{{s.ID, s.Parser.ID, s.Parser.Schema, 1, s.Fixture.SHA256, s.Fixture.TestedAt, hashString(code)}}})
	if err := os.WriteFile(filepath.Join(e.workspace, "fixtures/source-certification/adapter-certifications.json"), ledgerBytes, 0600); err != nil {
		t.Fatal(err)
	}
	index := caidaTestIndex(`<a href="20261101.as-rel2.txt.bz2">2026-11-15</a>`)
	asset := intelligence.CAIDASerial2Index + "20261101.as-rel2.txt.bz2"
	fetch.assets = map[string][]byte{intelligence.CAIDASerial2Index: index, asset: data}
	result, err := e.IngestPartitioned(context.Background(), s, now, binding)
	if err != nil || result.Snapshot == nil || fetch.calls != 2 || len(result.Snapshot.Records) != 0 || len(result.Snapshot.RecordPartitions) == 0 {
		t.Fatal(result, err, fetch.calls)
	}
	proof := result.Snapshot.CAIDAProof
	if proof == nil || proof.AssetURL != asset || proof.IndexSHA256 != sha256.Sum256(index) || proof.PayloadSHA256 != sha256.Sum256(data) || result.Snapshot.PublishedAt.Format(time.RFC3339) != "2026-11-01T00:00:00Z" {
		t.Fatal("selected asset or clock unbound", proof)
	}
	plan, err := intelligence.ReconcilePartitioned(context.Background(), e.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil || len(plan.State.Sources) != 1 || plan.State.Sources[0].ExpiresAt.Format(time.RFC3339) != "2026-12-01T00:00:00Z" || plan.State.Sources[0].Receipt.CAIDAProof.AssetURL != asset {
		t.Fatal(plan, err)
	}
	if err := intelligence.SavePartitionedState(context.Background(), e.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err := e.SealPrivateState(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	state, _, validation, err := validateSourceSet(context.Background(), e.workspace, []Source{s}, now, binding)
	if err != nil || validation == nil || state.Sources[0].Receipt.CAIDAProof.PayloadSHA256 != sha256.Sum256(data) {
		t.Fatal("sealed CAIDA receipt did not revalidate", err)
	}
	state.Sources[0].Receipt.CAIDAProof.Rows++
	if _, _, err := RevalidateStoredSources(context.Background(), e.workspace, []Source{s}, state, now, binding); err == nil {
		t.Fatal("stored CAIDA count bypassed actual partitions")
	}
	state.Sources[0].Receipt.CAIDAProof.Rows--
	state.Sources[0].Receipt.CAIDAProof = nil
	if _, _, err := RevalidateStoredSources(context.Background(), e.workspace, []Source{s}, state, now, binding); err == nil {
		t.Fatal("stored CAIDA missing proof accepted")
	}
	// Filename and index display timestamps cannot renew old body headers.
	fetch.assets[intelligence.CAIDASerial2Index] = caidaTestIndex(`<a href="20261201.as-rel2.txt.bz2">2026-12-01</a>`)
	fetch.assets[intelligence.CAIDASerial2Index+"20261201.as-rel2.txt.bz2"] = data
	stale, err := e.IngestPartitioned(context.Background(), s, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), binding)
	if err != nil || stale.Snapshot != nil || stale.Decision.State != "stale" {
		t.Fatal("fresh filename renewed stale input", stale, err)
	}
	// No older-file retry when the selected newest archive is corrupt.
	fetch.assets[intelligence.CAIDASerial2Index] = caidaTestIndex(`<a href="20261101.as-rel2.txt.bz2">x</a><a href="20261001.as-rel2.txt.bz2">x</a>`)
	fetch.assets[asset] = []byte("corrupt")
	before := fetch.calls
	bad, err := e.IngestPartitioned(context.Background(), s, now, binding)
	if err != nil || bad.Snapshot != nil || fetch.calls-before != 2 {
		t.Fatal("bad latest asset fell back", bad, err, fetch.calls-before)
	}
}

func TestCAIDACompletePrivateCapture(t *testing.T) {
	path := os.Getenv("ATLAS_CAIDA_OBSERVED_FILE")
	if path == "" {
		t.Skip("private complete capture not supplied")
	}
	ctx := context.Background()
	s := caidaTestSource()
	hash, size, err := hashFile(ctx, path, s.MaxCompressedBytes)
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(filepath.Dir(path), "caida-serial2-index-observed.html"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 15, 13, 1, 55, 0, time.UTC)
	asset, err := resolveCAIDASerial2Index(index, now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifyCAIDAFile(ctx, path, size, s, asset, sha256.Sum256(index), hash, now)
	if err != nil || proof.Rows != 680178 || proof.Headers != 173 || proof.BGPHeaders != 170 || proof.FirstObservedAt.Format(time.RFC3339) != "2026-11-01T00:00:00Z" || proof.LastObservedAt.Format(time.RFC3339) != "2026-11-05T00:00:00Z" {
		t.Fatal(proof, err)
	}
	if hashString(hash) != "14c2137b8a9390c36da7dea8ec74ab93069828b58dbeb2f279688cf06c41dbf4" {
		t.Fatal("private diagnostic capture changed")
	}
}
