package admission

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

type fixtureFetch struct {
	assets map[string][]byte
	calls  int
	fail   bool
}

func (f *fixtureFetch) Fetch(ctx context.Context, raw, destination string, bound int64) (acquire.Result, error) {
	f.calls++
	data, ok := f.assets[raw]
	if !ok || f.fail || int64(len(data)) > bound || ctx.Err() != nil {
		return acquire.Result{}, acquire.ErrFetch
	}
	if err := os.WriteFile(destination, data, 0600); err != nil {
		return acquire.Result{}, err
	}
	return acquire.Result{SHA256: hashString(sha256.Sum256(data)), Bytes: int64(len(data))}, nil
}

func prepared(t *testing.T, payload []byte, format string) (*Engine, Source, *fixtureFetch, time.Time, [32]byte) {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "fixtures", "source-certification")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "internal"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "adapter.go"), []byte("package adapter\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(base, "unit-observed.csv")
	if err := os.WriteFile(fixturePath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	no := false
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	source := Source{ID: "unit-vrp", Family: "unit-rpki-family", Category: "rpki", Admission: "active", URL: "https://github.com/unit/publisher/releases/download/v1/vrp.csv", Format: format,
		MaxCompressedBytes: 1 << 20, MaxAge: 720 * time.Hour, Weight: 70,
		Rights: Rights{"reviewed", "allow", "https://github.com/unit/publisher/blob/main/LICENSE", "unit-test reviewed evidence only", &no},
		Parser: Parser{"vrp-csv", "asn-prefix-maxLength-csv-v1", 1}, Fixture: Fixture{"passed", "fixtures/source-certification/unit-observed.csv", hashString(sha256.Sum256(payload)), "vrp-csv", "asn-prefix-maxLength-csv-v1", now.Add(-time.Hour).Format(time.RFC3339), true, &no},
		Publication: Publication{"github_release", "https://api.github.com/repos/unit/publisher/releases/latest", "published_at"},
		Coverage:    "mapping", Scope: "prefix", PublicFields: []string{"rpki_status"}, Fields: []string{"roa"}, FieldMappings: map[string][]string{"roa": {"rpki_status"}}}
	implementation, err := implementationHash(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(implementation)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	metadata := metadataFor(t, source.URL, payload, now.Add(-2*time.Hour), now.Add(-time.Hour))
	fetch := &fixtureFetch{assets: map[string][]byte{source.URL: payload, source.Publication.Locator: metadata}}
	engine, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	engine.fetch = fetch
	t.Cleanup(func() { _ = engine.Close() })
	return engine, source, fetch, now, sha256.Sum256([]byte("unit-normalization-policy"))
}

func metadataFor(t *testing.T, url string, payload []byte, release, created time.Time) []byte {
	t.Helper()
	metadata := releaseMetadata{PublishedAt: release.Format(time.RFC3339), Assets: []releaseAsset{{URL: url, Digest: "sha256:" + hashString(sha256.Sum256(payload)), State: "uploaded", CreatedAt: created.Format(time.RFC3339), Size: int64(len(payload))}}}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVerifiedIntakeAndWithdrawal(t *testing.T) {
	payload := []byte("asn,prefix,maxLength\nAS13335,1.1.1.0/24,24\n")
	engine, source, fetch, now, policyHash := prepared(t, payload, "csv")
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Decision.State != "current" || result.Snapshot == nil || fetch.calls != 2 || len(result.Snapshot.Records) != 1 {
		t.Fatalf("intake = %v, %v, calls=%d", result, err, fetch.calls)
	}
	if result.Snapshot.PayloadHash != sha256.Sum256(payload) || result.Snapshot.PublishedAt != now.Add(-2*time.Hour) || result.Snapshot.Records[0].VRP.ASN != 13335 {
		t.Fatal("payload proof or normalized facts mismatch")
	}
	plan, err := intelligence.Reconcile(intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, policyHash)
	if err != nil || len(plan.State.Sources) != 1 {
		t.Fatalf("reconcile admitted snapshot: %v", err)
	}
	source.Admission = "retired"
	withdrawn, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || withdrawn.Snapshot != nil || fetch.calls != 2 {
		t.Fatal("withdrawal downloaded or retained a snapshot")
	}
	retracted, err := intelligence.Reconcile(plan.State, []intelligence.SourcePolicy{withdrawn.Policy}, nil, now, policyHash)
	if err != nil || !retracted.FullRebuild || len(retracted.State.Sources) != 0 || len(retracted.ChangedSources) != 1 {
		t.Fatal("withdrawn contribution survived")
	}
	assertNoRawIntake(t, engine.workspace)
}

func TestReviewFailuresDoNotDownload(t *testing.T) {
	for _, scenario := range []string{"candidate", "rights_unknown", "attribution", "parser_unknown", "fixture_changed", "implementation_changed", "public_fields", "field_mapping", "unsupported_clock"} {
		t.Run(scenario, func(t *testing.T) {
			engine, source, fetch, now, policyHash := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
			switch scenario {
			case "candidate":
				source.Admission = "candidate"
			case "rights_unknown":
				source.Rights.AttributionRequired = nil
			case "attribution":
				yes := true
				source.Rights.AttributionRequired = &yes
			case "parser_unknown":
				source.Parser.ID = "arbitrary-parser"
			case "fixture_changed":
				os.WriteFile(filepath.Join(engine.workspace, filepath.FromSlash(source.Fixture.Path)), []byte("different\n"), 0600)
			case "implementation_changed":
				os.WriteFile(filepath.Join(engine.workspace, "internal", "adapter.go"), []byte("package changed\n"), 0600)
			case "public_fields":
				source.PublicFields = append(source.PublicFields, "source_id")
			case "field_mapping":
				source.FieldMappings = map[string][]string{"roa": {"source_id"}}
			case "unsupported_clock":
				source.Publication.Kind = "snapshot_metadata"
			}
			result, err := engine.Ingest(context.Background(), source, now, policyHash)
			if err != nil || result.Snapshot != nil || result.Decision.State != "quarantined" || fetch.calls != 0 {
				t.Fatalf("failed controls performed IO: %v %v calls=%d", result, err, fetch.calls)
			}
		})
	}
}

func TestProofAndParserFailuresCleanQuarantine(t *testing.T) {
	for _, scenario := range []string{"digest", "wrong_asset", "stale", "duplicate_key", "missing", "malformed_payload"} {
		t.Run(scenario, func(t *testing.T) {
			engine, source, fetch, now, policyHash := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
			switch scenario {
			case "digest":
				fetch.assets[source.Publication.Locator] = metadataFor(t, source.URL, []byte("different"), now, now)
			case "wrong_asset":
				fetch.assets[source.Publication.Locator] = metadataFor(t, "https://github.com/unit/publisher/releases/download/v1/other.csv", fetch.assets[source.URL], now, now)
			case "stale":
				fetch.assets[source.Publication.Locator] = metadataFor(t, source.URL, fetch.assets[source.URL], now, now.Add(-721*time.Hour))
			case "duplicate_key":
				fetch.assets[source.Publication.Locator] = []byte(`{"published_at":"2026-11-08T00:00:00Z","PUBLISHED_AT":"2026-11-08T00:00:00Z","assets":[]}`)
			case "missing":
				fetch.fail = true
			case "malformed_payload":
				fetch.assets[source.URL] = []byte("asn,prefix,maxLength\n13335,bad,24\n")
				fetch.assets[source.Publication.Locator] = metadataFor(t, source.URL, fetch.assets[source.URL], now, now)
			}
			result, err := engine.Ingest(context.Background(), source, now, policyHash)
			if err != nil || result.Snapshot != nil || result.Decision.State == "current" {
				t.Fatalf("bad input accepted: %v %v", result, err)
			}
			assertNoRawIntake(t, engine.workspace)
		})
	}
}

func assertNoRawIntake(t *testing.T, workspace string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(workspace, ".atlas-private"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != clockName && entry.Name() != engineLockName || entry.IsDir() {
			t.Fatal("raw intake quarantine survived")
		}
	}
}

func TestIdenticalPayloadDoesNotRenewAcrossRuns(t *testing.T) {
	engine, source, fetch, now, policyHash := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil {
		t.Fatal("initial verified intake failed")
	}
	later := now.Add(719 * time.Hour)
	fetch.assets[source.Publication.Locator] = metadataFor(t, source.URL, fetch.assets[source.URL], later, later)
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := New(engine.workspace)
	if err != nil {
		t.Fatal(err)
	}
	next.fetch = fetch
	t.Cleanup(func() { _ = next.Close() })
	result, err = next.Ingest(context.Background(), source, later, policyHash)
	if err != nil || result.Snapshot != nil || result.Decision.State != "stale" {
		t.Fatalf("identical content clock renewed: %v %v", result, err)
	}
	assertNoRawIntake(t, engine.workspace)
}

func TestClockCanOnlyMoveEarlierAndInvalidHistoryBlocks(t *testing.T) {
	engine, source, fetch, now, policyHash := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil {
		t.Fatal("initial clock failed")
	}
	fetch.assets[source.Publication.Locator] = metadataFor(t, source.URL, fetch.assets[source.URL], now.Add(-5*time.Hour), now.Add(-4*time.Hour))
	result, err = engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil || result.Snapshot.PublishedAt != now.Add(-5*time.Hour) {
		t.Fatalf("earlier verified clock lost: %v %v", result, err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(engine.workspace)
	if err != nil || reloaded.clocks[sha256.Sum256(fetch.assets[source.URL])] != now.Add(-5*time.Hour) {
		t.Fatal("earlier publication was not atomically retained")
	}
	if err := reloaded.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engine.workspace, ".atlas-private", clockName), []byte(`{"schema_version":1,"receipts":[{"payload_sha256":"bad","published_at":"2026-11-08T00:00:00Z"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(engine.workspace); err == nil {
		t.Fatal("invalid prior clock history silently discarded")
	}
}

func TestCompressedIntakeAndCancellation(t *testing.T) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	writer.Write([]byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"))
	writer.Close()
	engine, source, _, now, policyHash := prepared(t, buffer.Bytes(), "csv-gz")
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil {
		t.Fatalf("bounded gzip rejected: %v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Ingest(ctx, source, now, policyHash); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestSubscriptionsRequireItemProof(t *testing.T) {
	engine, source, fetch, now, policyHash := prepared(t, []byte("unused"), "txt")
	source.Category, source.Family, source.Scope, source.Coverage = "proxy_subscription_ip", "public-subscription-aggregators", "exact_ip", "positive_only"
	source.Parser = Parser{"subscription-literal", "literal-ip-subscription-v1", 1}
	source.PublicFields = []string{"reason_flags"}
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot != nil || result.Decision.Reason != "verified_item_publication_time_required" || fetch.calls != 0 {
		t.Fatalf("container clock freshened subscription: %v %v", result, err)
	}
	record := subscription.Record{IP: netip.MustParseAddr("1.1.1.1"), Proxy: true, PublishedAt: now, Family: "public-subscription-aggregators"}
	if _, err := LiteralEvidence(record, now, time.Time{}, now); err == nil {
		t.Fatal("missing item clock accepted")
	}
	if _, err := LiteralEvidence(record, now, now.Add(-168*time.Hour), now); err == nil {
		t.Fatal("expired item accepted")
	}
	stripped, err := LiteralEvidence(record, now, now.Add(-time.Hour), now)
	if err != nil || stripped.Evidence.Address.String() != "1.1.1.1" || stripped.Evidence.Signal != "proxy" || stripped.Evidence.ItemPublishedAt.IsZero() {
		t.Fatal("verified literal conversion failed")
	}
}

func TestCurrentCatalogRemainsIneligibleWithoutIO(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "configs", "sources.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sources, err := DecodeCatalog(file)
	if err != nil || len(sources) != 91 {
		t.Fatalf("catalog projection: %d %v", len(sources), err)
	}
	fetch := &fixtureFetch{}
	engine, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	engine.fetch = fetch
	for _, source := range sources {
		result, err := engine.Ingest(context.Background(), source, time.Now(), sha256.Sum256([]byte("policy")))
		if err != nil || result.Snapshot != nil || result.Decision.State != "quarantined" {
			t.Fatalf("uncertified catalog source accepted: %v %v", result, err)
		}
	}
	if fetch.calls != 0 {
		t.Fatal("inactive catalog downloaded bytes")
	}
}

func TestCatalogRejectsAmbiguousYAML(t *testing.T) {
	for _, value := range []string{
		"schema_version: 3\nschema_version: 3\nsources: []\n",
		"schema_version: 3\nsources: &s []\ncopy: *s\n",
		"schema_version: 3\nsources: []\nextra: .inf\n",
		"schema_version: 3\nsources: []\n---\nschema_version: 3\n",
		"schema_version: 3\nsources: []\n1: value\n",
	} {
		if _, err := DecodeCatalog(strings.NewReader(value)); err == nil {
			t.Fatal("ambiguous YAML accepted")
		}
	}
}

func TestPublicationBindingAndJSONBounds(t *testing.T) {
	payload := []byte("payload")
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	url := "https://github.com/unit/publisher/releases/download/v1/asset"
	metadata := metadataFor(t, url, payload, now.Add(-time.Hour), now.Add(-700*time.Hour))
	published, err := verifyRelease(metadata, url, sha256.Sum256(payload), int64(len(payload)), now)
	if err != nil || published != now.Add(-700*time.Hour) {
		t.Fatal("release metadata refreshed an old asset")
	}
	for _, value := range []string{
		`{"key":1,"KEY":2}`, `{"s":1,"\u017f":2}`, "{\"x\":\"\xff\"}", strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34),
	} {
		if uniqueJSON([]byte(value)) == nil {
			t.Fatal("ambiguous or unbounded JSON accepted")
		}
	}
	for _, locator := range []string{"https://api.github.com/repos/other/publisher/releases/latest", "https://api.github.com/repos/unit/publisher/releases/latest?x=1", "https://api.github.com/repos/unit/publisher/releases/../latest", "http://api.github.com/repos/unit/publisher/releases/latest"} {
		if validReleaseLocator(locator, url) {
			t.Fatal("unbound metadata locator accepted")
		}
	}
}

func TestCertificationFingerprintBindsEveryReviewInput(t *testing.T) {
	for _, scenario := range []string{"ledger", "implementation", "active_fixture"} {
		t.Run(scenario, func(t *testing.T) {
			engine, source, _, _, _ := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
			before, err := CertificationFingerprint(context.Background(), engine.workspace, []Source{source})
			if err != nil {
				t.Fatal(err)
			}
			var path string
			switch scenario {
			case "ledger":
				path = filepath.Join(engine.workspace, "fixtures", "source-certification", "adapter-certifications.json")
			case "implementation":
				path = filepath.Join(engine.workspace, "internal", "adapter.go")
			case "active_fixture":
				path = filepath.Join(engine.workspace, filepath.FromSlash(source.Fixture.Path))
			}
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("\n"); err != nil {
				t.Fatal(err)
			}
			file.Close()
			after, err := CertificationFingerprint(context.Background(), engine.workspace, []Source{source})
			if err != nil || before == after {
				t.Fatalf("review input change escaped fingerprint: %v", err)
			}
		})
	}
}

func TestCertificationFingerprintBoundAndCancellation(t *testing.T) {
	engine, source, _, _, _ := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CertificationFingerprint(ctx, engine.workspace, []Source{source}); !errors.Is(err, context.Canceled) {
		t.Fatal("fingerprint cancellation lost")
	}
	file, err := os.OpenFile(filepath.Join(engine.workspace, filepath.FromSlash(source.Fixture.Path)), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate((64 << 20) + 1)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CertificationFingerprint(context.Background(), engine.workspace, []Source{source}); err == nil {
		t.Fatal("aggregate certification read budget exceeded")
	}
}

func TestRuntimeMRTRequiresDedicatedGlobalCoordinator(t *testing.T) {
	engine, source, fetch, now, policyHash := prepared(t, []byte("fixture"), "mrt-gz")
	source.Category, source.Scope, source.Coverage = "bgp", "path", "mapping"
	source.Parser = Parser{"mrt-table-dump-v2", "mrt-table-dump-v2-unicast-v1", 1}
	source.PublicFields = []string{"bgp_origins", "bgp_paths"}
	source.Fields = []string{"asn", "as_path"}
	source.FieldMappings = map[string][]string{"asn": {"bgp_origins"}, "as_path": {"bgp_paths"}}
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot != nil || result.Decision.Reason != "dedicated_mrt_acquisition_required" || fetch.calls != 0 {
		t.Fatalf("source label bypassed global MRT gate: %v %v", result, err)
	}
}

func TestCleanupFailureCannotReturnSuccessfulSnapshot(t *testing.T) {
	engine, source, _, now, policyHash := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	engine.cleanup = func(string) error { return errors.New("private-path-and-content-must-not-escape") }
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err == nil || result.Snapshot != nil || result.Decision.State != "invalid" || result.Decision.Reason != "private_quarantine_cleanup_failed" || strings.Contains(err.Error(), "must-not-escape") {
		t.Fatalf("failed cleanup treated as success or exposed content: %v %v", result, err)
	}
}

func TestEarlierClockUpdateAtReceiptCapacity(t *testing.T) {
	engine, _, _, now, _ := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	key := sha256.Sum256([]byte("known clock"))
	engine.clocks[key] = now
	for index := uint64(1); len(engine.clocks) < maxClockReceipts; index++ {
		var other [32]byte
		binary.LittleEndian.PutUint64(other[:8], index)
		engine.clocks[other] = now
	}
	earlier := now.Add(-time.Hour)
	retained, err := engine.retainClock(context.Background(), key, earlier)
	if err != nil || retained != earlier || len(engine.clocks) != maxClockReceipts {
		t.Fatalf("full history prevented stronger existing clock: %v", err)
	}
	if _, err := engine.retainClock(context.Background(), sha256.Sum256([]byte("new clock")), now); err == nil {
		t.Fatal("new clock exceeded receipt capacity")
	}
}

func TestEngineExclusivelyOwnsWorkspaceUntilClosed(t *testing.T) {
	engine, source, fetch, now, policyHash := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	if other, err := New(engine.workspace); err == nil {
		other.Close()
		t.Fatal("two preloaded engines can overwrite private clocks")
	}
	independent, err := New(t.TempDir())
	if err != nil {
		t.Fatal("independent workspace incorrectly locked")
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal("Close is not idempotent")
	}
	result, err := engine.Ingest(context.Background(), source, now, policyHash)
	if err == nil || result.Snapshot != nil || fetch.calls != 0 {
		t.Fatal("closed engine performed acquisition")
	}
	if _, err := engine.retainClock(context.Background(), sha256.Sum256([]byte("new")), now); err == nil {
		t.Fatal("closed engine wrote publication history")
	}
	next, err := New(engine.workspace)
	if err != nil {
		t.Fatalf("owned lock was not released: %v", err)
	}
	next.Close()
}

func TestStaleWorkspaceLockFailsClosed(t *testing.T) {
	workspace := t.TempDir()
	private := filepath.Join(workspace, ".atlas-private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, engineLockName)
	if err := os.WriteFile(path, []byte("unreviewed prior lock"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(workspace); err == nil {
		t.Fatal("stale lock automatically stolen")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "unreviewed prior lock" {
		t.Fatal("stale ownership evidence erased")
	}
}
