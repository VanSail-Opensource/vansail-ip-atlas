package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func ffraudFixtureSource() Source {
	return Source{ID: "ffraud-ip", Family: "ffraud-original", Category: "abuse", Coverage: "positive_only", Scope: "exact_ip", Format: "csv", MaxCompressedBytes: 64 << 20, MaxAge: 720 * time.Hour,
		URL:         "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/threat-ips/confirmed-abusive.csv",
		Publication: Publication{"github_commit", "https://api.github.com/repos/FFraud-com/ip-fraud-database/commits?path=threat-ips%2Fconfirmed-abusive.csv&sha=main&per_page=1", "commit.committer.date"},
		Parser:      Parser{"ffraud-csv", "ffraud-five-column-risk-csv-v2", 2}, Fields: []string{"ip", "ffraud_score", "confirmations", "category", "type"}, PublicFields: []string{"reason_flags"}, FieldMappings: map[string][]string{"ip": {"reason_flags"}, "category": {"reason_flags"}, "type": {"reason_flags"}}, Signals: []string{"abuse", "botnet", "c2", "datacenter", "fraud", "malware", "proxy", "scanner", "spam", "tor", "vpn"}}
}

const ffraudTestHeader = "# Original publisher schema, synthetic test addresses.\nip,ffraud_score,confirmations,category,type\n"

func TestFFraudSelectsOnlyEachRowsReasonAndDropsPublisherScores(t *testing.T) {
	source := ffraudFixtureSource()
	if _, ok := selectAdapter(source); !ok {
		t.Fatal("FFraud schema not available through common dispatcher")
	}
	published := time.Date(2026, 11, 3, 21, 30, 44, 0, time.UTC)
	body := ffraudTestHeader
	labels := []string{"c2", "malware", "botnet", "brute_force", "web_attack", "scanner", "phishing", "spam", "abuse"}
	expected := []string{"c2", "malware", "botnet", "abuse", "abuse", "scanner", "fraud", "spam", "abuse"}
	for _, label := range labels {
		body += "1.1.1.1,95,40," + label + ",proxy\n"
	}
	body += "127.0.0.1,100,99,c2,tor\n::ffff:1.0.0.1,50,2,spam,\n2606:4700::1111,99,3,malware,mobile\n"
	var records []intelligence.NormalizedRecord
	err := parseRiskPayload(context.Background(), strings.NewReader(body), source, published, 100, func(r intelligence.NormalizedRecord) error { records = append(records, r); return r.Validate() })
	if err != nil || len(records) != 20 {
		t.Fatalf("parse count=%d err=%v", len(records), err)
	}
	for i, r := range records {
		e := r.Evidence
		if e == nil || r.Kind != intelligence.RecordEvidence || r.Coverage != nil || e.Family != source.Family || e.Scope != intelligence.Exact || e.Weight != 0 || !e.ItemPublishedAt.IsZero() || !e.SourcePublishedAt.Equal(published) {
			t.Fatal("publisher metadata became score, vote, coverage or item clock")
		}
		if i < len(expected)*2 && (i%2 == 0 && string(e.Signal) != expected[i/2] || i%2 == 1 && e.Signal != "proxy") {
			t.Fatal("configured signals assigned to every row", i, e.Signal)
		}
		encoded, _ := json.Marshal(r)
		for _, forbidden := range []string{"ffraud_score", "confirmations", "mobile", "usage_type"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatal("discarded publisher field survived", forbidden)
			}
		}
	}
	if records[18].Evidence.Address != netip.MustParseAddr("1.0.0.1") {
		t.Fatal("mapped literal not normalized")
	}
}

func TestFFraudRejectsSchemaDriftAndMalformedRows(t *testing.T) {
	good := "1.1.1.1,95,40,c2,proxy\n"
	for name, body := range map[string]string{
		"extra_item_date": strings.Replace(ffraudTestHeader, "category,type", "category,type,last_seen", 1) + "1.1.1.1,95,40,c2,proxy,2026-11-15\n",
		"missing_header":  good, "repeat_header": ffraudTestHeader + good + "ip,ffraud_score,confirmations,category,type\n",
		"unknown_reason":       ffraudTestHeader + strings.Replace(good, ",c2,", ",safe,", 1),
		"unknown_type":         ffraudTestHeader + strings.Replace(good, "proxy", "residential", 1),
		"low_score":            ffraudTestHeader + strings.Replace(good, ",95,", ",49,", 1),
		"high_score":           ffraudTestHeader + strings.Replace(good, ",95,", ",101,", 1),
		"fraction":             ffraudTestHeader + strings.Replace(good, ",95,", ",95.0,", 1),
		"one_confirmation":     ffraudTestHeader + strings.Replace(good, ",40,", ",1,", 1),
		"overflow":             ffraudTestHeader + strings.Replace(good, ",40,", ",4294967296,", 1),
		"negative":             ffraudTestHeader + strings.Replace(good, ",40,", ",-2,", 1),
		"hostname":             ffraudTestHeader + strings.Replace(good, "1.1.1.1", "example.invalid", 1),
		"url":                  ffraudTestHeader + strings.Replace(good, "1.1.1.1", "https://user:secret@example.invalid/", 1),
		"zone":                 ffraudTestHeader + strings.Replace(good, "1.1.1.1", "fe80::1%eth0", 1),
		"extra_field":          ffraudTestHeader + strings.TrimSuffix(good, "\n") + ",extra\n",
		"partial_final_row":    ffraudTestHeader + strings.TrimSuffix(good, "\n"),
		"blank_data_row":       ffraudTestHeader + good + "\n",
		"comment_after_header": ffraudTestHeader + good + "# new ignored date\n",
		"invalid_utf8":         ffraudTestHeader + good + "\xff\n",
		"nul":                  ffraudTestHeader + strings.Replace(good, "proxy", "proxy\x00", 1),
		"nonpublic_malformed":  ffraudTestHeader + "127.0.0.1,95,40,unknown,proxy\n",
		"empty":                ffraudTestHeader, "only_nonpublic": ffraudTestHeader + "127.0.0.1,95,40,c2,proxy\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := parseRiskPayload(context.Background(), strings.NewReader(body), ffraudFixtureSource(), time.Now().UTC(), 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
}

func TestFFraudRejectsSemanticRelabelingAndHonorsBounds(t *testing.T) {
	for _, mutate := range []func(*Source){func(s *Source) { s.Parser.Version = 1 }, func(s *Source) { s.Parser.Schema = "ffraud-five-column-risk-csv-v1" }, func(s *Source) { delete(s.FieldMappings, "type") }, func(s *Source) { s.FieldMappings["type"] = []string{"usage_type"} }, func(s *Source) { s.Signals = []string{"c2"} }, func(s *Source) { s.Signals = append(s.Signals, "hosting") }, func(s *Source) { s.Coverage = "assessment" }, func(s *Source) { s.Scope = "prefix" }, func(s *Source) { s.Fields = append(s.Fields, "last_seen") }, func(s *Source) { s.PublicFields = append(s.PublicFields, "usage_type") }, func(s *Source) { s.Format = "csv-gz" }} {
		s := ffraudFixtureSource()
		mutate(&s)
		if _, ok := selectAdapter(s); ok {
			t.Fatal("unsupported source semantics accepted")
		}
	}
	body := ffraudTestHeader + "1.1.1.1,95,40,c2,proxy\n"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sink := func(intelligence.NormalizedRecord) error { return nil }
	if err := parseRiskPayload(ctx, strings.NewReader(body), ffraudFixtureSource(), time.Now().UTC(), 100, sink); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	stop := errors.New("stop")
	if err := parseRiskPayload(context.Background(), strings.NewReader(body), ffraudFixtureSource(), time.Now().UTC(), 100, func(intelligence.NormalizedRecord) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("sink error lost", err)
	}
	for _, bad := range []string{body + "1.0.0.1,95,40,c2,proxy\n", ffraudTestHeader + strings.Repeat("x", 4097) + "\n"} {
		if err := parseRiskPayload(context.Background(), strings.NewReader(bad), ffraudFixtureSource(), time.Now().UTC(), 1, sink); err == nil {
			t.Fatal("bound ignored")
		}
	}
}

func TestFFraudInfrastructureSharesFamilyClockAndFixedWeights(t *testing.T) {
	source := ffraudFixtureSource()
	published := time.Date(2026, 11, 3, 21, 30, 44, 0, time.UTC)
	body := ffraudTestHeader
	for _, kind := range []string{"proxy", "vpn", "tor", "datacenter", "mobile", ""} {
		body += "1.1.1.1,50,2,abuse," + kind + "\n"
	}
	var evidence []intelligence.Evidence
	counts := map[intelligence.Signal]int{}
	err := parseRiskPayload(context.Background(), strings.NewReader(body), source, published, 100, func(r intelligence.NormalizedRecord) error {
		e := *r.Evidence
		if e.Family != source.Family || e.Address != netip.MustParseAddr("1.1.1.1") || e.Scope != intelligence.Exact || e.SubscriptionLiteral || e.Weight != 0 || !e.SourcePublishedAt.Equal(published) || !e.ItemPublishedAt.IsZero() || r.Usage != nil || r.Coverage != nil {
			return errors.New("infrastructure classification changed evidence semantics")
		}
		counts[e.Signal]++
		// Reconciliation supplies the reviewed source weight, not publisher score.
		e.Weight = 70
		evidence = append(evidence, e)
		return r.Validate()
	})
	want := map[intelligence.Signal]int{"abuse": 6, "proxy": 1, "vpn": 1, "tor": 1, "datacenter": 1}
	if err != nil || !reflect.DeepEqual(counts, want) {
		t.Fatal(counts, err)
	}
	f, err := os.Open("../../configs/scoring.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	policy, err := intelligence.LoadPolicy(f)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(rows []intelligence.Evidence) intelligence.QualityResult {
		engine, err := intelligence.NewEngine(policy, rows, nil, nil, published)
		if err != nil {
			t.Fatal(err)
		}
		quality, err := engine.Lookup(netip.MustParseAddr("1.1.1.1"))
		if err != nil {
			t.Fatal(err)
		}
		return quality
	}
	first := lookup(evidence)
	if first.Score == nil || first.Confidence != "low" || first.CoverageComplete {
		t.Fatal("one family gained independent coverage/confidence", first)
	}
	duplicated := append(append([]intelligence.Evidence(nil), evidence...), evidence...)
	if second := lookup(duplicated); !reflect.DeepEqual(first, second) {
		t.Fatal("duplicate rows supplied independent votes", first, second)
	}
	strongerMetadata := strings.ReplaceAll(strings.ReplaceAll(body, ",50,", ",100,"), ",2,", ",400,")
	var changed []intelligence.Evidence
	err = parseRiskPayload(context.Background(), strings.NewReader(strongerMetadata), source, published, 100, func(r intelligence.NormalizedRecord) error {
		e := *r.Evidence
		e.Weight = 70
		changed = append(changed, e)
		return nil
	})
	if err != nil || !reflect.DeepEqual(first, lookup(changed)) {
		t.Fatal("publisher score/report count changed fixed-weight result", err)
	}
}

func TestFFraudInputRowsAndNormalizedOutputHaveSeparateBudgets(t *testing.T) {
	body := ffraudTestHeader + "1.1.1.1,50,2,abuse,proxy\n"
	rows, err := scanFFraud(context.Background(), strings.NewReader(body), 1, nil)
	if err != nil || rows != 1 {
		t.Fatal("metadata counted output records instead of input rows", rows, err)
	}
	for _, bound := range []int{1, 2} {
		count := 0
		err := parseRiskPayload(context.Background(), strings.NewReader(body), ffraudFixtureSource(), time.Date(2026, 11, 3, 21, 30, 44, 0, time.UTC), bound, func(intelligence.NormalizedRecord) error { count++; return nil })
		if count > bound || (err == nil) != (bound == 2) {
			t.Fatal("second evidence bypassed normalized budget", bound, count, err)
		}
	}
}

func TestFFraudObservedExcerpt(t *testing.T) {
	f, err := os.Open("../../fixtures/source-certification/observed-ffraud.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	counts := map[intelligence.Signal]int{}
	err = parseRiskPayload(context.Background(), f, ffraudFixtureSource(), time.Date(2026, 11, 3, 21, 30, 44, 0, time.UTC), 100, func(r intelligence.NormalizedRecord) error { counts[r.Evidence.Signal]++; return r.Validate() })
	if err != nil || len(counts) != 10 || counts["fraud"] != 0 || counts["abuse"] != 3 || counts["proxy"] != 1 || counts["tor"] != 3 || counts["datacenter"] != 3 || counts["vpn"] != 1 {
		t.Fatal("observed category excerpt changed", counts, err)
	}
}

func TestFFraudCatalogControlsRemainInactive(t *testing.T) {
	f, err := os.Open("../../configs/sources.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sources, err := DecodeCatalog(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		if source.ID != "ffraud-ip" {
			continue
		}
		_, ok := selectAdapter(source)
		if !ok || !publicationSupported(source) || source.Admission != "candidate" || source.Fixture.Status != "passed" || source.Fixture.SHA256 == "" || source.Rights.Status != "reviewed" || source.Rights.Distribution != "allow" || source.Rights.Identifier != "MIT" {
			t.Fatal("candidate controls or implemented parser/publication binding changed")
		}
		return
	}
	t.Fatal("inactive FFraud candidate absent")
}
