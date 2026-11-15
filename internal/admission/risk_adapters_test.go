package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func riskFixtureSource(id string) Source {
	s := Source{Family: "reviewed-aggregate", Category: "abuse", Coverage: "positive_only", Scope: "exact_ip", Format: "tsv", Signals: []string{"abuse"}, Fields: []string{"ip", "list_count"}, PublicFields: []string{"reason_flags"}, FieldMappings: map[string][]string{"ip": {"reason_flags"}},
		Parser: Parser{ID: "ip-count-tsv", Schema: "ip-positive-count-tsv-v1", Version: 1}}
	if id == "feodo-csv" {
		s.Format, s.Signals = "csv", []string{"c2", "botnet", "malware"}
		s.Fields, s.FieldMappings = []string{"dst_ip", "last_online"}, map[string][]string{"dst_ip": {"reason_flags"}}
		s.Parser = Parser{ID: id, Schema: "feodo-six-column-csv-v1", Version: 1}
	}
	return s
}

func TestRiskCountTSVDiscardsCountsAndCannotManufactureCoverage(t *testing.T) {
	s := riskFixtureSource("ip-count-tsv")
	var records []intelligence.NormalizedRecord
	published := time.Date(2026, 11, 9, 2, 4, 45, 0, time.UTC)
	err := parseRiskPayload(context.Background(), strings.NewReader("# Observed two-column shape; addresses below are test literals.\n1.1.1.1\t9\n2606:4700::1111\t1\n127.0.0.1\t99\n::ffff:1.1.1.1\t8\n"), s, published, 100, func(record intelligence.NormalizedRecord) error {
		records = append(records, record)
		return record.Validate()
	})
	if err != nil || len(records) != 3 {
		t.Fatalf("count feed parse: rows=%d err=%v", len(records), err)
	}
	for _, record := range records {
		e := record.Evidence
		if record.Kind != intelligence.RecordEvidence || e == nil || e.Scope != intelligence.Exact || e.Family != s.Family || e.Signal != "abuse" || e.Weight != 0 || !e.ItemPublishedAt.IsZero() || !e.SourcePublishedAt.Equal(published) {
			t.Fatal("count became independent evidence, weight or coverage")
		}
	}
	if records[2].Evidence.Address != netip.MustParseAddr("1.1.1.1") {
		t.Fatal("mapped literal was not normalized")
	}
}

func TestRiskCommonAdapterDispatchCannotManufactureAssessment(t *testing.T) {
	for _, id := range []string{"ip-count-tsv", "feodo-csv"} {
		t.Run(id, func(t *testing.T) {
			source := riskFixtureSource(id)
			source.MaxCompressedBytes = 1 << 20
			implementation, ok := selectAdapter(source)
			if !ok {
				t.Fatal("configured positive-only risk schema unavailable through common selector")
			}
			body := "1.1.1.1\t9\n"
			if id == "feodo-csv" {
				body = feodoRiskFixture()
			}
			file := geoTestFile(t, []byte(body))
			count := 0
			err := parsePayloadTo(context.Background(), file, int64(len(body)), source, implementation, time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC), 100, func(record intelligence.NormalizedRecord) error {
				count++
				if record.Kind != intelligence.RecordEvidence || record.Coverage != nil || record.Evidence == nil || record.Evidence.Scope != intelligence.Exact || record.Evidence.Weight != 0 {
					t.Fatal("positive feed manufactured assessment coverage or weight")
				}
				return record.Validate()
			})
			if err != nil || count == 0 {
				t.Fatal("common dispatcher did not invoke configured risk parser", count, err)
			}
			source.Coverage = "assessment"
			if _, ok = selectAdapter(source); ok {
				t.Fatal("positive parser accepted assessment coverage")
			}
		})
	}
}

func feodoRiskFixture() string {
	return "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)\n# Last updated: 2026-03-04 14:28:39 UTC\n" +
		"\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n" +
		"\"2022-06-04 21:24:53\",\"1.1.1.1\",\"8080\",\"offline\",\"2026-03-07\",\"Emotet\"\n" +
		"\"2026-03-04 14:28:39\",\"2606:4700::1111\",\"443\",\"online\",\"2026-03-05\",\"QakBot\"\n# END 2 entries\n"
}

func TestRiskFeodoPreservesItemClockAndImmediatelyDropsAllOtherColumns(t *testing.T) {
	s := riskFixtureSource("feodo-csv")
	published := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	var records []intelligence.NormalizedRecord
	err := parseRiskPayload(context.Background(), strings.NewReader(feodoRiskFixture()), s, published, 100, func(record intelligence.NormalizedRecord) error {
		records = append(records, record)
		return record.Validate()
	})
	if err != nil || len(records) != 6 {
		t.Fatalf("Feodo parse: rows=%d err=%v", len(records), err)
	}
	for i, record := range records {
		e := record.Evidence
		day := 7
		if i >= 3 {
			day = 5
		}
		if e == nil || !e.ItemPublishedAt.Equal(time.Date(2026, 3, day, 0, 0, 0, 0, time.UTC)) || !e.SourcePublishedAt.Equal(published) || e.Scope != intelligence.Exact {
			t.Fatal("wrapper clock replaced the old per-item observation clock")
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"Emotet", "QakBot", "8080", "dst_port", "offline", "hostname"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatal("publisher-only field survived normalization")
			}
		}
	}
}

func TestRiskAdaptersRejectSemanticRelabelingAndAssessmentCoverage(t *testing.T) {
	for _, id := range []string{"ip-count-tsv", "feodo-csv"} {
		original := riskFixtureSource(id)
		if !selectRiskAdapter(original) {
			t.Fatal("implemented schema not selectable")
		}
		for _, mutate := range []func(*Source){
			func(s *Source) { s.Signals = []string{"vpn"} },
			func(s *Source) { s.Signals = []string{"abuse", "abuse"} },
			func(s *Source) { s.Coverage = "assessment" },
			func(s *Source) { s.Scope = "prefix" },
			func(s *Source) { s.PublicFields = []string{"reason_flags", "usage_type"} },
			func(s *Source) { s.Parser.Schema = "unknown" },
		} {
			s := original
			mutate(&s)
			if selectRiskAdapter(s) {
				t.Fatal("unsupported source semantics accepted")
			}
		}
	}
}

func TestRiskAdaptersRejectChangedSchemasCorruptionAndPartialRows(t *testing.T) {
	for _, test := range []struct{ id, body string }{
		{"ip-count-tsv", "1.1.1.1 9\n"}, {"ip-count-tsv", "1.1.1.1\t0\n"}, {"ip-count-tsv", "1.1.1.1\t1.5\n"},
		{"ip-count-tsv", "1.1.1.1\t1\textra\n"}, {"ip-count-tsv", "example.invalid\t1\n"},
		{"ip-count-tsv", "http://user:secret@example.invalid:8080/path\t1\n"},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "dst_ip", "hostname", 1)},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "8080", "65536", 1)},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "offline", "uncertain", 1)},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "2026-03-07", "2026-02-30", 1)},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "1.1.1.1", "example.invalid", 1)},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "# END 2 entries\n", "", 1)},
		{"feodo-csv", strings.Replace(feodoRiskFixture(), "# END 2 entries", "# END 3 entries", 1)},
	} {
		if err := parseRiskPayload(context.Background(), strings.NewReader(test.body), riskFixtureSource(test.id), time.Now().UTC(), 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
			t.Fatalf("invalid %s input accepted", test.id)
		}
	}
}

func TestRiskAdaptersBoundRowsAndHonorCancellationAndSinkErrors(t *testing.T) {
	s := riskFixtureSource("ip-count-tsv")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parseRiskPayload(ctx, strings.NewReader("1.1.1.1\t1\n"), s, time.Now().UTC(), 100, func(intelligence.NormalizedRecord) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel lost: %v", err)
	}
	stop := errors.New("stop")
	if err := parseRiskPayload(context.Background(), strings.NewReader("1.1.1.1\t1\n"), s, time.Now().UTC(), 100, func(intelligence.NormalizedRecord) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("sink error lost: %v", err)
	}
	for _, body := range []string{"1.1.1.1\t1\n1.0.0.1\t1\n", strings.Repeat("x", (1<<20)+1)} {
		if err := parseRiskPayload(context.Background(), strings.NewReader(body), s, time.Now().UTC(), 1, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
			t.Fatal("row or value bound not enforced")
		}
	}
}

func TestObservedRiskFeedSchemas(t *testing.T) {
	directory := os.Getenv("ATLAS_RISK_OBSERVED_DIRECTORY")
	if directory == "" {
		t.Skip("private observed risk captures are not provided")
	}
	for _, test := range []struct {
		file, parser string
		records      int
	}{
		{"ipsum-list.bin", "ip-count-tsv", 132875},
		{"feodo-csv.bin", "feodo-csv", 15},
	} {
		t.Run(test.parser, func(t *testing.T) {
			file, err := os.Open(filepath.Join(directory, test.file))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			count := 0
			err = parseRiskPayload(context.Background(), file, riskFixtureSource(test.parser), time.Date(2026, 11, 9, 2, 4, 45, 0, time.UTC), 1_000_000, func(record intelligence.NormalizedRecord) error { count++; return record.Validate() })
			if err != nil || count != test.records {
				t.Fatalf("observed schema changed: count=%d err=%v", count, err)
			}
			t.Logf("Complete private capture parsed: %d normalized records; no admission decision made", count)
		})
	}
}

func FuzzRiskPayload(f *testing.F) {
	f.Add(false, []byte("1.1.1.1\t3\n"))
	f.Add(true, []byte(feodoRiskFixture()))
	f.Fuzz(func(t *testing.T, feodo bool, payload []byte) {
		if len(payload) > 2<<20 {
			t.Skip()
		}
		id := "ip-count-tsv"
		if feodo {
			id = "feodo-csv"
		}
		count := 0
		err := parseRiskPayload(context.Background(), strings.NewReader(string(payload)), riskFixtureSource(id), time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC), 4096, func(record intelligence.NormalizedRecord) error {
			count++
			if record.Kind != intelligence.RecordEvidence || record.Evidence == nil || !record.Evidence.Address.IsValid() || record.Evidence.Scope != intelligence.Exact {
				t.Fatal("nonliteral fact escaped risk parser")
			}
			return record.Validate()
		})
		if err == nil && count == 0 {
			t.Fatal("empty risk source accepted")
		}
	})
}
