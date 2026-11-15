package admission

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func TestProductionQualificationRejectsUnsealedOrIncompleteState(t *testing.T) {
	ctx := context.Background()
	e, s, _, now, binding := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	s.Rights.Identifier = "CC0-1.0"
	result, err := e.IngestPartitioned(ctx, s, now, binding)
	if err != nil || result.Snapshot == nil {
		t.Fatal(err, result)
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, e.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = intelligence.SavePartitionedState(ctx, e.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if _, err = QualifyProductionState(ctx, e.workspace, []Source{s}, now, binding); err == nil {
		t.Fatal("unsealed source state qualified")
	}
	if err = e.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	state, err := intelligence.VerifyPrivateStateSeal(ctx, e.workspace, binding)
	if err != nil {
		t.Fatal(err)
	}
	report, stats, err := RevalidateStoredSources(ctx, e.workspace, []Source{s}, state, now, binding)
	if err != nil || len(stats) != 1 || stats[0].Kinds[intelligence.RecordVRP-1] != 1 {
		t.Fatal(err, stats)
	}
	if err = report.RequireProduction(); err == nil {
		t.Fatal("VRP-only state qualified missing geography and paths")
	}
	for _, capability := range report.Capabilities {
		if capability.Capability == "rpki" && capability.Qualified {
			t.Fatal("a positive VRP row established complete negative coverage")
		}
	}
	if _, err = QualifyProductionState(ctx, e.workspace, []Source{s}, now, binding); err == nil {
		t.Fatal("incomplete source state promoted")
	}
	withdrawn := s
	withdrawn.Rights.Distribution = "deny"
	if _, _, err = RevalidateStoredSources(ctx, e.workspace, []Source{withdrawn}, state, now, binding); err == nil {
		t.Fatal("withdrawn rights retained")
	}
	if _, _, err = RevalidateStoredSources(ctx, e.workspace, []Source{s}, state, state.Sources[0].ExpiresAt, binding); err == nil {
		t.Fatal("expired source retained")
	}
	if (&ProductionQualification{}).VRPComplete() {
		t.Fatal("zero-value qualification asserted VRP completeness")
	}
}
func TestCapabilityReportRequiresActualFacts(t *testing.T) {
	stats := []SourceStatistics{{ID: "one", Family: "shared", Country: true, City: true, Coordinates: true}, {ID: "two", Family: "shared", Country: true, City: true, Coordinates: true}}
	report := deriveCapabilities(stats, time.Unix(1800000000, 0))
	for _, c := range report.Capabilities {
		if c.Capability == "country" && !c.Qualified {
			t.Fatal("country absent")
		}
		if (c.Capability == "region_city" || c.Capability == "coordinates") && c.Qualified {
			t.Fatal("correlated votes qualified city")
		}
	}
	stats[1].Family = "independent"
	report = deriveCapabilities(stats, time.Unix(1800000000, 0))
	for _, c := range report.Capabilities {
		if (c.Capability == "region_city" || c.Capability == "coordinates") && !c.Qualified {
			t.Fatal("independent observed city missing")
		}
	}
}

func TestPositiveRiskCapabilityDoesNotInventAbsentCategories(t *testing.T) {
	stats := []SourceStatistics{{ID: "positive", Family: "one", Exact: true, Signals: map[intelligence.Signal]bool{"tor": true}}}
	report := deriveCapabilities(stats, time.Unix(1800000000, 0))
	if report.ReleaseScope != "release-scope-v5" {
		t.Fatal(report.ReleaseScope)
	}
	for _, v := range report.Capabilities {
		if v.Capability == "risk_reasons" && !v.Qualified {
			t.Fatal("verified positive observation blocked by absent categories")
		}
	}
	stats[0].Signals = nil
	for _, v := range deriveCapabilities(stats, time.Unix(1800000000, 0)).Capabilities {
		if v.Capability == "risk_reasons" && v.Qualified {
			t.Fatal("empty observations qualified risk")
		}
	}
}
func TestRightsDigestCanonicalUTF8(t *testing.T) {
	no := false
	s := Source{Rights: Rights{Identifier: "CC0-1.0", Status: "reviewed", Distribution: "allow", EvidenceURL: "https://example.com/LICENSE", ReviewBasis: "reviewed Å & text", AttributionRequired: &no}}
	got, credit, err := RightsDigests(s)
	if err != nil || credit != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(`{"attribution_required":false,"distribution":"allow","evidence_url":"https://example.com/LICENSE","identifier":"CC0-1.0","review_basis":"reviewed Å & text","status":"reviewed"}`))
	if got != digestTest(want) {
		t.Fatal("rights digest differs from Python canonical object", got)
	}
}
func digestTest(hash [32]byte) string { return hashString(hash) }

func TestRightsDigestIncludesExactLogoNotice(t *testing.T) {
	yes := true
	source := Source{Rights: Rights{Identifier: "CC0-1.0", Status: "reviewed", Distribution: "allow", EvidenceURL: "https://example.com/LICENSE", ReviewBasis: "synthetic review", AttributionRequired: &yes, Attribution: &intelligence.DatasetAttribution{Name: "Synthetic", Text: "Required credit", URL: "https://example.com", Logo: &intelligence.DatasetLogo{Alt: "Publisher", Path: "/_atlas/legal/" + strings.Repeat("a", 64) + ".png", SHA256: strings.Repeat("a", 64)}}}}
	first, credit, err := RightsDigests(source)
	if err != nil || credit == nil {
		t.Fatal(err)
	}
	source.Rights.Attribution.Logo.Alt = "Changed publisher logo"
	next, nextCredit, err := RightsDigests(source)
	if err != nil || next == first || nextCredit == nil || *nextCredit == *credit {
		t.Fatal("logo change did not invalidate rights digest", err)
	}
}

func TestCanonicalPrivateJSONUnicodeAndLiteralEscapes(t *testing.T) {
	value := struct {
		Text string `json:"text"`
	}{"actual:\u2028\u2029 literal:\\u2028 slash-actual:\\\u2028 & <>"}
	data, err := CanonicalPrivateJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("{\"text\":\"actual:\u2028\u2029 literal:\\\\u2028 slash-actual:\\\\\u2028 & <>\"}")
	if string(data) != string(want) {
		t.Fatalf("canonical Unicode mismatch: %q", data)
	}
	var decoded struct {
		Text string `json:"text"`
	}
	if err = json.Unmarshal(data, &decoded); err != nil || decoded.Text != value.Text {
		t.Fatal("canonical conversion changed string semantics", err)
	}
}

// This optional full-payload observation is intentionally absent from hosted
// artifacts. It exercises captured, hash-verified real rows beyond a tiny
// structural fixture without treating a private capture as source admission.
func TestObservedPrivateCountryCapacity(t *testing.T) {
	base := filepath.Join("..", "..", "build-private", "qualification-20261109")
	for _, name := range []string{"user-country-ipv4.csv", "server-country-ipv4.csv", "user-country-ipv6.csv"} {
		file, err := os.Open(filepath.Join(base, name))
		if os.IsNotExist(err) {
			t.Skip("private complete country snapshots absent")
		}
		if err != nil {
			t.Fatal(err)
		}
		var count uint64
		s := bulkSource("country-range-csv", "start-end-country-csv-v1")
		err = parseBulkPayload(context.Background(), file, s, time.Date(2026, 11, 9, 0, 44, 57, 0, time.UTC), 100_000_000, func(v intelligence.NormalizedRecord) error { count++; return v.Validate() })
		file.Close()
		if err != nil {
			t.Fatal(name, err)
		}
		if count < 100000 {
			t.Fatal("unexpectedly small full snapshot")
		}
		t.Logf("%s: %d normalized prefixes", name, count)
		data, _ := json.Marshal(struct {
			SchemaVersion    int    `json:"schema_version"`
			File             string `json:"file"`
			Records          uint64 `json:"normalized_records"`
			AdmissionChanged bool   `json:"admission_changed"`
		}{1, name, count, false})
		if err = os.WriteFile(filepath.Join(base, name+".parser.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
