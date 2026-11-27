package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func jacobrakaiTestSource(t *testing.T) Source {
	t.Helper()
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
		if source.ID == jacobrakaiID {
			return source
		}
	}
	t.Fatal("reviewed source absent")
	return Source{}
}

func jacobrakaiTestExcerpt(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	b, err := os.ReadFile("../../fixtures/source-certification/observed-jacobrakai-honeypot-excerpt.json")
	if err != nil {
		t.Fatal(err)
	}
	clock, err := timestamp("2026-11-22T03:00:02Z")
	if err != nil {
		t.Fatal(err)
	}
	return b, clock
}

// Turn the three rights-cleared original rows into a synthetic complete envelope.
// Only the count fields change. The reviewed excerpt is never a runtime proof.
func jacobrakaiTestEnvelope(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	b, clock := jacobrakaiTestExcerpt(t)
	for _, pair := range [][2]string{{`"count": 414`, `"count": 3`}, {`"credential": 277`, `"credential": 1`}, {`"loader": 28`, `"loader": 1`}, {`"scanner": 109`, `"scanner": 1`}} {
		if bytes.Count(b, []byte(pair[0])) != 1 {
			t.Fatal("fixture totals no longer match test contract")
		}
		b = bytes.ReplaceAll(b, []byte(pair[0]), []byte(pair[1]))
	}
	return b, clock
}

func TestJacobrakaiObservedExcerptAndCompletePayload(t *testing.T) {
	s := jacobrakaiTestSource(t)
	ctx := context.Background()
	adapter, ok := selectAdapter(s)
	if !ok || adapter != riskAdapter || !publicationSupported(s) {
		t.Fatal("reviewed source dispatch unavailable")
	}
	excerpt, clock := jacobrakaiTestExcerpt(t)
	capture, err := timestamp(s.Fixture.TestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := validateJacobrakaiExcerpt(ctx, bytes.NewReader(excerpt), s, adapter, capture); err != nil || count != 2 {
		t.Fatal("claimed observed fixture failed", count, err)
	}
	if _, err := verifyJacobrakaiFile(ctx, bytes.NewReader(excerpt), s, capture); err == nil {
		t.Fatal("excerpt proved complete publication")
	}
	b, _ := jacobrakaiTestEnvelope(t)
	if got, err := verifyJacobrakaiFile(ctx, bytes.NewReader(b), s, capture); err != nil || !got.Equal(clock) {
		t.Fatal("verified clock differs from embedded publisher result", got, err)
	}
	if _, err := verifyJacobrakaiFile(ctx, bytes.NewReader(b), s, clock.Add(-time.Second)); err == nil {
		t.Fatal("future publisher clock accepted")
	}
	var document struct{ IPs []jacobrakaiRow }
	if err := json.Unmarshal(b, &document); err != nil {
		t.Fatal(err)
	}
	wantSignals := []intelligence.Signal{"abuse", "scanner"}
	i := 0
	err = parseRiskPayload(ctx, bytes.NewReader(b), s, clock, 3, func(r intelligence.NormalizedRecord) error {
		if i >= len(wantSignals) || r.Kind != intelligence.RecordEvidence || r.Evidence.Scope != intelligence.Exact || r.Evidence.Family != s.Family || r.Evidence.Signal != wantSignals[i] || !r.Evidence.Current || r.Evidence.SubscriptionLiteral || r.Evidence.Weight != 0 || r.Evidence.Address.String() != document.IPs[i].Address || !r.Evidence.SourcePublishedAt.Equal(clock) || r.Evidence.ItemPublishedAt.Format(time.RFC3339) != document.IPs[i].LastSeen {
			t.Fatal("normalized observation is not exact and dated")
		}
		if wire, _ := json.Marshal(r); strings.Contains(string(wire), "attempt") || strings.Contains(string(wire), "first_banned") {
			t.Fatal("unrelated publisher metadata escaped normalization")
		}
		i++
		return r.Validate()
	})
	if err != nil || i != 2 {
		t.Fatal("wrong or missing tier observations", i, err)
	}

	for _, mut := range []func(*Source){
		func(s *Source) { s.Family = "unrelated-family" }, func(s *Source) { s.Weight++ },
		func(s *Source) { s.Publication.Locator = "https://example.invalid/" },
		func(s *Source) { s.URL = "https://example.invalid/" },
		func(s *Source) { s.Publication.Field = "last_seen" },
		func(s *Source) { s.Signals = []string{"malware", "scanner"} },
		func(s *Source) { s.Coverage = "complete" },
	} {
		bad := s
		mut(&bad)
		if _, ok := selectAdapter(bad); ok || publicationSupported(bad) {
			t.Fatal("changed exact positive-only source contract accepted")
		}
	}
}

func TestJacobrakaiRejectsChangedAndTruncatedEvidence(t *testing.T) {
	ctx := context.Background()
	s := jacobrakaiTestSource(t)
	b, clock := jacobrakaiTestEnvelope(t)
	var document struct{ IPs []jacobrakaiRow }
	if err := json.Unmarshal(b, &document); err != nil {
		t.Fatal(err)
	}
	bad := [][]byte{
		b[:len(b)/2], append(bytes.Clone(b), []byte("{}")...), make([]byte, jacobrakaiByteLimit+1),
	}
	for _, pair := range [][2]string{
		{`"CC0-1.0"`, `"MIT"`}, {`"window_days": 30`, `"window_days": 31`},
		{`"scanner_min_events": 1000`, `"scanner_min_events": 999`}, {`"count": 3`, `"count": 4`},
		{`"count": 3`, `"Count": 3, "count": 3`}, {`"credential": 1`, `"credential": 0`},
		{`"tier": "scanner"`, `"tier": "malware"`},
		{document.IPs[1].Address, document.IPs[0].Address}, {document.IPs[1].Address, "192.0.2.1"},
		{document.IPs[1].Address, "example.invalid:22"}, {document.IPs[1].Address, "2001:db8::1"},
		{document.IPs[1].LastSeen, "2099-11-22T03:00:02Z"}, {document.IPs[1].FirstSeen, "2000-01-01T00:00:00Z"},
		{`"first_banned": null`, `"unrecognized": null`},
	} {
		if !bytes.Contains(b, []byte(pair[0])) {
			t.Fatal("changed fixture no longer exercises case")
		}
		bad = append(bad, bytes.Replace(b, []byte(pair[0]), []byte(pair[1]), 1))
	}
	for i, body := range bad {
		if err := parseRiskPayload(ctx, bytes.NewReader(body), s, clock, 3, func(intelligence.NormalizedRecord) error {
			t.Fatalf("test %d: emitted before complete validated feed", i)
			return nil
		}); err == nil {
			t.Fatalf("test %d: invalid feed accepted", i)
		}
	}
	stop := errors.New("sink halted")
	if err := parseRiskPayload(ctx, bytes.NewReader(b), s, clock, 3, func(intelligence.NormalizedRecord) error { return stop }); !errors.Is(err, stop) {
		t.Fatal("sink failure lost")
	}
	if err := parseRiskPayload(ctx, bytes.NewReader(b), s, clock, 2, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
		t.Fatal("row limit failed to count and bound ignored tiers")
	}
}

func TestJacobrakaiServingAndProductionExpiry(t *testing.T) {
	s := jacobrakaiTestSource(t)
	b, clock := jacobrakaiTestEnvelope(t)
	_, values, err := readJacobrakai(context.Background(), bytes.NewReader(b), s, jacobrakaiRowLimit, false)
	if err != nil || len(values) != 2 {
		t.Fatal("synthetic fixture envelope failed", err)
	}
	r := values[0]
	expires := r.ItemPublishedAt.Add(jacobrakaiWindow)
	intake := expires.Add(-jacobrakaiServeSlack)
	if !jacobrakaiEligible(r.ItemPublishedAt, intake.Add(-time.Nanosecond)) || jacobrakaiEligible(r.ItemPublishedAt, intake) || jacobrakaiEligible(time.Time{}, clock) {
		t.Fatal("serving cutoff rounded or advanced")
	}
	r.Weight = s.Weight
	makeScan := func(expiry time.Time) *sourceRecordScan {
		return newSourceRecordScan(s, intelligence.SourceRecordClocks{ID: s.ID, PublishedAt: clock, ExpiresAt: expiry}, intake)
	}
	accept := func(scan *sourceRecordScan, e intelligence.Evidence) error {
		return scan.accept(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &e})
	}
	scan := makeScan(expires)
	if err := accept(scan, r); err != nil || accept(scan, r) == nil || accept(makeScan(expires.Add(time.Second)), r) == nil {
		t.Fatal("private-state scan allowed duplicate or extended expiry", err)
	}
	for _, mut := range []func(*intelligence.Evidence){
		func(e *intelligence.Evidence) { e.ItemPublishedAt = time.Time{} },
		func(e *intelligence.Evidence) { e.ItemPublishedAt = clock.Add(time.Second) },
		func(e *intelligence.Evidence) { e.Signal = "c2" },
		func(e *intelligence.Evidence) { e.Weight++ },
	} {
		bad := r
		mut(&bad)
		if accept(makeScan(expires), bad) == nil {
			t.Fatal("private-state scan accepted changed original observation")
		}
	}
}
