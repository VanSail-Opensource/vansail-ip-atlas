package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestReviewedDatasetAttributionIsBoundAndRetractsWhenRemoved(t *testing.T) {
	payload := []byte("asn,prefix,maxLength\nAS13335,1.1.1.0/24,24\n")
	engine, source, _, now, hash := prepared(t, payload, "csv")
	yes := true
	source.Rights.AttributionRequired = &yes
	source.Rights.Attribution = &intelligence.DatasetAttribution{Name: "Synthetic Dataset", Text: "Copyright Synthetic Author", URL: "https://example.com/data", LicenseURL: "https://example.com/license"}
	result, err := engine.Ingest(context.Background(), source, now, hash)
	if err != nil || result.Decision.State != "current" || result.Snapshot == nil {
		t.Fatal("reviewed global attribution rejected", result.Decision, err)
	}
	first, err := intelligence.Reconcile(intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, hash)
	if err != nil || len(first.State.Sources) != 1 || first.State.Sources[0].Attribution == nil || *first.State.Sources[0].Attribution != *source.Rights.Attribution {
		t.Fatal("attribution receipt missing", err)
	}
	if err := intelligence.SavePrivateState(engine.workspace, first.State); err != nil {
		t.Fatal(err)
	}
	stored, err := intelligence.LoadPrivateState(engine.workspace)
	if err != nil || stored.Sources[0].Attribution == nil || *stored.Sources[0].Attribution != *source.Rights.Attribution {
		t.Fatal("private credit persistence changed", err)
	}
	encoded, err := json.Marshal(first.State.Sources[0].Records)
	if err != nil || strings.Contains(string(encoded), "Synthetic Dataset") || strings.Contains(string(encoded), "example.com") {
		t.Fatal("global attribution entered normalized IP records", err)
	}
	changed := result.Policy
	copy := *changed.Attribution
	copy.Text = "Copyright Revised Synthetic Author"
	changed.Attribution = &copy
	next, err := intelligence.Reconcile(first.State, []intelligence.SourcePolicy{changed}, []intelligence.SourceSnapshot{*result.Snapshot}, now, hash)
	if err != nil || !next.FullRebuild || next.State.Sources[0].Fingerprint == first.State.Sources[0].Fingerprint {
		t.Fatal("credit edit reused old receipt", err)
	}
	changed.Attribution = nil
	withdrawn, err := intelligence.Reconcile(next.State, []intelligence.SourcePolicy{changed}, []intelligence.SourceSnapshot{*result.Snapshot}, now, hash)
	if err != nil || len(withdrawn.State.Sources) != 0 || !withdrawn.FullRebuild {
		t.Fatal("required-credit removal kept data eligible", err)
	}
}

func TestCatalogDatasetAttributionIsStrictAndTyped(t *testing.T) {
	for _, item := range []struct {
		name, credit string
		valid        bool
	}{
		{"valid", `{name: "Synthetic Dataset", text: "Copyright Synthetic Author", url: "https://example.com/data", license_url: "https://example.com/license"}`, true},
		{"unknown-field", `{name: "Synthetic Dataset", text: "Copyright Synthetic Author", url: "https://example.com/data", source_id: "must-stay-private"}`, false},
		{"missing-text", `{name: "Synthetic Dataset", url: "https://example.com/data"}`, false},
		{"private-license", `{name: "Synthetic Dataset", text: "Copyright Synthetic Author", url: "https://example.com/data", license_url: "https://10.0.0.1/license"}`, false},
		{"control", `{name: "Synthetic Dataset", text: "Copyright\nHidden", url: "https://example.com/data"}`, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			document := fmt.Sprintf("schema_version: 3\nsources:\n- id: synthetic\n  evidence_family: synthetic\n  scope: prefix\n  refresh: {max_stale: 720h}\n  coverage: {scope: prefix}\n  license:\n    status: reviewed\n    distribution: allow\n    attribution_required: true\n    attribution: %s\n", item.credit)
			sources, err := DecodeCatalog(strings.NewReader(document))
			if !item.valid {
				if err == nil {
					t.Fatal("invalid attribution object accepted")
				}
				return
			}
			if err != nil || len(sources) != 1 || sources[0].Rights.Attribution == nil || sources[0].Rights.Attribution.Name != "Synthetic Dataset" {
				t.Fatal("typed attribution projection changed", err)
			}
		})
	}
}

func TestInvalidDatasetCreditCannotAuthorizeIntake(t *testing.T) {
	for _, kind := range []string{"unreviewed", "missing", "private-url", "credentials", "query", "control", "non-nfc"} {
		t.Run(kind, func(t *testing.T) {
			engine, source, fetch, now, hash := prepared(t, []byte("asn,prefix,maxLength\nAS13335,1.1.1.0/24,24\n"), "csv")
			yes := true
			source.Rights.AttributionRequired = &yes
			source.Rights.Attribution = &intelligence.DatasetAttribution{Name: "Synthetic Dataset", Text: "Copyright Synthetic Author", URL: "https://example.com/data"}
			switch kind {
			case "unreviewed":
				source.Rights.Status = "unknown"
			case "missing":
				source.Rights.Attribution = nil
			case "private-url":
				source.Rights.Attribution.URL = "https://127.0.0.1/data"
			case "credentials":
				source.Rights.Attribution.URL = "https://secret@example.com/data"
			case "query":
				source.Rights.Attribution.URL = "https://example.com/data?secret=1"
			case "control":
				source.Rights.Attribution.Text = "Copyright\u202eHidden"
			case "non-nfc":
				source.Rights.Attribution.Name = "Cafe\u0301"
			}
			result, err := engine.Ingest(context.Background(), source, now, hash)
			if err != nil || result.Decision.State != "quarantined" || result.Snapshot != nil || fetch.calls != 0 {
				t.Fatal("unsafe/unreviewed credit reached download", result.Decision, err)
			}
		})
	}
}
