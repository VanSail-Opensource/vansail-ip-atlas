package admission

import (
	"context"
	"testing"

	"vansail-ip-atlas/internal/intelligence"
)

func TestEducationalSourceUseDecisionRetainsIntakeGates(t *testing.T) {
	for _, decision := range []string{"allow", "user_authorized_educational_use"} {
		t.Run(decision, func(t *testing.T) {
			engine, source, fetch, now, binding := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
			source.Rights.Distribution = decision
			source.Rights.ReviewBasis = "Publisher terms reviewed; project owner explicitly authorized educational use without asserting publisher permission."
			result, err := engine.Ingest(context.Background(), source, now, binding)
			if err != nil || result.Snapshot == nil || result.Decision.State != "current" || !result.Policy.RightsReviewed || fetch.calls != 2 {
				t.Fatal("explicit reviewed source-use decision did not retain verified intake", err, result.Decision, fetch.calls)
			}
		})
	}
	for _, mutation := range []string{"unknown-decision", "pending-review", "deny", "unreviewed", "blank-review", "missing-terms", "private-terms", "unresolved-credit", "missing-credit", "uncertified", "unsupported-parser"} {
		t.Run(mutation, func(t *testing.T) {
			engine, source, fetch, now, binding := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
			source.Rights.Distribution = "user_authorized_educational_use"
			switch mutation {
			case "unknown-decision":
				source.Rights.Distribution = "educational"
			case "pending-review":
				source.Rights.Distribution = "review"
			case "deny":
				source.Rights.Distribution = "deny"
			case "unreviewed":
				source.Rights.Status = "unknown"
			case "blank-review":
				source.Rights.ReviewBasis = " \t\n"
			case "missing-terms":
				source.Rights.EvidenceURL = ""
			case "private-terms":
				source.Rights.EvidenceURL = "https://127.0.0.1/terms"
			case "unresolved-credit":
				source.Rights.AttributionRequired = nil
			case "missing-credit":
				yes := true
				source.Rights.AttributionRequired = &yes
			case "uncertified":
				source.Fixture.Status = "missing"
			case "unsupported-parser":
				source.Parser.ID = "unknown"
			}
			result, err := engine.Ingest(context.Background(), source, now, binding)
			if err != nil || result.Snapshot != nil || result.Decision.State != "quarantined" || fetch.calls != 0 {
				t.Fatal("educational decision bypassed an independent intake gate", err, result.Decision, fetch.calls)
			}
		})
	}
}

func TestEducationalSourceUseDecisionBindsRevalidationAndWithdrawal(t *testing.T) {
	ctx := context.Background()
	engine, source, fetch, now, binding := prepared(t, []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n"), "csv")
	source.Rights.Distribution = "user_authorized_educational_use"
	yes := true
	source.Rights.AttributionRequired = &yes
	source.Rights.Attribution = &intelligence.DatasetAttribution{Name: "Synthetic Dataset", Text: "Publisher terms retained; educational use is the project owner's decision.", URL: "https://example.com/terms"}
	result, err := engine.IngestPartitioned(ctx, source, now, binding)
	if err != nil || result.Snapshot == nil {
		t.Fatal("reviewed educational intake failed", err)
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, engine.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = intelligence.SavePartitionedState(ctx, engine.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err = engine.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	state, report, validation, err := validateSourceSet(ctx, engine.workspace, []Source{source}, now, binding)
	if err != nil || report.IncludedSources != 1 || report.RequireProduction() == nil {
		t.Fatal("educational decision changed capability requirements", err)
	}
	if _, _, err = validation.revalidate(ctx, engine.workspace, []Source{source}, now, binding); err != nil {
		t.Fatal("unchanged educational decision failed revalidation", err)
	}
	changed := source
	changed.Rights.Distribution = "allow"
	if _, _, err = validation.revalidate(ctx, engine.workspace, []Source{changed}, now, binding); err == nil {
		t.Fatal("changed distribution decision reused prior qualification")
	}
	changed.Rights.Distribution = "deny"
	if _, _, err = RevalidateStoredSources(ctx, engine.workspace, []Source{changed}, state, now, binding); err == nil {
		t.Fatal("withdrawn educational decision retained production eligibility")
	}
	before := fetch.calls
	withdrawn, err := engine.IngestPartitioned(ctx, changed, now, binding)
	if err != nil || withdrawn.Snapshot != nil || fetch.calls != before {
		t.Fatal("withdrawal fetched or retained a snapshot", err)
	}
	retracted, err := intelligence.ReconcilePartitioned(ctx, engine.workspace, state, []intelligence.SourcePolicy{withdrawn.Policy}, nil, now, binding)
	if err != nil || len(retracted.State.Sources) != 0 || !retracted.FullRebuild {
		t.Fatal("withdrawn decision did not retract previous contributions", err)
	}
	if _, _, err = RevalidateStoredSources(ctx, engine.workspace, []Source{source}, state, state.Sources[0].ExpiresAt, binding); err == nil {
		t.Fatal("educational decision renewed expired input")
	}
}

func TestEducationalSourceUseDecisionBindsRightsAndCreditDigests(t *testing.T) {
	yes := true
	source := Source{Rights: Rights{Status: "reviewed", Distribution: "user_authorized_educational_use", EvidenceURL: "https://example.com/terms", ReviewBasis: "Terms reviewed; project owner authorized educational use.", AttributionRequired: &yes, Attribution: &intelligence.DatasetAttribution{Name: "Synthetic Dataset", Text: "Retained publisher notice", URL: "https://example.com/data"}}}
	before, credit, err := RightsDigests(source)
	if err != nil || credit == nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"decision", "terms", "basis", "credit"} {
		changed := source
		copy := *source.Rights.Attribution
		changed.Rights.Attribution = &copy
		switch mutation {
		case "decision":
			changed.Rights.Distribution = "allow"
		case "terms":
			changed.Rights.EvidenceURL = "https://example.com/revised-terms"
		case "basis":
			changed.Rights.ReviewBasis += " Revised decision."
		case "credit":
			changed.Rights.Attribution.Text += " Revised notice."
		}
		after, nextCredit, err := RightsDigests(changed)
		if err != nil || before == after || nextCredit == nil || (mutation == "credit") != (*credit != *nextCredit) {
			t.Fatal("rights decision or exact credit was not independently bound", mutation, err)
		}
	}
}

func TestEducationalSourceUseDecisionRetainsMRTControls(t *testing.T) {
	engine, sources, fetch, now, binding := preparedMRTCoordinator(t)
	for i := range sources {
		sources[i].Rights.Distribution = "user_authorized_educational_use"
		if !validMRTControls(sources[i]) {
			t.Fatal("reviewed educational decision rejected by MRT controls")
		}
	}
	unknown := sources[0]
	unknown.Rights.Distribution = "educational"
	if validMRTControls(unknown) {
		t.Fatal("unknown source-use decision admitted MRT")
	}
	result, err := engine.IngestMRT(context.Background(), sources, now, binding, MRTIntakeOptions{Enabled: true})
	if err != nil || fetch.calls != 2 || len(result.CaptureClocks) != 2 {
		t.Fatal("educational decision changed independent MRT acquisition controls", err)
	}
}
