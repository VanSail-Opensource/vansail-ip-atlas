package admission

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func preparedRPKIObservation(t *testing.T) (*Engine, Source, time.Time, [32]byte) {
	t.Helper()
	payload := []byte(rpkiClientFixture())
	engine, source, fetch, _, binding := prepared(t, payload, "json")
	now := rpkiClientClock().Add(4 * time.Hour)
	source.URL = "https://console.rpki-client.org/rpki.json"
	source.Parser = Parser{ID: "rpki-client-json", Schema: "rpki-client-payloads-json-v1", Version: 1}
	source.Publication = Publication{Kind: "embedded", Locator: source.URL, Field: "metadata.buildtime"}
	source.Fixture.Parser, source.Fixture.Schema = source.Parser.ID, source.Parser.Schema
	source.Fixture.TestedAt = rpkiClientClock().Format(time.RFC3339)
	implementation, err := implementationHash(context.Background(), engine.workspace)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(implementation)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(engine.workspace, "fixtures", "source-certification", "adapter-certifications.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	fetch.assets = map[string][]byte{source.URL: payload}
	return engine, source, now, binding
}

func TestRPKIObservationAdmissionAndCurrentVerificationPreserveSourceFreshness(t *testing.T) {
	ctx := context.Background()
	engine, source, now, binding := preparedRPKIObservation(t)
	result, err := engine.IngestPartitioned(ctx, source, now, binding)
	if err != nil || result.Snapshot == nil {
		t.Fatal("historical authorization snapshot was not admitted", err, result.Decision)
	}
	proof := result.Snapshot.VRPProof
	if proof == nil || proof.Version != 2 || proof.Rows != 3 || proof.RetainedRows != 3 || !proof.ObservedAt.Equal(rpkiClientClock()) || !proof.CoverageValidUntil.Equal(rpkiClientClock().Add(time.Hour)) || !result.Snapshot.ContentValidUntil.IsZero() {
		t.Fatal("observation proof invented a clock, dropped rows or clamped the source")
	}
	plan, err := intelligence.ReconcilePartitioned(ctx, engine.workspace, intelligence.BuildState{}, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, now, binding)
	if err != nil || len(plan.State.Sources) != 1 {
		t.Fatal("observation source did not reconcile", err)
	}
	if !plan.State.Sources[0].ExpiresAt.Equal(rpkiClientClock().Add(source.MaxAge)) {
		t.Fatal("source freshness was renewed or tied to authorization expiry")
	}
	if err = intelligence.SavePartitionedState(ctx, engine.workspace, plan.State, intelligence.BuildState{}); err != nil {
		t.Fatal(err)
	}
	if err = engine.SealPrivateState(ctx, binding); err != nil {
		t.Fatal(err)
	}
	state, report, validation, err := validateSourceSet(ctx, engine.workspace, []Source{source}, now, binding)
	if err != nil || validation == nil {
		t.Fatal("authenticated observation failed source verification", err)
	}
	if _, _, err = validation.revalidate(ctx, engine.workspace, []Source{source}, now, binding); err != nil {
		t.Fatal("same-process verified observation reuse failed", err)
	}
	_, stats, err := RevalidateStoredSources(ctx, engine.workspace, []Source{source}, state, now.Add(24*time.Hour), binding)
	if err != nil || len(stats) != 1 || !stats[0].VRPComplete || !stats[0].VRPObservedAt.Equal(proof.ObservedAt) || !stats[0].VRPCoverageValidUntil.Equal(proof.CoverageValidUntil) {
		t.Fatal("current-time verifier discarded historical authorizations or changed their epoch", err)
	}
	if err = report.RequireProduction(); err == nil {
		t.Fatal("RPKI snapshot fabricated the missing core capabilities")
	}
	if _, _, err = RevalidateStoredSources(ctx, engine.workspace, []Source{source}, state, rpkiClientClock().Add(source.MaxAge), binding); err == nil {
		t.Fatal("publisher freshness expired but source remained eligible")
	}
	withdrawn := source
	withdrawn.Rights.Distribution = "deny"
	if _, _, err = RevalidateStoredSources(ctx, engine.workspace, []Source{withdrawn}, state, now, binding); err == nil {
		t.Fatal("historical observation bypassed rights withdrawal")
	}
	for _, scenario := range []string{"coverage", "retained-count", "mixed-version", "source-content-deadline", "observation-after-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			var changed intelligence.BuildState
			if err = json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			receipt := changed.Sources[0].Receipt
			switch scenario {
			case "coverage":
				receipt.VRPProof.CoverageValidUntil = receipt.VRPProof.CoverageValidUntil.Add(-time.Second)
			case "retained-count":
				receipt.VRPProof.RetainedRows--
			case "mixed-version":
				receipt.VRPProof.AcceptedRows = 3
			case "source-content-deadline":
				receipt.ContentValidUntil = proof.CoverageValidUntil
			case "observation-after-expiry":
				receipt.VRPProof.ObservedAt = proof.CoverageValidUntil
			}
			if _, _, err = RevalidateStoredSources(ctx, engine.workspace, []Source{source}, changed, now, binding); err == nil {
				t.Fatal("mutated observation proof accepted")
			}
		})
	}
}

func TestRPKIObservationCohortRejectsMixedEpochsAndUnboundRows(t *testing.T) {
	observed := rpkiClientClock()
	first := SourceStatistics{VRPComplete: true, VRPObservedAt: observed, VRPCoverageValidUntil: observed.Add(time.Hour)}
	first.Kinds[intelligence.RecordVRP-1] = 2
	second := first
	second.VRPCoverageValidUntil = observed.Add(2 * time.Hour)
	if err := validateRPKIObservationCohort([]SourceStatistics{first, second, {}}); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"different-epoch", "legacy-proof", "partial-rows", "expired-at-observation"} {
		t.Run(scenario, func(t *testing.T) {
			changed := second
			switch scenario {
			case "different-epoch":
				changed.VRPObservedAt = observed.Add(time.Second)
			case "legacy-proof":
				changed.VRPObservedAt = time.Time{}
			case "partial-rows":
				changed.VRPComplete = false
			case "expired-at-observation":
				changed.VRPCoverageValidUntil = observed
			}
			if err := validateRPKIObservationCohort([]SourceStatistics{first, changed}); err == nil {
				t.Fatal("ambiguous historical RPKI cohort accepted")
			}
		})
	}
	if _, _, ok := (&ProductionQualification{}).RPKIObservation(); ok {
		t.Fatal("empty qualification minted a historical epoch")
	}
}
