package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// Full upstream captures are private and optional. This observes complete-body
// parser behavior without manufacturing an authenticated intake receipt.
func TestObservedPrivatePublicSources(t *testing.T) {
	base := filepath.Join("..", "..", "build-private", "source-expansion-20261115")
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct{ name, digest string }{
		{"tor-exit-addresses.txt", "2dd1e8c0b10444af0980601a85afad8940f64e93867450701d1acab5eabaade4"},
		{"ipverse-as.json", "4bab4bbb5fb04991f172a0f87503b2cc734e28f79b78de999709da00d2ae8f62"},
	} {
		t.Run(item.name, func(t *testing.T) {
			file, err := os.Open(filepath.Join(base, item.name))
			if os.IsNotExist(err) {
				t.Skip("private captured full payload absent")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			h := sha256.New()
			if _, err = io.Copy(h, file); err != nil || hex.EncodeToString(h.Sum(nil)) != item.digest {
				t.Fatal("private capture hash mismatch", err)
			}
			if _, err = file.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			var records, current int
			var oldest time.Time
			emit := func(r intelligence.NormalizedRecord) error {
				records++
				if err := r.Validate(); err != nil {
					return err
				}
				item := now
				if r.Usage != nil {
					item = r.Usage.ObservedAt
				}
				if r.Evidence != nil {
					item = r.Evidence.ItemPublishedAt
				}
				if now.Before(item.Add(720 * time.Hour)) {
					current++
					if oldest.IsZero() || item.Before(oldest) {
						oldest = item
					}
				}
				return nil
			}
			if item.name == "tor-exit-addresses.txt" {
				_, err = parseTorExitAddresses(context.Background(), file, now, 720*time.Hour, 1_000_000, emit)
			} else {
				err = parseIPverseUsageJSON(context.Background(), file, "ipverse-as", 1_000_000, emit)
			}
			if err != nil || records == 0 || current == 0 {
				t.Fatal("full source parse failed", records, current, err)
			}
			t.Logf("normalized=%d current=%d earliest_item=%s", records, current, oldest.Format(time.RFC3339))
		})
	}
}

func TestTorExitObservationsKeepItemClockAndDiscardRelayMetadata(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	body := "ExitNode 0123456789ABCDEF0123456789ABCDEF01234567\nPublished 2026-11-14 01:00:00\nLastStatus 2026-11-15 10:00:00\nExitAddress 8.8.8.8 2026-11-15 10:10:00\nExitAddress 8.8.4.4 2026-09-01 10:10:00\nExitAddress 10.0.0.1 2026-11-15 10:10:00\n"
	var got []intelligence.NormalizedRecord
	clock, err := parseTorExitAddresses(context.Background(), strings.NewReader(body), now, 720*time.Hour, 100, func(r intelligence.NormalizedRecord) error { got = append(got, r); return nil })
	if err != nil || len(got) != 1 || !clock.Equal(time.Date(2026, 11, 15, 10, 10, 0, 0, time.UTC)) {
		t.Fatal(clock, got, err)
	}
	e := got[0].Evidence
	if e.Signal != "tor" || e.Address.String() != "8.8.8.8" || e.ItemPublishedAt != clock {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(body, "LastStatus", "Hostname", 1), strings.Replace(body, "8.8.8.8", "example.com", 1), strings.Replace(body, "2026-11-15 10:10:00", "2026-11-18 10:10:00", 1), strings.Replace(body, "LastStatus 2026-11-15 10:00:00\n", "", 1), body + "ExitNode 0123456789ABCDEF0123456789ABCDEF01234567\n"} {
		if _, err := parseTorExitAddresses(context.Background(), strings.NewReader(bad), now, 720*time.Hour, 100, nil); err == nil {
			t.Fatal("malformed descriptor accepted")
		}
	}
}

func TestIPverseUsageJSONKeepsOnlyUnambiguousObservedCategories(t *testing.T) {
	body := `[{"asn":13335,"metadata":{"category":"hosting","lastModified":"2026-11-14","networkRole":"tier1_transit"},"stats":null,"lastAnnounced":"2026-11-15"},{"asn":15169,"metadata":{"category":"isp","lastModified":"2026-11-14"},"stats":null,"lastAnnounced":"2026-11-15"}]`
	var got []intelligence.NormalizedRecord
	err := parseIPverseUsageJSON(context.Background(), strings.NewReader(body), "ipverse-as", 100, func(r intelligence.NormalizedRecord) error { got = append(got, r); return nil })
	if err != nil || len(got) != 1 || got[0].Usage.ASN != 13335 || got[0].Usage.Evidence.Type != "hosting" || got[0].Usage.Prefix.IsValid() || got[0].Usage.ObservedAt.IsZero() {
		t.Fatal(got, err)
	}
	for _, bad := range []string{`[{}]`, `[{"asn":13335,"metadata":null}]`, `[{"asn":13335,"metadata":{"category":"hosting"}}]`, strings.Replace(body, `"hosting"`, `"new-category"`, 1), strings.Replace(body, `"asn":13335`, `"asn":13335,"asn":15169`, 1), body + `{}`, strings.Replace(body, `"2026-11-14"`, `"bad"`, 1), `[{"asn":13335,"metadata":{"category":"hosting","lastModified":"2026-11-14","x":"` + strings.Repeat("x", 1<<20) + `"}}]`} {
		if err := parseIPverseUsageJSON(context.Background(), strings.NewReader(bad), "ipverse-as", 100, func(intelligence.NormalizedRecord) error { return nil }); err == nil {
			t.Fatal("malformed JSON admitted")
		}
	}
}

func TestIPverseConsecutiveIntakesHaveOverlappingOriginalDeadlines(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`[
		{"asn":1,"metadata":{"category":"hosting","lastModified":"2026-10-10"}},
		{"asn":2,"metadata":{"category":"business","lastModified":"2026-10-11"}},
		{"asn":3,"metadata":{"category":"education_research","lastModified":"2026-10-12"}},
		{"asn":4,"metadata":{"category":"government_admin","lastModified":"2026-10-13"}}
	]`)
	engine, source, fetch, now, binding := prepared(t, payload, "json")
	source.Category, source.Scope = "asn", "asn"
	source.Parser = Parser{"ipverse-asn-usage-json", "ipverse-as-category-json-v1", 2}
	source.Fixture.Parser, source.Fixture.Schema = source.Parser.ID, source.Parser.Schema
	source.Rights.Identifier = "CC0-1.0"
	source.Fields, source.PublicFields = []string{"metadata.category"}, []string{"usage_type"}
	source.FieldMappings = map[string][]string{"metadata.category": {"usage_type"}}
	certifyGeoTestSource(t, engine, source)

	var previous intelligence.BuildState
	// The second eligible refresh starts after the longest measured gap between
	// successful scheduled intake starts. Verify the same immutable payload twice.
	for i, intake := range []time.Time{now, now.Add(38 * time.Hour)} {
		bounded, err := engine.Ingest(ctx, source, intake, binding)
		if err != nil || bounded.Snapshot == nil || len(bounded.Snapshot.Records) != 2-i {
			t.Fatal("bounded role inventory", i, bounded.Decision, err)
		}
		result, err := engine.IngestPartitioned(ctx, source, intake, binding)
		if err != nil || result.Snapshot == nil || result.Snapshot.PayloadHash != sha256.Sum256(payload) ||
			result.Snapshot.ProofPayloadHash != result.Snapshot.PayloadHash || !result.Snapshot.PublishedAt.Equal(now.Add(-2*time.Hour)) {
			t.Fatal("original payload and publication binding", i, result.Decision, err)
		}
		plan, err := intelligence.ReconcilePartitioned(ctx, engine.workspace, previous, []intelligence.SourcePolicy{result.Policy}, []intelligence.SourceSnapshot{*result.Snapshot}, intake, binding)
		if err != nil || len(plan.State.Sources) != 1 {
			t.Fatal("partitioned role reconciliation", i, err)
		}
		stored := plan.State.Sources[0]
		var roles []intelligence.NormalizedRecord
		if err := intelligence.WalkStoredSource(ctx, engine.workspace, stored, func(r intelligence.NormalizedRecord) error { roles = append(roles, r); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(roles) != 2-i || roles[0].Usage.ASN != uint32(3+i) || roles[len(roles)-1].Usage.ASN != 4 {
			t.Fatal("retained roles differ", i, roles)
		}
		for j, r := range roles {
			if !r.Usage.ObservedAt.Equal(bounded.Snapshot.Records[j].Usage.ObservedAt) {
				t.Fatal("partitioned item clock differs")
			}
		}
		wantExpiry := roles[0].Usage.ObservedAt.Add(source.MaxAge)
		if !stored.ExpiresAt.Equal(wantExpiry) || !plan.NextExpiry.Equal(wantExpiry) ||
			!stored.ExpiresAt.After(intake.Add(asnUsageServingWindow)) {
			t.Fatal("original item no longer bounds the release", i, stored.ExpiresAt)
		}
		if i > 0 && (!previous.Sources[0].ExpiresAt.After(intake.Add(8*time.Hour)) ||
			!stored.ExpiresAt.After(previous.Sources[0].ExpiresAt)) {
			t.Fatal("successor lacks overlap with the active release")
		}
		if _, _, err := RevalidateStoredSources(ctx, engine.workspace, []Source{source}, plan.State, wantExpiry.Add(-time.Second), binding); err != nil {
			t.Fatal("remaining window is valid through the original deadline", err)
		}
		// A rolled-forward evaluation time must not qualify older normalized roles.
		forged := plan.State
		forged.EvaluatedAt = wantExpiry.Add(-asnUsageServingWindow)
		if _, _, err := RevalidateStoredSources(ctx, engine.workspace, []Source{source}, forged, forged.EvaluatedAt, binding); err == nil || !strings.Contains(err.Error(), "ASN role projection") {
			t.Fatal("accepted role with insufficient validity at intake")
		}
		previous = plan.State
	}
	// The same authenticated source eventually has no eligible roles. The
	// parser must also reject malformed rows even when their item dates are old.
	last, err := engine.IngestPartitioned(ctx, source, now.Add(96*time.Hour), binding)
	if err != nil || last.Snapshot != nil || last.Decision.Reason != "no_asn_role_survives_serving_window" {
		t.Fatal("empty original role inventory", last.Decision, err)
	}
	invalid := []byte(strings.Replace(string(payload), "hosting", "unrecognized", 1))
	fetch.assets[source.URL] = invalid
	fetch.assets[source.Publication.Locator] = metadataFor(t, source.URL, invalid, now, now)
	last, err = engine.IngestPartitioned(ctx, source, now, binding)
	if err != nil || last.Snapshot != nil || last.Decision.Reason != "schema_or_parser_failed" {
		t.Fatal("invalid older row escaped full parsing", last.Decision, err)
	}
}
