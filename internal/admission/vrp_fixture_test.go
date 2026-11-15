package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

func observedRPKIExcerpt(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../fixtures/source-certification/observed-rpki-client-excerpt.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRPKIObservedExcerptNeverBecomesCompleteRuntimeProof(t *testing.T) {
	_, source, _, _ := preparedRPKIObservation(t)
	source.Fixture.PayloadFormat = "rpki-client-excerpt"
	data := observedRPKIExcerpt(t)
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	count, err := validateRPKIClientExcerpt(context.Background(), bytes.NewReader(data), source, rpkiClientJSON, now)
	if err != nil || count != 21 {
		t.Fatal("original observed rows or expired row rejected", count, err)
	}
	// The fixture wrapper is not a runtime snapshot, even though its original
	// metadata and row fields are accepted by the same strict field decoders.
	limits := intelligence.ParseLimits{Bytes: int64(len(data)), Records: 2_000_000, LineBytes: 1 << 20}
	if _, err = parseRPKIClientPayload(context.Background(), bytes.NewReader(data), limits, now, nil); err == nil {
		t.Fatal("excerpt minted runtime completeness")
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "fixture_schema")
	partial, _ := json.Marshal(fields)
	limits.Bytes = int64(len(partial))
	if _, err = parseRPKIClientPayload(context.Background(), bytes.NewReader(partial), limits, now, nil); err == nil {
		t.Fatal("partial body with unchanged publisher total minted completeness")
	}
}

func TestRPKIObservedExcerptRejectsChangedSchemaAndEnvelope(t *testing.T) {
	_, source, _, _ := preparedRPKIObservation(t)
	source.Fixture.PayloadFormat = "rpki-client-excerpt"
	data := string(observedRPKIExcerpt(t))
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"changed-total":          strings.Replace(data, `"uniquevrps": 1034924`, `"uniquevrps": 21`, 1),
		"duplicate":              strings.Replace(data, `"uniquevrps": 1034924`, `"uniquevrps": 1034924, "UNIQUEVRPS": 1034924`, 1),
		"bad-row":                strings.Replace(data, `"maxLength": 24`, `"maxLength": 129`, 1),
		"bad-ta":                 strings.Replace(data, `"ta": "apnic"`, `"ta": "unknown"`, 1),
		"expired-at-observation": strings.Replace(data, `"expires": 1794747860`, `"expires": 1794747496`, 1),
		"extra-field":            strings.Replace(data, `"fixture_schema":`, `"unexpected": true, "fixture_schema":`, 1),
		"truncated":              data[:len(data)-2],
		"trailing":               data + `{}`,
		"oversized":              data + strings.Repeat(" ", 1<<20),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateRPKIClientExcerpt(context.Background(), strings.NewReader(value), source, rpkiClientJSON, now); err == nil {
				t.Fatal("invalid excerpt accepted")
			}
		})
	}
	for _, mutation := range []func(*Source){
		func(s *Source) { s.Fixture.ContentEncoding = "gzip" },
		func(s *Source) { s.Fixture.PayloadFormat = "original" },
		func(s *Source) { s.URL = "https://example.org/rpki.json" },
		func(s *Source) { s.Parser.Version++ },
	} {
		changed := source
		mutation(&changed)
		if _, err := validateRPKIClientExcerpt(context.Background(), strings.NewReader(data), changed, rpkiClientJSON, now); err == nil {
			t.Fatal("unreviewed fixture controls accepted")
		}
	}
	if _, err := validateRPKIClientExcerpt(context.Background(), strings.NewReader(data), source, vrpCSV, now); err == nil {
		t.Fatal("different selected adapter accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validateRPKIClientExcerpt(ctx, strings.NewReader(data), source, rpkiClientJSON, now); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}

func TestRPKIObservedExcerptCertificationStillBindsExactLedger(t *testing.T) {
	engine, source, _, _ := preparedRPKIObservation(t)
	data := observedRPKIExcerpt(t)
	source.Fixture.PayloadFormat = "rpki-client-excerpt"
	source.Fixture.TestedAt = "2026-11-16T00:00:00Z"
	source.Fixture.SHA256 = hashString(sha256.Sum256(data))
	path := filepath.Join(engine.workspace, filepath.FromSlash(source.Fixture.Path))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, err := implementationHash(context.Background(), engine.workspace)
	if err != nil {
		t.Fatal(err)
	}
	ledgerBytes, _ := json.Marshal(ledger{1, []certification{{source.ID, source.Parser.ID, source.Parser.Schema, 1, source.Fixture.SHA256, source.Fixture.TestedAt, hashString(code)}}})
	if err = os.WriteFile(filepath.Join(engine.workspace, "fixtures/source-certification/adapter-certifications.json"), ledgerBytes, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	if err = engine.certify(context.Background(), source, rpkiClientJSON, now); err != nil {
		t.Fatal("observed schema failed certification", err)
	}
	source.Fixture.TestedAt = "2026-11-16T00:00:01Z"
	if err = engine.certify(context.Background(), source, rpkiClientJSON, now); err == nil {
		t.Fatal("unbound certificate accepted")
	}
}
