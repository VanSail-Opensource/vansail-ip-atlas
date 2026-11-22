package admission

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

// Every admitted source must parse its exact captured fixture with the current
// adapter. This runs before network acquisition and never creates a review.
func TestReviewedObservedCatalogFixtures(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(root, "configs", "sources.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sources, err := DecodeCatalog(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		if source.Fixture.Status != "passed" {
			continue
		}
		t.Run(source.ID, func(t *testing.T) {
			ctx := context.Background()
			implementation, ok := selectAdapter(source)
			if !ok || !publicationSupported(source) {
				t.Fatal("reviewed adapter or full publication verifier missing")
			}
			path, err := privateFile(filepath.Join(root, "fixtures", "source-certification"), filepath.Join(root, filepath.FromSlash(source.Fixture.Path)))
			if err != nil {
				t.Fatal(err)
			}
			hash, size, err := hashFile(ctx, path, 64<<20)
			if err != nil || hashString(hash) != source.Fixture.SHA256 {
				t.Fatal("observed fixture bytes changed", err)
			}
			clock, err := time.Parse(time.RFC3339, source.Fixture.TestedAt)
			if err != nil {
				t.Fatal(err)
			}
			input, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			var count uint64
			emit := func(record intelligence.NormalizedRecord) error { count++; return record.Validate() }
			if source.Fixture.PayloadFormat == "nro-delegated-excerpt" {
				count, err = validateNROExcerpt(ctx, input, source, implementation, clock)
			} else if source.Fixture.PayloadFormat == "rpki-client-excerpt" {
				var rows int
				rows, err = validateRPKIClientExcerpt(ctx, input, source, implementation, clock)
				count = uint64(rows)
			} else if source.Fixture.PayloadFormat == "decoded-csv" {
				err = parseGeoProviderFixture(ctx, input, source, 1_000_000, emit)
			} else {
				err = parsePayloadTo(ctx, input, size, source, implementation, clock, 1_000_000, emit)
			}
			if err != nil || count == 0 {
				t.Fatal("actual observed fixture did not parse", err)
			}
			if source.Admission == "active" {
				if err := (&Engine{workspace: root}).certify(ctx, source, implementation, clock); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
