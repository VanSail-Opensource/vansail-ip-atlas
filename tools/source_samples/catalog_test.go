package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These checks exercise an optional local private inventory, without network
// requests. Captures have no reviewed redistribution grant and must never be
// published to the public repository merely to make this integration test run.
func TestPrivateSampleInventory(t *testing.T) {
	root := filepath.Join("..", "..", "fixtures", "source-samples")
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); os.IsNotExist(err) {
		t.Skip("build-private source captures absent; this is not source certification")
	} else if err != nil {
		t.Fatal(err)
	}
	catalogBytes, err := os.ReadFile(filepath.Join("..", "..", "configs", "sources.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg catalog
	if err := yaml.Unmarshal(catalogBytes, &cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.PublicOutputAllowed || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.SourceCatalogSHA256) || len(m.Sources) != len(cfg.Sources) {
		t.Fatal("private manifest/catalog identity mismatch")
	}
	if m.SourceCatalogSHA256 != hashBytes(catalogBytes) {
		t.Log("historical private capture catalog hash retained; current policy revision differs, source-entry metadata and every captured byte are still checked below")
	}
	records, err := loadPrevious(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiscoveries(filepath.Join(root, "discovery.json"), cfg.Sources); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.Summary, summarize(m.Sources)) {
		t.Fatal("summary mismatch")
	}
	referenced := make(map[string]bool)
	uuid := regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	for _, src := range cfg.Sources {
		rec, ok := records[src.ID]
		if !ok || !rec.ExplicitlyNotFixtureTest || rec.Admission != src.Admission || rec.PublicationProof != src.PublicationProof.Kind ||
			rec.ExistingFixtureStatus != src.Fixture.Status || rec.DeclaredFormat != src.Download.Format || rec.EvidenceFamily != src.EvidenceFamily {
			t.Fatalf("source admission/metadata changed: %s", src.ID)
		}
		path := rec.FormatOnlyRecord
		if isCaptured(rec) {
			path = rec.SamplePath
			if rec.SampleBytes > maxSampleBytes || rec.CapturedAt == "" {
				t.Fatalf("invalid sample budget/time: %s", src.ID)
			}
			if src.Category == "proxy_subscription_ip" {
				if rec.Status != "captured_sanitized" || len(rec.Redactions) == 0 {
					t.Fatalf("unsanitized subscription: %s", src.ID)
				}
				fragment, _ := os.ReadFile(filepath.Join(root, path))
				if uuid.Match(fragment) || strings.Contains(string(fragment), "?security=") || strings.Contains(string(fragment), "?type=") {
					t.Fatalf("credential or transport suffix in %s", src.ID)
				}
			}
		} else if rec.Blocker == "" || path == "" {
			t.Fatalf("missing blocker: %s", src.ID)
		}
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
		if referenced[path] {
			t.Fatalf("shared artifact path: %s", path)
		}
		referenced[path] = true
	}
	for _, sub := range []string{"samples", "format-only"} {
		files, err := os.ReadDir(filepath.Join(root, sub))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if file.IsDir() || file.Type()&os.ModeSymlink != 0 || !referenced[sub+"/"+file.Name()] {
				t.Fatalf("orphan or unsafe artifact: %s/%s", sub, file.Name())
			}
		}
	}
}
