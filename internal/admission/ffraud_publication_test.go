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

func TestFFraudCommitProofBindsGenerationCountAndImmutableBytes(t *testing.T) {
	for _, scenario := range []string{"valid", "missing_metadata", "metadata_count", "metadata_project", "metadata_duplicate", "metadata_timezone", "generation_after_commit", "metadata_zero", "immutable_mismatch", "wrong_repository", "wrong_ref", "wrong_path"} {
		t.Run(scenario, func(t *testing.T) {
			source := ffraudFixtureSource()
			payload := []byte(ffraudTestHeader + "1.1.1.1,95,40,c2,proxy\n127.0.0.1,50,2,spam,\n")
			now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
			commitTime := now.Add(-2 * time.Hour)
			generated := now.Add(-3 * time.Hour)
			sha := strings.Repeat("a", 40)
			commit := `[{"sha":"` + sha + `","url":"https://api.github.com/repos/FFraud-com/ip-fraud-database/commits/` + sha + `","commit":{"author":{"date":"` + commitTime.Format(time.RFC3339) + `"},"committer":{"date":"` + commitTime.Format(time.RFC3339) + `"}}}]`
			metadata := `{"project":"ip-fraud-database","generated_utc":"` + generated.Format(time.RFC3339) + `","live_utc":"` + now.Format(time.RFC3339) + `","counts":{"confirmed_abusive_ips":2}}`
			immutableURL := "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/" + sha + "/threat-ips/confirmed-abusive.csv"
			metadataURL := "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/" + sha + "/metadata.json"
			fetch := &fixtureFetch{assets: map[string][]byte{immutableURL: payload}}
			switch scenario {
			case "metadata_count":
				metadata = strings.Replace(metadata, `"confirmed_abusive_ips":2`, `"confirmed_abusive_ips":1`, 1)
			case "metadata_project":
				metadata = strings.Replace(metadata, "ip-fraud-database", "mirror", 1)
			case "metadata_duplicate":
				metadata = strings.Replace(metadata, `"generated_utc":`, `"GENERATED_UTC":"2026-11-15T11:59:00Z","generated_utc":`, 1)
			case "metadata_timezone":
				metadata = strings.Replace(metadata, generated.Format(time.RFC3339), "2026-11-15T09:00:00", 1)
			case "generation_after_commit":
				metadata = strings.Replace(metadata, generated.Format(time.RFC3339), now.Format(time.RFC3339), 1)
			case "metadata_zero":
				metadata = strings.Replace(metadata, `"confirmed_abusive_ips":2`, `"confirmed_abusive_ips":0`, 1)
			case "immutable_mismatch":
				fetch.assets[immutableURL] = []byte("different bytes\n")
			case "wrong_repository":
				source.URL = strings.Replace(source.URL, "FFraud-com", "mirror", 1)
				source.Publication.Locator = strings.Replace(source.Publication.Locator, "FFraud-com", "mirror", 1)
			case "wrong_ref":
				source.URL = strings.Replace(source.URL, "/main/", "/other/", 1)
				source.Publication.Locator = strings.Replace(source.Publication.Locator, "sha=main", "sha=other", 1)
			case "wrong_path":
				source.URL = strings.Replace(source.URL, "confirmed-abusive.csv", "partial.csv", 1)
				source.Publication.Locator = strings.Replace(source.Publication.Locator, "confirmed-abusive.csv", "partial.csv", 1)
			}
			if scenario != "missing_metadata" {
				fetch.assets[metadataURL] = []byte(metadata)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "commit.json")
			if err := os.WriteFile(path, []byte(commit), 0600); err != nil {
				t.Fatal(err)
			}
			actual, err := (&Engine{fetch: fetch}).verifyCommit(context.Background(), path, dir, source, sha256.Sum256(payload), int64(len(payload)), now)
			if scenario == "valid" {
				if err != nil || !actual.Equal(generated) || fetch.calls != 2 {
					t.Fatal("generation/count/bytes not bound", actual, err, fetch.calls)
				}
			} else if err == nil {
				t.Fatal("invalid publication accepted", actual)
			}
		})
	}
}

func TestFFraudCandidateDoesNotAdmitOrDownload(t *testing.T) {
	payload := []byte(ffraudTestHeader + "1.1.1.1,95,40,c2,proxy\n")
	engine, _, fetch, now, hash := prepared(t, payload, "csv")
	source := ffraudFixtureSource()
	source.Admission = "candidate"
	result, err := engine.Ingest(context.Background(), source, now, hash)
	if err != nil || result.Snapshot != nil || fetch.calls != 0 {
		t.Fatal("adapter availability activated candidate", result, err, fetch.calls)
	}
}

func TestFFraudPrivateCompleteCapture(t *testing.T) {
	root := os.Getenv("ATLAS_FFRAUD_OBSERVED_DIRECTORY")
	if root == "" {
		t.Skip("private complete FFraud capture not provided")
	}
	payload, err := os.Open(filepath.Join(root, "ffraud-csv.body"))
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Close()
	var receipt struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}
	receiptBytes, err := os.ReadFile(filepath.Join(root, "ffraud-csv.receipt.json"))
	if err != nil || json.Unmarshal(receiptBytes, &receipt) != nil {
		t.Fatal("capture receipt unavailable", err)
	}
	digest, size, err := hashFile(context.Background(), payload.Name(), ffraudByteLimit)
	if err != nil || hashString(digest) != receipt.SHA256 || size != receipt.Bytes {
		t.Fatal("complete capture bytes changed", err)
	}
	rows, err := scanFFraud(context.Background(), payload, ffraudRowLimit, nil)
	if err != nil || rows != 1651503 {
		t.Fatal("complete input census mismatch", rows, err)
	}
	if _, err = payload.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	err = parseRiskPayload(context.Background(), payload, ffraudFixtureSource(), time.Date(2026, 11, 3, 21, 30, 44, 0, time.UTC), ffraudRowLimit, func(record intelligence.NormalizedRecord) error {
		counts[string(record.Evidence.Signal)]++
		return record.Validate()
	})
	total := 0
	for _, count := range counts {
		total += count
	}
	if err != nil || total != 1651501 || len(counts) != 6 || counts["fraud"] != 0 {
		t.Fatal("complete normalization census mismatch", total, counts, err)
	}
	t.Logf("Complete private capture: %d input rows, %d public observations, category counts %v; no source admission/certification", rows, total, counts)
}
