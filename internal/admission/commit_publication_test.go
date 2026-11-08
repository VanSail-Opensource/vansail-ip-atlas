package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func prepareCommit(t *testing.T) (*Engine, Source, *fixtureFetch, time.Time, [32]byte) {
	t.Helper()
	payload := []byte("asn,prefix,maxLength\n13335,1.1.1.0/24,24\n")
	e, source, fetch, now, policyHash := prepared(t, payload, "csv")
	source.URL = "https://raw.githubusercontent.com/unit/publisher/main/data/vrp.csv"
	source.Publication = Publication{"github_commit", "https://api.github.com/repos/unit/publisher/commits?path=data%2Fvrp.csv&sha=main&per_page=1", "commit.committer.date"}
	sha := strings.Repeat("a", 40)
	metadata := []map[string]any{{"sha": sha, "url": "https://api.github.com/repos/unit/publisher/commits/" + sha, "commit": map[string]any{"author": map[string]string{"date": now.Add(-3 * time.Hour).Format(time.RFC3339)}, "committer": map[string]string{"date": now.Add(-2 * time.Hour).Format(time.RFC3339)}}}}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	fetch.assets = map[string][]byte{source.URL: payload, source.Publication.Locator: data, "https://raw.githubusercontent.com/unit/publisher/" + sha + "/data/vrp.csv": payload}
	return e, source, fetch, now, policyHash
}

func TestCommitIntakeRequiresExactImmutableContent(t *testing.T) {
	e, source, fetch, now, policyHash := prepareCommit(t)
	result, err := e.Ingest(context.Background(), source, now, policyHash)
	if err != nil || result.Snapshot == nil || !result.Snapshot.ImmutableCommitBound || result.Snapshot.PublishedAt != now.Add(-3*time.Hour) || fetch.calls != 3 {
		t.Fatalf("immutable commit intake: %v %v calls=%d", result, err, fetch.calls)
	}
	assertNoRawIntake(t, e.workspace)
}

func TestCommitIntakeRejectsUnboundOrInvalidProof(t *testing.T) {
	for _, scenario := range []string{"wrong_repo", "wrong_path", "wrong_ref", "wrong_field", "missing_immutable", "different_immutable", "wrong_commit_url", "invalid_sha", "duplicate_key", "empty", "multiple", "future", "stale_author"} {
		t.Run(scenario, func(t *testing.T) {
			e, source, fetch, now, policyHash := prepareCommit(t)
			immutable := "https://raw.githubusercontent.com/unit/publisher/" + strings.Repeat("a", 40) + "/data/vrp.csv"
			data := string(fetch.assets[source.Publication.Locator])
			switch scenario {
			case "wrong_repo":
				source.Publication.Locator = strings.Replace(source.Publication.Locator, "unit/publisher", "unit/other", 1)
			case "wrong_path":
				source.Publication.Locator = strings.Replace(source.Publication.Locator, "data%2Fvrp.csv", "other.csv", 1)
			case "wrong_ref":
				source.Publication.Locator = strings.Replace(source.Publication.Locator, "sha=main", "sha=other", 1)
			case "wrong_field":
				source.Publication.Field = "commit.message"
			case "missing_immutable":
				delete(fetch.assets, immutable)
			case "different_immutable":
				fetch.assets[immutable] = []byte("unbound payload")
			case "wrong_commit_url":
				data = strings.Replace(data, "/commits/", "/git/commits/", 1)
			case "invalid_sha":
				data = strings.ReplaceAll(data, strings.Repeat("a", 40), "main")
			case "duplicate_key":
				data = strings.Replace(data, `"sha":`, `"SHA":"duplicate","sha":`, 1)
			case "empty":
				data = "[]"
			case "multiple":
				data = data[:len(data)-1] + "," + data[1:]
			case "future":
				data = strings.ReplaceAll(data, now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(25*time.Hour).Format(time.RFC3339))
			case "stale_author":
				data = strings.ReplaceAll(data, now.Add(-3*time.Hour).Format(time.RFC3339), now.Add(-721*time.Hour).Format(time.RFC3339))
			}
			fetch.assets[source.Publication.Locator] = []byte(data)
			result, err := e.Ingest(context.Background(), source, now, policyHash)
			if err != nil || result.Snapshot != nil || result.Decision.State == "current" {
				t.Fatalf("invalid commit proof accepted: %v %v", result, err)
			}
			assertNoRawIntake(t, e.workspace)
		})
	}
}

func TestRecommittingIdenticalContentCannotRenewItsClock(t *testing.T) {
	e, source, fetch, now, policyHash := prepareCommit(t)
	first, err := e.Ingest(context.Background(), source, now, policyHash)
	if err != nil || first.Snapshot == nil {
		t.Fatal("initial commit intake failed", err)
	}
	later := now.Add(719 * time.Hour)
	metadata := string(fetch.assets[source.Publication.Locator])
	metadata = strings.ReplaceAll(metadata, strings.Repeat("a", 40), strings.Repeat("b", 40))
	metadata = strings.ReplaceAll(metadata, now.Add(-3*time.Hour).Format(time.RFC3339), later.Add(-time.Hour).Format(time.RFC3339))
	metadata = strings.ReplaceAll(metadata, now.Add(-2*time.Hour).Format(time.RFC3339), later.Format(time.RFC3339))
	fetch.assets[source.Publication.Locator] = []byte(metadata)
	fetch.assets["https://raw.githubusercontent.com/unit/publisher/"+strings.Repeat("b", 40)+"/data/vrp.csv"] = fetch.assets[source.URL]
	result, err := e.Ingest(context.Background(), source, later, policyHash)
	if err != nil || result.Snapshot != nil || result.Decision.State != "stale" {
		t.Fatalf("recommit renewed old content: %v %v", result, err)
	}
	assertNoRawIntake(t, e.workspace)
}
