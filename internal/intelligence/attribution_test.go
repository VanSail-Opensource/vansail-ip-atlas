package intelligence

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDatasetAttributionSharedPublicURLCorpus(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/contracts/attribution-urls-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Version int `json:"schema_version"`
		Cases   []struct {
			URL   string `json:"url"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.Version != 1 {
		t.Fatal("credit URL corpus invalid", err)
	}
	for _, item := range corpus.Cases {
		credit := DatasetAttribution{Name: "Synthetic Dataset", Text: "Copyright Synthetic Author", URL: item.URL}
		if got := credit.Validate() == nil; got != item.Valid {
			t.Errorf("credit URL validity mismatch: %s got %v want %v", item.URL, got, item.Valid)
		}
	}
}

func TestDatasetAttributionSharedPlainTextAndSecretCorpus(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/contracts/attribution-text-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Version int `json:"schema_version"`
		Cases   []struct {
			Text  string `json:"text"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.Version != 1 {
		t.Fatal("credit text corpus invalid", err)
	}
	for _, item := range corpus.Cases {
		credit := DatasetAttribution{Name: "Synthetic Dataset", Text: item.Text, URL: "https://publisher.example/data"}
		if got := credit.Validate() == nil; got != item.Valid {
			t.Errorf("credit text case validity mismatch: got %v want %v", got, item.Valid)
		}
	}
}
