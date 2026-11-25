package admission

import (
	"slices"
	"testing"
)

func TestPrivateLabelsIncludeEveryCatalogNameAndLongLocator(t *testing.T) {
	catalog := []Source{{ID: "sample-feed", Family: "X4B", SourceGroup: "Straße", Admission: "retired", URL: "https://example.invalid/data", Rights: Rights{EvidenceURL: "https://example.invalid/data"}, Publication: Publication{Locator: "short"}}}
	got := PrivateLabelValues(catalog)
	want := []string{"https://example.invalid/data", "sample-feed", "strasse", "x4b"}
	if !slices.Equal(got, want) {
		t.Fatal(got)
	}
	q := &ProductionQualification{privateLabels: got}
	q.PrivateLabelValues()[0] = "changed"
	if !slices.Equal(q.PrivateLabelValues(), want) {
		t.Fatal("caller mutated verified catalog rules")
	}
}
