package admission

import (
	"slices"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

// PrivateLabelValues mirrors the publication scanner's catalog projection.
// The catalog includes withdrawn or unavailable sources, whose identifiers
// still cannot be serialized in a public dictionary.
func PrivateLabelValues(catalog []Source) []string {
	var values []string
	fold := cases.Fold()
	for _, source := range catalog {
		for _, name := range []string{source.ID, source.Family, source.SourceGroup} {
			if name != "" {
				values = append(values, fold.String(name))
			}
		}
		for _, locator := range []string{source.URL, source.Rights.EvidenceURL, source.Publication.Locator} {
			if utf8.RuneCountInString(locator) >= 8 {
				values = append(values, fold.String(locator))
			}
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// PrivateLabelValues returns a copy of the rules bound to the verified catalog.
func (q *ProductionQualification) PrivateLabelValues() []string {
	return slices.Clone(q.privateLabels)
}
