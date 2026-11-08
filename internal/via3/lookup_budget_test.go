package via3

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestLookupBudgetBoundCoversCanonicalAndEscapedAnswers(t *testing.T) {
	g := golden(t)
	for _, vector := range g.Vectors {
		data, err := json.Marshal(vector.Answer)
		if err != nil {
			t.Fatal(err)
		}
		if bound := lookupJSONBound(vector.Answer); bound < len(data) {
			t.Fatalf("%s: serialized %d exceeds bound %d", vector.Q, len(data), bound)
		}
	}
	for _, value := range []string{"", "<>&\"\\\x00", "\u2028\u2029", "\xff", strings.Repeat("中", 256)} {
		answer := g.Vectors[0].Answer
		answer.Q, answer.ReleaseID, answer.Kind = value, value, value
		answer.Geo = &GeoAnswer{Country: &value, RegistrationCountry: &value, Region: &value, City: &value, Precision: &value}
		answer.Network = &NetworkAnswer{Prefix: value, Name: &value, Organization: &value, ISP: &value, Origins: []uint32{math.MaxUint32}}
		answer.Usage = &UsageAnswer{Type: value, Assignment: value}
		answer.Quality = &QualityAnswer{Confidence: value, Reasons: []string{value}}
		answer.ASNs = []ASNAnswer{{Name: &value, Organization: &value, Country: &value, RiskBand: value, Confidence: value, Prefixes: []string{value}, NetworkClass: value, Stability: value}}
		answer.BGP = BGPAnswer{Origins: []uint32{math.MaxUint32}, Paths: []PathAnswer{{ASNs: []uint32{math.MaxUint32}, Visibility: value, Segments: []SegmentAnswer{{Type: value, ASNs: []uint32{math.MaxUint32}}}}}, Relationships: []RelationshipAnswer{{Relation: value}}, Tier1: []TierAnswer{{NetworkClass: value, Stability: value}}, RPKI: []RPKIAnswer{{Status: value}}}
		data, err := json.Marshal(answer)
		if err != nil {
			t.Fatal(err)
		}
		if bound := lookupJSONBound(answer); bound < len(data) {
			t.Fatalf("escaped answer: serialized %d exceeds bound %d", len(data), bound)
		}
	}
}

func TestLookupBudgetFallbackPreservesLimitAndNonfiniteErrors(t *testing.T) {
	answer := LookupAnswer{Q: strings.Repeat("<", PublicAnswerBytes/5)}
	if ErrorCode(lookupFits(answer)) != "resource_limit" {
		t.Fatal("escaped JSON crossed answer cap")
	}
	answer = LookupAnswer{Q: strings.Repeat("x", PublicAnswerBytes/6)}
	if err := lookupFits(answer); err != nil {
		t.Fatal("conservative bound rejected a serializable in-budget answer", err)
	}
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		answer = LookupAnswer{Geo: &GeoAnswer{Latitude: &value}}
		if err := lookupFits(answer); err == nil {
			t.Fatal("nonfinite JSON value bypassed serialization validation")
		}
	}
}
