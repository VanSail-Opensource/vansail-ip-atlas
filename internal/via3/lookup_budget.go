package via3

import "math"

// lookupJSONBound conservatively counts the complete canonical answer without
// creating a second serialized copy. Fixed per-record allowances exceed all
// field names, punctuation, booleans, nulls and finite numeric encodings in the
// frozen schema-3 answer. Strings allow six bytes per input byte, covering JSON
// escapes, HTML escapes and invalid UTF-8 replacement. Audit this bound when
// changing LookupAnswer or any nested answer schema.
//
// A bound above the cap is inconclusive: lookupFits still uses the exact JSON
// serializer. A loose estimate never rejects an otherwise permitted answer.
func lookupJSONBound(a LookupAnswer) int {
	b := jsonBound{n: 2048}
	b.text(a.Q)
	b.text(a.Kind)
	b.text(a.ReleaseID)
	if g := a.Geo; g != nil {
		b.add(256)
		b.labels(g.Country, g.RegistrationCountry, g.Region, g.City, g.Precision)
		b.floats(g.Latitude, g.Longitude)
	}
	if n := a.Network; n != nil {
		b.add(128)
		b.text(n.Prefix)
		b.labels(n.Name, n.Organization, n.ISP)
		b.elements(len(n.Origins), 12)
	}
	if u := a.Usage; u != nil {
		b.add(128)
		b.text(u.Type)
		b.text(u.Assignment)
	}
	if q := a.Quality; q != nil {
		b.add(512)
		b.text(q.Confidence)
		for _, value := range q.Reasons {
			b.text(value)
		}
		b.floats(q.Layers.Exact, q.Layers.Prefix, q.Layers.ASN, q.Layers.Neighbors)
	}
	for _, asn := range a.ASNs {
		b.add(512)
		b.labels(asn.Name, asn.Organization, asn.Country)
		b.floats(asn.Risk)
		b.text(asn.RiskBand)
		b.text(asn.Confidence)
		b.text(asn.NetworkClass)
		b.text(asn.Stability)
		for _, prefix := range asn.Prefixes {
			b.text(prefix)
		}
	}
	b.elements(len(a.BGP.Origins), 12)
	for _, path := range a.BGP.Paths {
		b.add(128)
		b.text(path.Visibility)
		b.elements(len(path.ASNs), 12)
		for _, segment := range path.Segments {
			b.add(64)
			b.text(segment.Type)
			b.elements(len(segment.ASNs), 12)
		}
	}
	for _, edge := range a.BGP.Relationships {
		b.add(128)
		b.text(edge.Relation)
	}
	for _, tier := range a.BGP.Tier1 {
		b.add(64)
		b.text(tier.NetworkClass)
		b.text(tier.Stability)
	}
	for _, rpki := range a.BGP.RPKI {
		b.add(64)
		b.text(rpki.Status)
	}
	return b.n
}

type jsonBound struct{ n int }

func (b *jsonBound) add(n int) {
	if n < 0 || n > PublicAnswerBytes-b.n {
		b.n = PublicAnswerBytes + 1
		return
	}
	b.n += n
}
func (b *jsonBound) elements(count, width int) {
	if count > PublicAnswerBytes/width {
		b.n = PublicAnswerBytes + 1
		return
	}
	b.add(count * width)
}
func (b *jsonBound) text(value string) {
	if len(value) > PublicAnswerBytes/6 {
		b.n = PublicAnswerBytes + 1
		return
	}
	b.add(6*len(value) + 3)
}
func (b *jsonBound) labels(values ...*string) {
	for _, value := range values {
		if value != nil {
			b.text(*value)
		}
	}
}
func (b *jsonBound) floats(values ...*float64) {
	for _, value := range values {
		if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0)) {
			b.n = PublicAnswerBytes + 1
		}
	}
}
func lookupFits(a LookupAnswer) error {
	if lookupJSONBound(a) <= PublicAnswerBytes {
		return nil
	}
	return answerFits(a)
}
