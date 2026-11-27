package intelligence

import "net/netip"

// decodeWriterExactEvidence handles the ordinary writer shape for exact
// evidence without allocating the general JSON decoder's intermediate state.
// Any other shape uses the complete strict decoder. Neither this recognition
// nor decoding authenticates a publication clock or admits an observation.
func decodeWriterExactEvidence(data []byte) (*Evidence, bool) {
	r := writerFrameReader{remaining: data}
	if !r.take(`{"Version":3,"Kind":1,"Evidence":{"Family":`) {
		return nil, false
	}
	var v Evidence
	v.Family = r.plainString()
	r.take(`,"Signal":`)
	v.Signal = Signal(r.plainString())
	r.take(`,"Scope":0,"Address":`)
	address, err := netip.ParseAddr(r.plainString())
	if err != nil || address.Zone() != "" || !r.take(`,"Prefix":"","ASN":0,"SourcePublishedAt":`) {
		return nil, false
	}
	v.Address = address
	v.SourcePublishedAt = r.utcSecond()
	r.take(`,"ItemPublishedAt":`)
	v.ItemPublishedAt = r.utcSecond()
	r.take(`,"Weight":`)
	v.Weight = r.number()
	switch string(r.remaining) {
	case `,"Current":true,"SubscriptionLiteral":false}}`:
		v.Current = true
	case `,"Current":true,"SubscriptionLiteral":true}}`:
		v.Current, v.SubscriptionLiteral = true, true
	default:
		return nil, false
	}
	return &v, true
}
