package intelligence

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
)

// decodeWriterGeo recognizes the common fixed field order emitted by RecordWriter.
// Any other representation goes through the ordinary strict decoder, including
// escaped strings, reordered members, and newly introduced fields.
// The caller checks UTF-8 before selecting either decoder.
func decodeWriterGeo(data []byte) (*GeoEvidence, bool) {
	r := writerFrameReader{remaining: data}
	if !r.take(`{"Version":3,"Kind":4,"Geo":{"Family":`) {
		return nil, false
	}
	var v GeoEvidence
	v.Family = r.plainString()
	r.take(`,"Weight":`)
	v.Weight = r.number()
	r.take(`,"Prefix":`)
	p, err := netip.ParsePrefix(r.plainString())
	if err != nil {
		return nil, false
	}
	v.Prefix = p
	r.take(`,"PhysicalCountry":`)
	v.PhysicalCountry = r.plainString()
	r.take(`,"RegistrationCountry":`)
	v.RegistrationCountry = r.plainString()
	r.take(`,"Region":`)
	v.Region = r.plainString()
	r.take(`,"City":`)
	v.City = r.plainString()
	r.take(`,"Coordinates":`)
	if bytes.HasPrefix(r.remaining, []byte("null")) {
		r.take("null")
	} else {
		var coords Coordinates
		r.take(`{"Latitude":`)
		coords.Latitude = r.number()
		r.take(`,"Longitude":`)
		coords.Longitude = r.number()
		r.take(`,"Precision":`)
		precision, err := strconv.ParseUint(string(r.numericToken('}')), 10, 8)
		if err != nil {
			return nil, false
		}
		coords.Precision = uint8(precision)
		r.take("}")
		v.Coordinates = &coords
	}
	switch string(r.remaining) {
	case `,"Current":true}}`:
		v.Current = true
	case `,"Current":false}}`:
	default:
		return nil, false
	}
	return &v, true
}

type writerFrameReader struct {
	remaining []byte
}

func (r *writerFrameReader) take(literal string) bool {
	if !bytes.HasPrefix(r.remaining, []byte(literal)) {
		r.remaining = nil
		return false
	}
	r.remaining = r.remaining[len(literal):]
	return true
}

func (r *writerFrameReader) plainString() string {
	if !r.take(`"`) {
		return ""
	}
	for i, b := range r.remaining {
		switch {
		case b == '"':
			value := string(r.remaining[:i])
			r.remaining = r.remaining[i+1:]
			return value
		case b == '\\' || b < 0x20:
			r.remaining = nil
			return ""
		}
	}
	r.remaining = nil
	return ""
}

// A token must pass both JSON syntax and the destination Go type. The strict
// fallback handles unusual numeric spellings beyond the common length bound.
func (r *writerFrameReader) numericToken(delimiter byte) []byte {
	end := bytes.IndexByte(r.remaining, delimiter)
	if end <= 0 || end > 32 || !json.Valid(r.remaining[:end]) {
		r.remaining = nil
		return nil
	}
	token := r.remaining[:end]
	r.remaining = r.remaining[end:]
	return token
}

func (r *writerFrameReader) number() float64 {
	value, err := strconv.ParseFloat(string(r.numericToken(',')), 64)
	if err != nil {
		r.remaining = nil
	}
	return value
}
