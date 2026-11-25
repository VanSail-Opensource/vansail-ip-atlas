package intelligence

import (
	"bytes"
	"net/netip"

	"vansail-ip-atlas/internal/facts"
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
	v.PhysicalCountry = r.country()
	r.take(`,"RegistrationCountry":`)
	v.RegistrationCountry = r.country()
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
		coords.Precision = uint8(r.unsigned(8))
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

func (r *writerFrameReader) country() string {
	if len(r.remaining) >= 4 && r.remaining[0] == '"' && r.remaining[3] == '"' {
		if code := facts.CountryCode(string(r.remaining[1:3])); code != "" {
			r.remaining = r.remaining[4:]
			return code
		}
	}
	return r.plainString()
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

// The usual writer spelling is a short decimal. Its numerator and power-of-ten
// denominator both fit exactly in a float64, so IEEE division produces the
// same rounded result as the general JSON number decoder. Longer decimals and
// exponents fall back to that decoder for the complete frame.
func (r *writerFrameReader) number() float64 {
	end := bytes.IndexByte(r.remaining, ',')
	if end <= 0 || end > 15 {
		r.remaining = nil
		return 0
	}
	token := r.remaining[:end]
	negative := token[0] == '-'
	if negative {
		token = token[1:]
	}
	if len(token) == 0 || len(token) > 1 && token[0] == '0' && token[1] != '.' {
		r.remaining = nil
		return 0
	}
	var coefficient uint64
	scale := uint64(1)
	fraction := false
	for i, b := range token {
		if b == '.' && !fraction && i > 0 && i+1 < len(token) {
			fraction = true
			continue
		}
		if b < '0' || b > '9' {
			r.remaining = nil
			return 0
		}
		coefficient = 10*coefficient + uint64(b-'0')
		if fraction {
			scale *= 10
		}
	}
	r.remaining = r.remaining[end:]
	v := float64(coefficient) / float64(scale)
	if negative {
		return -v
	}
	return v
}
