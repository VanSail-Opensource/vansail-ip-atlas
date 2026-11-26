package intelligence

import (
	"bytes"
	"net/netip"
	"strconv"
	"time"
)

// Match the exact default JSON writer spelling of the ordinary spatial origin,
// path and VRP rows. Private peer identities, escaped strings, and unfamiliar
// layouts retain the standard encoder. This only recognizes canonical bytes
// after the caller has independently decoded and validated the whole record.
func canonicalWriterRouting(data []byte, record NormalizedRecord) bool {
	if record.MRTOriginatedAt != nil || record.MRT != nil {
		return false
	}
	r := writerFrameReader{remaining: data}
	var scratch [64]byte
	prefix := func(p netip.Prefix) bool {
		return p.IsValid() && r.take(`"`) && r.take(string(p.AppendTo(scratch[:0]))) && r.take(`"`)
	}
	unsigned := func(v uint32) bool {
		return r.take(string(strconv.AppendUint(scratch[:0], uint64(v), 10)))
	}
	array := func(values []uint32) bool {
		if values == nil {
			return r.take(`null`)
		}
		if !r.take(`[`) {
			return false
		}
		for i, value := range values {
			if (i != 0 && !r.take(`,`)) || !unsigned(value) {
				return false
			}
		}
		return r.take(`]`)
	}
	switch record.Kind {
	case RecordOrigins:
		v := record.Origins
		return r.take(`{"Version":3,"Kind":3,"Origins":{"Prefix":`) && prefix(v.Prefix) &&
			r.take(`,"Origins":`) && array(v.Origins) && string(r.remaining) == `}}`
	case RecordVRP:
		v := record.VRP
		if !r.take(`{"Version":3,"Kind":6,"VRP":{"Prefix":`) || !prefix(v.Prefix) ||
			!r.take(`,"MaxLength":`) || !unsigned(uint32(v.MaxLength)) || !r.take(`,"ASN":`) || !unsigned(v.ASN) {
			return false
		}
		if t := v.ValidUntil; !t.IsZero() {
			if t.Location() != time.UTC || t.Year() < 0 || t.Year() > 9999 || !r.take(`,"ValidUntil":"`) ||
				!r.take(string(t.AppendFormat(scratch[:0], time.RFC3339Nano))) || !r.take(`"`) {
				return false
			}
		}
		return string(r.remaining) == `}}`
	case RecordPath:
		v := record.Path
		x := v.Observation
		if len(x.Segments) != 1 || x.Segments[0].Type != ASSequence || !x.Current || x.OriginOutward {
			return false
		}
		for i := range len(x.Family) {
			switch c := x.Family[i]; c {
			case '"', '\\', '<', '>', '&':
				return false
			default:
				if c < 0x20 || c > 0x7e {
					return false
				}
			}
		}
		return r.take(`{"Version":3,"Kind":7,"Path":{"Prefix":`) && prefix(v.Prefix) &&
			r.take(`,"Observation":{"Origin":`) && unsigned(x.Origin) && r.take(`,"Segments":[{"Type":1,"ASNs":`) &&
			array(x.Segments[0].ASNs) && r.take(`}],"Family":"`) && r.take(x.Family) &&
			string(r.remaining) == `","Current":true,"OriginOutward":false}}}`
	default:
		return false
	}
}

// decodeWriterRouting recognizes common writer shapes for a single origin, a
// single AS_SEQUENCE and a VRP. Spatial spools strip private MRT peer identity,
// while original observations retain it. Other layouts use the strict general
// decoder, including AS sets and confederations. Row admission is unchanged.
func decodeWriterRouting(data []byte) (NormalizedRecord, bool) {
	var record NormalizedRecord
	r := writerFrameReader{remaining: data}
	const start = `{"Version":3,"Kind":`
	if !r.take(start) || len(r.remaining) == 0 {
		return record, false
	}
	switch r.remaining[0] {
	case '3':
		if !r.take(`3,"Origins":{"Prefix":`) {
			return record, false
		}
		p, err := netip.ParsePrefix(r.plainString())
		if err != nil || !r.take(`,"Origins":[`) {
			return record, false
		}
		record.Kind = RecordOrigins
		record.Origins = &OriginMapping{Prefix: p, Origins: []uint32{r.unsigned(32)}}
		r.take(`]}`)
	case '6':
		if !r.take(`6,"VRP":{"Prefix":`) {
			return record, false
		}
		p, err := netip.ParsePrefix(r.plainString())
		if err != nil || !r.take(`,"MaxLength":`) {
			return record, false
		}
		row := &VRP{Prefix: p, MaxLength: uint8(r.unsigned(8))}
		r.take(`,"ASN":`)
		row.ASN = r.unsigned(32)
		if !bytes.Equal(r.remaining, []byte(`}}`)) {
			if !r.take(`,"ValidUntil":`) {
				return record, false
			}
			row.ValidUntil = r.utcSecond()
		}
		if !bytes.Equal(r.remaining, []byte(`}}`)) {
			return record, false
		}
		return NormalizedRecord{Version: 3, Kind: RecordVRP, VRP: row}, true
	case '7':
		if !r.take(`7,"Path":{"Prefix":`) {
			return record, false
		}
		p, err := netip.ParsePrefix(r.plainString())
		if err != nil || !r.take(`,"Observation":{"Origin":`) {
			return record, false
		}
		path := &ScopedPath{Prefix: p}
		path.Observation.Origin = r.unsigned(32)
		if !r.take(`,"Segments":[{"Type":1,"ASNs":[`) {
			return record, false
		}
		asns := make([]uint32, 0, 8)
		for {
			asns = append(asns, r.unsigned(32))
			if len(r.remaining) == 0 || r.remaining[0] != ',' {
				break
			}
			if len(asns) >= 255 {
				return record, false
			}
			r.remaining = r.remaining[1:]
		}
		if !r.take(`]}],"Family":`) {
			return record, false
		}
		path.Observation.Segments = []PathSegment{{Type: ASSequence, ASNs: asns}}
		path.Observation.Family = r.plainString()
		if !r.take(`,"Current":true,"OriginOutward":false}}`) {
			return record, false
		}
		path.Observation.Current = true
		record.Kind, record.Path = RecordPath, path
	default:
		return record, false
	}
	if bytes.Equal(r.remaining, []byte(`}`)) {
		record.Version = 3
		return record, true
	}
	if !r.take(`,"MRTOriginatedAt":`) {
		return record, false
	}
	originated := r.utcSecond()
	if !r.take(`,"MRT":{"PeerKey":[`) {
		return record, false
	}
	var identity MRTRouteIdentity
	for i := range identity.PeerKey {
		if i > 0 && !r.take(",") {
			return record, false
		}
		identity.PeerKey[i] = byte(r.unsigned(8))
	}
	r.take(`],"PeerIndex":`)
	identity.PeerIndex = uint16(r.unsigned(16))
	r.take(`,"PeerTable":`)
	identity.PeerTable = r.unsigned(32)
	r.take(`,"PathID":`)
	identity.PathID = r.unsigned(32)
	if !r.take(`,"AddPath":false,"PeerAmbiguous":false,"CapturedAt":`) {
		return record, false
	}
	identity.CapturedAt = r.utcSecond()
	if !bytes.Equal(r.remaining, []byte(`}}`)) {
		return record, false
	}
	record.Version, record.MRTOriginatedAt, record.MRT = 3, &originated, &identity
	return record, true
}

// unsigned accepts only unquoted decimal JSON integers representable by the
// particular unsigned destination. Any other spelling falls back to JSON.
func (r *writerFrameReader) unsigned(bits uint) uint32 {
	data := r.remaining
	var value uint64
	end := 0
	for end < len(data) && data[end] >= '0' && data[end] <= '9' {
		if end >= 10 {
			r.remaining = nil
			return 0
		}
		value = value*10 + uint64(data[end]-'0')
		end++
	}
	if end == 0 || end > 1 && data[0] == '0' || value >= uint64(1)<<bits {
		r.remaining = nil
		return 0
	}
	r.remaining = data[end:]
	return uint32(value)
}

func (r *writerFrameReader) utcSecond() time.Time {
	const length = len(`"2006-01-02T15:04:05Z"`)
	var result time.Time
	if len(r.remaining) < length || r.remaining[0] != '"' || r.remaining[length-2] != 'Z' || r.remaining[length-1] != '"' || result.UnmarshalJSON(r.remaining[:length]) != nil {
		r.remaining = nil
		return time.Time{}
	}
	r.remaining = r.remaining[length:]
	return result
}
