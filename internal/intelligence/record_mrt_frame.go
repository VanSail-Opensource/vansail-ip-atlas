package intelligence

import (
	"bytes"
	"net/netip"
	"time"
)

// decodeWriterMRT recognizes the ordinary writer shape for a single observed
// origin or a single AS_SEQUENCE. The strict general decoder handles all other
// layouts, including AS sets and confederations. Row admission is unchanged.
func decodeWriterMRT(data []byte) (NormalizedRecord, bool) {
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
