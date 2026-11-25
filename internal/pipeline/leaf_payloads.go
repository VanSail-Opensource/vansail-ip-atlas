package pipeline

import (
	"bytes"

	"vansail-ip-atlas/internal/via3"
)

// A leaf's scalar facts often repeat across unrelated addresses. The consumer
// must read these payloads without mutation. Share only strictly decoded values of
// identical type and bytes during one leaf scan. Prefix, rank, inheritance,
// exactness and the original logical byte limit are verified on every frame.
type leafPayloads struct {
	values map[string]via3.PublicRecord
	keys   [64]string
	next   int
}

func (c *leafPayloads) decode(frame []byte, limit int64) (encoded, via3.PublicRecord, error) {
	if !bytes.HasPrefix(frame, []byte(compactRunMarker)) {
		return decodeRunPayload(frame, limit)
	}
	data := frame[len(compactRunMarker):]
	r, err := decodeCompactRunHeader(data, limit)
	if err != nil {
		return encoded{}, r, err
	}
	payload := data[compactRunHeader:]
	// Exclude arbitrary cardinality payloads and long labels. These tables
	// retain at most 64 small typed bodies and 64 KiB of original JSON keys.
	switch r.Kind {
	case 2, 3, 5, 6, 9, 13:
	default:
		return decodeCompactRunBody(r, data, limit)
	}
	if len(payload) > 1024 {
		return decodeCompactRunBody(r, data, limit)
	}
	old, ok := c.values[string(payload)]
	if ok && old.Kind == r.Kind {
		r.Geo = old.Geo
		r.Coordinates = old.Coordinates
		r.Usage = old.Usage
		r.Quality = old.Quality
		r.RPKI = old.RPKI
		r.Tier1 = old.Tier1
		return compactDecodedFrame(r, data, limit)
	}
	row, r, err := decodeCompactRunBody(r, data, limit)
	if err != nil || ok {
		return row, r, err
	}
	if c.values == nil {
		c.values = make(map[string]via3.PublicRecord, len(c.keys))
	}
	key := string(payload)
	delete(c.values, c.keys[c.next])
	c.keys[c.next] = key
	c.next = (c.next + 1) % len(c.keys)
	c.values[key] = r
	return row, r, nil
}
