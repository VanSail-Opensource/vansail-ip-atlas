package pipeline

import (
	"bytes"
	"errors"

	"vansail-ip-atlas/internal/via3"
)

// This sink belongs to the running compiler sort. Direct Producer callers
// still receive independently decoded records through their own callback.
type spatialReplaySink struct {
	compiler *compiler
	append   func(ownedRunFrame) error
}

// Remember up to 64 small payloads for one leaf. A payload can enter only
// after a strict decode and the current compiler's normalizer and canonical
// writer produce that exact JSON for the same kind. Each hit independently
// validates its header, dense byte budget and pre-inheritance status.
type spatialReplayBodies struct {
	compiler *compiler
	kinds    map[string]uint16
	keys     [64]string
	next     int
}

var errSpatialPublicRow = errors.New("cached spatial public stream differs")

func (b *spatialReplayBodies) canonical(frame []byte, limit int64) (ownedRunFrame, error) {
	return b.canonicalMatching(frame, limit, nil)
}

func (b *spatialReplayBodies) canonicalMatching(frame []byte, limit int64, matches func(via3.PublicRecord) bool) (ownedRunFrame, error) {
	if !bytes.HasPrefix(frame, []byte(compactRunMarker)) {
		_, record, err := decodeRunPayload(frame, limit)
		if err != nil {
			return ownedRunFrame{}, err
		}
		if record.Kind >= 8 && record.Kind != 9 || matches != nil && !matches(record) {
			return ownedRunFrame{}, errSpatialPublicRow
		}
		return b.compiler.newCanonicalRunFrame(record)
	}
	data := frame[len(compactRunMarker):]
	record, err := decodeCompactRunHeader(data, limit)
	if err != nil {
		return ownedRunFrame{}, err
	}
	if record.Inherited || record.Kind >= 8 && record.Kind != 9 || matches != nil && !matches(record) {
		return ownedRunFrame{}, errSpatialPublicRow
	}
	body := data[compactRunHeader:]
	eligible := record.Kind != 7 && len(body) <= 1024
	if eligible && b.kinds[string(body)] == record.Kind {
		row, _, err := compactDecodedFrame(record, data, limit)
		if err != nil {
			return ownedRunFrame{}, err
		}
		// The run writer owns these bytes even after a reader advances or
		// another callback changes its input buffer.
		row.data = bytes.Clone(data)
		return ownedRunFrame{owner: b.compiler, row: row}, nil
	}
	_, record, err = decodeCompactRunBody(record, data, limit)
	if err != nil {
		return ownedRunFrame{}, err
	}
	out, err := b.compiler.newCanonicalRunFrame(record)
	if err == nil && eligible && bytes.Equal(body, out.row.data[compactRunHeader:]) {
		if b.kinds == nil {
			b.kinds = make(map[string]uint16, len(b.keys))
		}
		key := string(body)
		if _, exists := b.kinds[key]; !exists {
			delete(b.kinds, b.keys[b.next])
			b.keys[b.next] = key
			b.next = (b.next + 1) % len(b.keys)
			b.kinds[key] = record.Kind
		}
	}
	return out, err
}
