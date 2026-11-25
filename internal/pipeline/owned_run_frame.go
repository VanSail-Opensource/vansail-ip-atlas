package pipeline

import (
	"errors"

	"vansail-ip-atlas/internal/via3"
)

// ownedRunFrame carries canonical transport bytes created in this compilation.
// It is not a public-fact semantic approval. The bytes have no accessor and
// never alias caller records, decoded payloads or a reusable reader buffer.
// An owned frame originates in the canonical encoder or an authenticated reader.
// Changing an overlay strictly decodes its original payload before re-encoding.
// A nil owner marks a fallback frame that can never establish a segment proof.
type ownedRunFrame struct {
	owner *compiler
	row   encoded
}

func (c *compiler) newCanonicalRunFrame(input via3.PublicRecord) (ownedRunFrame, error) {
	if c == nil {
		return ownedRunFrame{}, errors.New("canonical run frame requires an owner")
	}
	record, err := normalize(input)
	if err != nil {
		return ownedRunFrame{}, err
	}
	c.redactPrivateLabels(&record)
	row, err := encodeCompactRunRecord(record)
	if err != nil {
		return ownedRunFrame{}, err
	}
	return ownedRunFrame{owner: c, row: row}, nil
}

func (f ownedRunFrame) ownedBy(c *compiler) bool {
	return c != nil && f.owner == c && f.row.compact && !f.row.sparse &&
		len(f.row.key) == 32 && len(f.row.data) > compactRunHeader && f.row.logicalBytes > 0
}

// In a planning scan the record can contain only header fields. Reconstruct
// the complete original payload before changing its inheritance flag. A strict
// fallback keeps its original representation and never gains a proof.
func (f ownedRunFrame) inherited(record via3.PublicRecord) (ownedRunFrame, error) {
	if f.owner != nil {
		_, original, err := decodeCompactRunPayload(f.row.data, f.owner.options.Limits.RecordBytes)
		if err != nil {
			return ownedRunFrame{}, err
		}
		record = original
	}
	record.Inherited = true
	row, err := reencodeRunRecord(record, f.row)
	if err != nil {
		return ownedRunFrame{}, err
	}
	return ownedRunFrame{owner: f.owner, row: row}, nil
}

// This is usable only after an original process-local segment proof has
// authenticated the actual frame bytes. Kind 12 retains strict payload decoding
// because Relationship.To participates in its identity but is not in the header.
func decodeOwnedRunPayload(data []byte, limit int64) (encoded, via3.PublicRecord, error) {
	if len(data) < len(compactRunMarker) || string(data[:len(compactRunMarker)]) != compactRunMarker {
		return encoded{}, via3.PublicRecord{}, errors.New("proved run is not canonical compact transport")
	}
	data = data[len(compactRunMarker):]
	record, err := decodeCompactRunHeader(data, limit)
	if err != nil {
		return encoded{}, record, err
	}
	if record.Kind == 12 {
		return decodeCompactRunBody(record, data, limit)
	}
	logical := compactLogicalBytes(record, len(data)-compactRunHeader)
	if logical > limit {
		return encoded{}, record, errors.New("private compact frame exceeds original byte limit")
	}
	return encoded{key: identity(record), data: data, logicalBytes: logical, compact: true}, record, nil
}
