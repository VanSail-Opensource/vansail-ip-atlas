package pipeline

import (
	"errors"

	"vansail-ip-atlas/internal/via3"
)

// ownedRunFrame carries canonical transport bytes created in this compilation.
// It is not a public-fact semantic approval. The bytes have no accessor and
// never alias caller records, decoded payloads or a reusable reader buffer.
// The only factories are normalization+encoding below and an authenticated
// compiler-owned run reader. Final leaves still use the strict payload decoder.
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
