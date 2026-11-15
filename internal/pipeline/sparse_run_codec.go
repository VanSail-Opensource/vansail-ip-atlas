package pipeline

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"

	"vansail-ip-atlas/internal/via3"
)

// The marker belongs to each length-delimited private frame, so sparse rows
// remain distinguishable from legacy JSON even when a run contains both. It
// never changes a public record or the VIA3 format.
const sparseRunMarker = "ATSP\x01\x00\x00\x00"

// Keep the exact PublicRecord field order and types. The explicit conversion
// below fails to compile if that structure changes; only nil union fields are
// omitted. Nested nulls, empty arrays, zero payloads and all keys are preserved.
type sparseRunRecord struct {
	Version      uint16
	Kind         uint16
	Prefix       netip.Prefix
	Exact        bool
	Inherited    bool
	ASN          uint32
	Rank         uint16
	Geo          *via3.GeoData          `json:",omitempty"`
	Coordinates  *via3.CoordinateData   `json:",omitempty"`
	Network      *via3.NetworkData      `json:",omitempty"`
	Usage        *via3.UsageData        `json:",omitempty"`
	Quality      *via3.QualityData      `json:",omitempty"`
	Profile      *via3.ProfileData      `json:",omitempty"`
	ASNAggregate *via3.ASNData          `json:",omitempty"`
	RPKI         *via3.RPKIData         `json:",omitempty"`
	Origins      *via3.OriginsData      `json:",omitempty"`
	Path         *via3.PathData         `json:",omitempty"`
	Relationship *via3.RelationshipData `json:",omitempty"`
	Tier1        *via3.TierData         `json:",omitempty"`
}

func omittedRunBytes(r via3.PublicRecord) int64 {
	var n int64
	for _, field := range [...]struct {
		nilValue bool
		name     string
	}{
		{r.Geo == nil, "Geo"}, {r.Coordinates == nil, "Coordinates"},
		{r.Network == nil, "Network"}, {r.Usage == nil, "Usage"},
		{r.Quality == nil, "Quality"}, {r.Profile == nil, "Profile"},
		{r.ASNAggregate == nil, "ASNAggregate"}, {r.RPKI == nil, "RPKI"},
		{r.Origins == nil, "Origins"}, {r.Path == nil, "Path"},
		{r.Relationship == nil, "Relationship"}, {r.Tier1 == nil, "Tier1"},
	} {
		if field.nilValue {
			n += int64(len(field.name) + len(`,"":null`))
		}
	}
	return n
}

func encodeRunRecord(record via3.PublicRecord, sparse bool) (encoded, error) {
	var data []byte
	var err error
	if sparse {
		data, err = json.Marshal(sparseRunRecord(record))
	} else {
		data, err = json.Marshal(record)
	}
	if err != nil {
		return encoded{}, err
	}
	row := encoded{key: identity(record), data: data, logicalBytes: int64(len(data)), sparse: sparse}
	if sparse {
		row.logicalBytes += omittedRunBytes(record)
	}
	return row, nil
}

func (r encoded) frameBytes() int64 {
	n := int64(4 + len(r.data))
	if r.sparse {
		n += int64(len(sparseRunMarker))
	}
	return n
}

func writeRunFrame(w io.Writer, row encoded) error {
	length := row.frameBytes() - 4
	if length <= 0 || length > int64(^uint32(0)) {
		return errors.New("private sort frame exceeds limit")
	}
	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], uint32(length))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if row.sparse {
		if _, err := io.WriteString(w, sparseRunMarker); err != nil {
			return err
		}
	}
	_, err := w.Write(row.data)
	return err
}

func decodeRunPayload(data []byte, limit int64) (encoded, via3.PublicRecord, error) {
	sparse := bytes.HasPrefix(data, []byte(sparseRunMarker[:4]))
	if sparse {
		if !bytes.HasPrefix(data, []byte(sparseRunMarker)) {
			return encoded{}, via3.PublicRecord{}, errors.New("private sparse frame version invalid")
		}
		data = data[len(sparseRunMarker):]
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return encoded{}, via3.PublicRecord{}, errors.New("private sort frame exceeds limit")
	}
	record, err := decode(data)
	if err != nil {
		return encoded{}, record, err
	}
	row := encoded{key: identity(record), data: data, logicalBytes: int64(len(data)), sparse: sparse}
	if sparse {
		// Writer-produced sparse frames have exactly their original dense size.
		// For noncanonical private input this deliberately overcharges explicit
		// nulls rather than treating decoded values as proof a field was absent.
		// Preserve the original bytes: duplicate keys/whitespace/case variants
		// must never collapse distinct same-identity frames during merge.
		row.logicalBytes += omittedRunBytes(record)
	}
	if row.logicalBytes > limit {
		return encoded{}, record, errors.New("private sort frame exceeds original byte limit")
	}
	return row, record, nil
}

func lessEncoded(a, b encoded) bool {
	if a.key != b.key {
		return a.key < b.key
	}
	if a.sparse != b.sparse {
		return !a.sparse
	}
	return bytes.Compare(a.data, b.data) < 0
}

func equalEncoded(a, b encoded) bool {
	return a.sparse == b.sparse && bytes.Equal(a.data, b.data)
}
