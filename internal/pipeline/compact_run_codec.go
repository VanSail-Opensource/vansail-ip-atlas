package pipeline

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/netip"
	"strconv"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/via3"
)

// Only the private sort transport changes. Common scalar fields use a closed
// 32-byte header; the selected union retains its exact JSON bytes and strict
// decoder. Every read still validates the complete payload. Public VIA3 and the
// original dense JSON record/sort/partition budgets are unchanged.
const compactRunMarker = "ATCP\x01\x00\x00\x00"
const compactRunHeader = 32

func runPayload(r via3.PublicRecord) (any, error) {
	values := [...]any{r.Geo, r.Coordinates, r.Network, r.Usage, r.Quality, r.Profile, r.ASNAggregate, r.RPKI, r.Origins, r.Path, r.Relationship, r.Tier1}
	present := [...]bool{r.Geo != nil, r.Coordinates != nil, r.Network != nil, r.Usage != nil, r.Quality != nil, r.Profile != nil, r.ASNAggregate != nil, r.RPKI != nil, r.Origins != nil, r.Path != nil, r.Relationship != nil, r.Tier1 != nil}
	count := 0
	for i, ok := range present {
		if ok {
			if r.Kind != uint16(i+2) {
				return nil, errors.New("private compact union differs from kind")
			}
			count++
		}
	}
	if count != 1 || r.Kind < 2 || r.Kind > 13 {
		return nil, errors.New("private compact union missing")
	}
	return values[r.Kind-2], nil
}

// Dense envelope with scalar values removed and all twelve union fields null.
// Replace exactly one four-byte null with the selected original JSON payload.
const denseRunEnvelope = `{"Version":,"Kind":,"Prefix":"","Exact":,"Inherited":,"ASN":,"Rank":,"Geo":null,"Coordinates":null,"Network":null,"Usage":null,"Quality":null,"Profile":null,"ASNAggregate":null,"RPKI":null,"Origins":null,"Path":null,"Relationship":null,"Tier1":null}`

func compactLogicalBytes(r via3.PublicRecord, payloadBytes int) int64 {
	var scratch [128]byte
	numbers := strconv.AppendUint(scratch[:0], uint64(r.Version), 10)
	numbers = strconv.AppendUint(numbers, uint64(r.Kind), 10)
	numbers = strconv.AppendUint(numbers, uint64(r.ASN), 10)
	numbers = strconv.AppendUint(numbers, uint64(r.Rank), 10)
	n := len(denseRunEnvelope) + len(numbers) + 10 + payloadBytes - 4
	if r.Exact {
		n--
	}
	if r.Inherited {
		n--
	}
	if r.Prefix.IsValid() {
		n += len(r.Prefix.AppendTo(scratch[:0]))
	}
	return int64(n)
}

func compactHeader(r via3.PublicRecord) ([compactRunHeader]byte, error) {
	var h [compactRunHeader]byte
	if r.Version != 3 || r.Kind < 2 || r.Kind > 13 || r.Kind != 11 && r.Rank != 0 || r.Kind != 8 && r.Kind < 11 && r.Kind != 9 && r.ASN != 0 {
		return h, errors.New("private compact metadata invalid")
	}
	binary.LittleEndian.PutUint16(h[0:2], r.Version)
	binary.LittleEndian.PutUint16(h[2:4], r.Kind)
	binary.LittleEndian.PutUint32(h[4:8], r.ASN)
	binary.LittleEndian.PutUint16(h[8:10], r.Rank)
	if r.Exact {
		h[10] |= 1
	}
	if r.Inherited {
		h[10] |= 2
	}
	if r.Kind == 8 || r.Kind >= 11 {
		if !facts.PublicASN(r.ASN) || r.Prefix.IsValid() || r.Exact || r.Inherited {
			return h, errors.New("private compact ASN metadata invalid")
		}
	} else {
		p := r.Prefix
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || r.Exact && p.Bits() != p.Addr().BitLen() || r.Inherited && (r.Exact || r.Kind == 7) {
			return h, errors.New("private compact prefix metadata invalid")
		}
		h[12] = byte(p.Bits())
		if p.Addr().Is4() {
			h[11] = 4
			a := p.Addr().As4()
			copy(h[28:32], a[:])
		} else {
			h[11] = 6
			a := p.Addr().As16()
			copy(h[16:32], a[:])
		}
	}
	return h, nil
}

func encodeCompactRunRecord(r via3.PublicRecord) (encoded, error) {
	header, err := compactHeader(r)
	if err != nil {
		return encoded{}, err
	}
	payload, err := runPayload(r)
	if err != nil {
		return encoded{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return encoded{}, err
	}
	logical := compactLogicalBytes(r, len(data))
	frame := make([]byte, compactRunHeader+len(data))
	copy(frame, header[:])
	copy(frame[compactRunHeader:], data)
	return encoded{key: identity(r), data: frame, logicalBytes: logical, compact: true}, nil
}

func decodeCompactRunPayload(data []byte, limit int64) (encoded, via3.PublicRecord, error) {
	var r via3.PublicRecord
	deny := errors.New("private compact frame invalid")
	if len(data) <= compactRunHeader || int64(len(data)) > limit {
		return encoded{}, r, deny
	}
	h := data[:compactRunHeader]
	r.Version, r.Kind = binary.LittleEndian.Uint16(h[0:2]), binary.LittleEndian.Uint16(h[2:4])
	r.ASN, r.Rank = binary.LittleEndian.Uint32(h[4:8]), binary.LittleEndian.Uint16(h[8:10])
	r.Exact, r.Inherited = h[10]&1 != 0, h[10]&2 != 0
	switch h[11] {
	case 0:
	case 4:
		r.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte(h[28:32])), int(h[12]))
	case 6:
		r.Prefix = netip.PrefixFrom(netip.AddrFrom16([16]byte(h[16:32])), int(h[12]))
	default:
		return encoded{}, r, deny
	}
	canonical, err := compactHeader(r)
	if err != nil || !bytes.Equal(h, canonical[:]) {
		return encoded{}, r, deny
	}
	var target any
	switch r.Kind {
	case 2:
		r.Geo = new(via3.GeoData)
		target = r.Geo
	case 3:
		r.Coordinates = new(via3.CoordinateData)
		target = r.Coordinates
	case 4:
		r.Network = new(via3.NetworkData)
		target = r.Network
	case 5:
		r.Usage = new(via3.UsageData)
		target = r.Usage
	case 6:
		r.Quality = new(via3.QualityData)
		target = r.Quality
	case 7:
		r.Profile = new(via3.ProfileData)
		target = r.Profile
	case 8:
		r.ASNAggregate = new(via3.ASNData)
		target = r.ASNAggregate
	case 9:
		r.RPKI = new(via3.RPKIData)
		target = r.RPKI
	case 10:
		r.Origins = new(via3.OriginsData)
		target = r.Origins
	case 11:
		r.Path = new(via3.PathData)
		target = r.Path
	case 12:
		r.Relationship = new(via3.RelationshipData)
		target = r.Relationship
	case 13:
		r.Tier1 = new(via3.TierData)
		target = r.Tier1
	}
	payload := data[compactRunHeader:]
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' || jsonv2.Unmarshal(payload, target, json.DefaultOptionsV1(), jsonv2.RejectUnknownMembers(true)) != nil {
		return encoded{}, r, deny
	}
	logical := compactLogicalBytes(r, len(payload))
	if logical > limit {
		return encoded{}, r, errors.New("private compact frame exceeds original byte limit")
	}
	return encoded{key: identity(r), data: data, logicalBytes: logical, compact: true}, r, nil
}

func reencodeRunRecord(r via3.PublicRecord, prior encoded) (encoded, error) {
	if prior.compact {
		return encodeCompactRunRecord(r)
	}
	return encodeRunRecord(r, prior.sparse)
}
