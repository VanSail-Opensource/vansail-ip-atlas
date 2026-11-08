package via3

import (
	"context"
	"encoding/hex"
	"golang.org/x/text/unicode/norm"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
	"vansail-ip-atlas/internal/facts"
)

// PublicRecord is a versioned tagged union AFTER private evidence fusion. Exactly
// one member matching Kind must be nonnil. Source/proof/credential fields have no
// representation here. CompilePartition buffers one bounded partition, not a full
// bulk dataset; its upstream partition sink owns streaming and external sorting.
type PublicRecord struct {
	Version      uint16
	Kind         uint16
	Prefix       netip.Prefix
	Exact        bool
	Inherited    bool
	ASN          uint32
	Rank         uint16
	Geo          *GeoData
	Coordinates  *CoordinateData
	Network      *NetworkData
	Usage        *UsageData
	Quality      *QualityData
	Profile      *ProfileData
	ASNAggregate *ASNData
	RPKI         *RPKIData
	Origins      *OriginsData
	Path         *PathData
	Relationship *RelationshipData
	Tier1        *TierData
}
type GeoData struct{ Country, RegistrationCountry, Region, City string }
type CoordinateData struct {
	Latitude, Longitude float64
	Precision           uint8
	Unknown             bool // compile-only tombstone; encoded as the existing zero-presence row
}
type NetworkData struct {
	Name, Organization, ISP string
	Origins                 []uint32
}
type UsageData struct {
	Type, Assignment           uint8
	Anycast, DirectedBroadcast *bool
}
type QualityData struct {
	Score                         *uint8
	Confidence                    uint8
	Reasons                       uint32
	Exact, Prefix, ASN, Neighbors *float64
}
type CellData struct {
	Address                    netip.Addr
	Usage, Assignment          uint8
	Anycast, DirectedBroadcast *bool
	Score                      *uint8
	Confidence                 uint8
	Reasons                    uint32
	ExactRisk                  *float64
	AttachNetwork              bool
}
type ProfileData struct {
	Cells       []CellData
	DominantASN uint32
}
type ASNData struct {
	Name, Organization, Country string
	Risk                        *float64
	Confidence                  uint8
	Reasons                     uint32
	Prefixes                    []netip.Prefix
	CustomerCone, TransitDegree *uint32
	NetworkClass, Stability     uint8
}
type RPKIData struct{ Status, MaximumLength uint8 }
type OriginsData struct{ ASNs []uint32 }
type SegmentData struct {
	Type uint8
	ASNs []uint32
}
type PathData struct {
	Segments      []SegmentData
	GraphEligible bool
	Visibility    uint8
}
type RelationshipData struct {
	To                 uint32
	Relation           uint8
	Observed, Inferred bool
}
type TierData struct{ NetworkClass, Stability uint8 }
type PartitionInput struct {
	Partition    string
	PrefixRoutes []netip.Prefix
	ASNRoutes    []uint32
	Records      []PublicRecord
}
type CompiledPartition struct {
	Objects      []BuiltObject
	Destinations map[uint16]BuiltObject
}
type CompileInput struct {
	Mode              string
	Clock, ValidUntil int64
	Partitions        []PartitionInput
	ProductionGate    func(context.Context) error
}

func recordPartitionValid(partition string, r PublicRecord) bool {
	if partition == "all" {
		return true
	}
	isASN := r.Kind == 8 || r.Kind >= 11
	if strings.HasPrefix(partition, "asn:") {
		if !isASN {
			return false
		}
		p := strings.Split(partition, ":")
		first, _ := strconv.ParseUint(p[1], 10, 32)
		last, _ := strconv.ParseUint(p[2], 10, 32)
		return uint64(r.ASN) >= first && uint64(r.ASN) <= last
	}
	if isASN {
		return false
	}
	p := strings.Split(partition[2:], "/")
	raw, _ := hex.DecodeString(p[0])
	length, _ := strconv.Atoi(p[1])
	var address netip.Addr
	if partition[0] == '4' {
		var b [4]byte
		copy(b[:], raw[12:])
		address = netip.AddrFrom4(b)
	} else {
		var b [16]byte
		copy(b[:], raw)
		address = netip.AddrFrom16(b)
	}
	scope := netip.PrefixFrom(address, length)
	if r.Inherited {
		return r.Prefix.Addr().BitLen() == address.BitLen() && r.Prefix.Bits() <= length && r.Prefix.Contains(address)
	}
	return r.Prefix.Addr().BitLen() == address.BitLen() && r.Prefix.Bits() >= length && scope.Contains(r.Prefix.Addr())
}

func SanitizeLabel(input string) string {
	if !utf8.ValidString(input) {
		return ""
	}
	input = norm.NFC.String(input)
	tokens := strings.Fields(input)
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.Trim(token, ",;!()[]\"'")
		unsafe := false
		for _, r := range token {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				unsafe = true
				break
			}
		}
		if unsafe || unsafeLabelToken(token) {
			continue
		}
		if token != "" {
			out = append(out, token)
		}
	}
	result := strings.Join(out, " ")
	if len(result) > 256 {
		result = result[:256]
		for !utf8.ValidString(result) {
			result = result[:len(result)-1]
		}
		result = strings.TrimSpace(result)
	}
	return result
}
func countryNumber(value string) (uint16, error) {
	if value == "" {
		return 0, nil
	}
	if !facts.CountryValid(value) {
		return 0, fail("record")
	}
	return 1 + uint16(value[0]-'A')*26 + uint16(value[1]-'A'), nil
}
func millionths(value *float64, cap float64) (uint32, error) {
	if value == nil {
		return 0, nil
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > cap {
		return 0, fail("record")
	}
	return uint32(math.Floor(*value*1000000 + 0.5)), nil
}
func normalizedASNs(input []uint32) ([]uint32, error) {
	out := append([]uint32(nil), input...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	result := out[:0]
	for _, asn := range out {
		if !facts.PublicASN(asn) {
			return nil, fail("record")
		}
		if len(result) == 0 || result[len(result)-1] != asn {
			result = append(result, asn)
		}
	}
	return result, nil
}
func recordUnionValid(r PublicRecord) bool {
	members := []bool{r.Geo != nil, r.Coordinates != nil, r.Network != nil, r.Usage != nil, r.Quality != nil, r.Profile != nil, r.ASNAggregate != nil, r.RPKI != nil, r.Origins != nil, r.Path != nil, r.Relationship != nil, r.Tier1 != nil}
	count := 0
	for i, value := range members {
		if value {
			count++
			if uint16(i+2) != r.Kind {
				return false
			}
		}
	}
	return r.Version == 3 && count == 1
}

func CompilePartition(ctx context.Context, input PartitionInput) (CompiledPartition, error) {
	out := CompiledPartition{Objects: []BuiltObject{}, Destinations: make(map[uint16]BuiltObject)}
	if !validPartition(input.Partition) || len(input.Records) > 32768 {
		return out, fail("partition_budget")
	}
	groups := make(map[uint16][]PublicRecord)
	labels := make(map[string]bool)
	estimated := 0
	label := func(text string) {
		if text = SanitizeLabel(text); text != "" {
			labels[text] = true
			estimated += len(text)
		}
	}
	for _, r := range input.Records {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !recordUnionValid(r) {
			return out, fail("record")
		}
		width, _ := schema(r.Kind)
		estimated += width + 64
		if r.Kind == 8 || r.Kind >= 11 {
			if !facts.PublicASN(r.ASN) || r.Prefix.IsValid() || r.Exact || r.Inherited {
				return out, fail("record")
			}
		} else {
			if !r.Prefix.IsValid() {
				return out, fail("record")
			}
			r.Prefix = r.Prefix.Masked()
			if r.Prefix.Addr().Is4In6() && r.Prefix.Bits() >= 96 {
				r.Prefix = netip.PrefixFrom(r.Prefix.Addr().Unmap(), r.Prefix.Bits()-96).Masked()
			}
			if r.Exact && r.Prefix.Bits() != r.Prefix.Addr().BitLen() {
				return out, fail("record")
			}
			if r.Inherited && (r.Kind == 7 || r.Exact) {
				return out, fail("record")
			}
			if r.Kind == 9 && !facts.PublicASN(r.ASN) {
				return out, fail("record")
			}
		}
		if !recordPartitionValid(input.Partition, r) {
			return out, fail("record")
		}
		switch r.Kind {
		case 2:
			label(r.Geo.Region)
			label(r.Geo.City)
		case 4:
			label(r.Network.Name)
			label(r.Network.Organization)
			label(r.Network.ISP)
			estimated += 4 * len(r.Network.Origins)
		case 7:
			if len(r.Profile.Cells) > 256 {
				return out, fail("record")
			}
			estimated += 32 * len(r.Profile.Cells)
		case 8:
			label(r.ASNAggregate.Name)
			label(r.ASNAggregate.Organization)
			estimated += 24 * len(r.ASNAggregate.Prefixes)
		case 10:
			estimated += 4 * len(r.Origins.ASNs)
		case 11:
			for _, segment := range r.Path.Segments {
				estimated += 12 + 4*len(segment.ASNs)
			}
		}
		if estimated > 32<<20 {
			return out, fail("partition_budget")
		}
		groups[r.Kind] = append(groups[r.Kind], r)
	}
	add := func(shard Shard, partition string) (BuiltObject, error) {
		if err := ValidatePublicProfile(shard); err != nil {
			return BuiltObject{}, err
		}
		bytes, err := Write(ctx, shard)
		if err != nil {
			return BuiltObject{}, err
		}
		object := BuiltObject{Info: ObjectInfo{Bytes: len(bytes), Kind: shard.Kind, Partition: partition, SHA256: Hash(bytes)}, Bytes: bytes, Shard: shard}
		out.Objects = append(out.Objects, object)
		return object, nil
	}
	var dict BuiltObject
	stringsList := make([]string, 0, len(labels))
	for text := range labels {
		stringsList = append(stringsList, text)
	}
	sort.Strings(stringsList)
	stringIDs := make(map[string]uint32, len(stringsList))
	if len(stringsList) > 0 {
		offsets := []uint32{0}
		var text []byte
		for i, label := range stringsList {
			stringIDs[label] = uint32(i)
			text = append(text, []byte(label)...)
			offsets = append(offsets, uint32(len(text)))
		}
		shard := newShard(14)
		shard.set(5, intVector(offsets...))
		shard.set(6, BytesVector(text))
		var err error
		dict, err = add(shard, "all")
		if err != nil {
			return out, err
		}
	}
	writeLabel := func(row []byte, offset int, bit uint, text string, dictOrdinal uint32) {
		text = SanitizeLabel(text)
		if text == "" {
			nullRef(row, offset)
			return
		}
		p32(row, 0, u32(row, 0)|bits(bit))
		stringRef(row, offset, dictOrdinal, stringIDs[text])
	}
	for kind := uint16(2); kind <= 13; kind++ {
		records := groups[kind]
		if len(records) == 0 {
			continue
		}
		sort.SliceStable(records, func(i, j int) bool {
			a, b := records[i], records[j]
			if kind == 8 || kind >= 11 {
				if a.ASN != b.ASN {
					return a.ASN < b.ASN
				}
				if kind == 12 {
					return a.Relationship.To < b.Relationship.To
				}
				return a.Rank < b.Rank
			}
			c := keyCompare(PrefixKey(a.Prefix, a.Exact, 0), PrefixKey(b.Prefix, b.Exact, 0))
			if c != 0 {
				return c < 0
			}
			if kind == 9 {
				return a.ASN < b.ASN
			}
			return !a.Inherited && b.Inherited
		})
		width, _ := schema(kind)
		var rows, index, overlays, asnIndex, integerRows, segmentRows, cellRows, pageRows [][]byte
		var references []BuiltObject
		dictionaryUsed := false
		for _, r := range records {
			if kind == 2 && (SanitizeLabel(r.Geo.Region) != "" || SanitizeLabel(r.Geo.City) != "") || kind == 4 && (SanitizeLabel(r.Network.Name) != "" || SanitizeLabel(r.Network.Organization) != "" || SanitizeLabel(r.Network.ISP) != "") || kind == 8 && (SanitizeLabel(r.ASNAggregate.Name) != "" || SanitizeLabel(r.ASNAggregate.Organization) != "") {
				dictionaryUsed = true
			}
		}
		if dictionaryUsed {
			references = append(references, dict)
		}
		// ASN prefix page objects precede their aggregate; each page has <=256 rows.
		pagesByASN := make(map[uint32][]BuiltObject)
		if kind == 8 {
			for _, r := range records {
				prefixes := append([]netip.Prefix(nil), r.ASNAggregate.Prefixes...)
				for i := range prefixes {
					if !prefixes[i].IsValid() {
						return out, fail("record")
					}
					prefixes[i] = prefixes[i].Masked()
				}
				sort.Slice(prefixes, func(i, j int) bool {
					return keyCompare(PrefixKey(prefixes[i], false, 0), PrefixKey(prefixes[j], false, 0)) < 0
				})
				for first := 0; first < len(prefixes); first += 256 {
					end := first + 256
					if end > len(prefixes) {
						end = len(prefixes)
					}
					prefixRows := make([][]byte, 0, end-first)
					for i := first; i < end; i++ {
						if i > 0 && prefixes[i] == prefixes[i-1] {
							return out, fail("record")
						}
						key := PrefixKey(prefixes[i], false, 0)
						row := make([]byte, 24)
						copy(row[:20], key[:20])
						prefixRows = append(prefixRows, row)
					}
					page := newShard(8)
					page.set(11, Vector(24, prefixRows...))
					object, err := add(page, "all")
					if err != nil {
						return out, err
					}
					pagesByASN[r.ASN] = append(pagesByASN[r.ASN], object)
					references = append(references, object)
				}
			}
		}
		if kind == 7 {
			needed := false
			for _, record := range records {
				for _, cell := range record.Profile.Cells {
					if cell.AttachNetwork {
						needed = true
					}
				}
			}
			if network, ok := out.Destinations[4]; ok && needed {
				references = append(references, network)
			}
		}
		networkOrdinals := make(map[string]uint32)
		if network, ok := out.Destinations[4]; ok && kind == 7 {
			records, _ := network.Shard.Rows(3)
			for ordinal := 0; ordinal < len(records)/40; ordinal++ {
				key := string(records[ordinal*40 : (ordinal+1)*40])
				if _, exists := networkOrdinals[key]; !exists {
					networkOrdinals[key] = uint32(ordinal)
				}
			}
		}
		// Deduplicate shared dictionaries/pages in this local reference directory.
		unique := make(map[string]BuiltObject)
		for _, object := range references {
			unique[object.Info.SHA256] = object
		}
		references = references[:0]
		for _, object := range unique {
			references = append(references, object)
		}
		directory, objectID := makeObjectDir(references...)
		dictID := uint32(0)
		if dictionaryUsed {
			dictID = objectID(dict)
		}
		appendInts := func(values []uint32) (uint32, uint32) {
			first := uint32(len(integerRows))
			for _, v := range values {
				row := make([]byte, 4)
				p32(row, 0, v)
				integerRows = append(integerRows, row)
			}
			return first, uint32(len(values))
		}
		for recordPosition, r := range records {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			row := make([]byte, width)
			ordinal := uint32(len(rows))
			if kind == 11 && recordPosition > 0 && records[recordPosition-1].ASN == r.ASN && records[recordPosition-1].Rank == r.Rank {
				return out, fail("record")
			}
			if kind == 8 || kind >= 11 {
				if len(asnIndex) == 0 || u32(asnIndex[len(asnIndex)-1], 0) != r.ASN {
					key := make([]byte, 8)
					p32(key, 0, r.ASN)
					p32(key, 4, ordinal)
					asnIndex = append(asnIndex, key)
				} else if kind != 11 && kind != 12 {
					return out, fail("record")
				}
			} else {
				key := PrefixKey(r.Prefix, r.Exact, ordinal)
				if r.Inherited {
					overlays = append(overlays, key)
				} else {
					index = append(index, key)
				}
			}
			switch kind {
			case 2:
				value, err := countryNumber(r.Geo.Country)
				if err != nil {
					return out, err
				}
				if value != 0 {
					p32(row, 0, bits(0))
					p16(row, 4, value)
				}
				value, err = countryNumber(r.Geo.RegistrationCountry)
				if err != nil {
					return out, err
				}
				if value != 0 {
					p32(row, 0, u32(row, 0)|bits(1))
					p16(row, 6, value)
				}
				writeLabel(row, 8, 2, r.Geo.Region, dictID)
				writeLabel(row, 16, 3, r.Geo.City, dictID)
			case 3:
				v := r.Coordinates
				if v.Unknown {
					if v.Latitude != 0 || v.Longitude != 0 || v.Precision != 0 {
						return out, fail("record")
					}
					break
				}
				if math.IsNaN(v.Latitude) || math.IsNaN(v.Longitude) || math.IsInf(v.Latitude, 0) || math.IsInf(v.Longitude, 0) || math.Abs(v.Latitude) > 90 || math.Abs(v.Longitude) > 180 || v.Precision < 1 || v.Precision > 4 {
					return out, fail("record")
				}
				p32(row, 0, bits(4))
				p32(row, 4, uint32(int32(math.Round(v.Latitude*1000))))
				p32(row, 8, uint32(int32(math.Round(v.Longitude*1000))))
				row[12] = v.Precision
			case 4:
				p32(row, 0, bits(15))
				v := r.Network
				if v.Origins != nil {
					origins, err := normalizedASNs(v.Origins)
					if err != nil {
						return out, err
					}
					first, count := appendInts(origins)
					p32(row, 0, u32(row, 0)|bits(19))
					p32(row, 4, first)
					p32(row, 8, count)
				}
				writeLabel(row, 16, 16, v.Name, dictID)
				writeLabel(row, 24, 17, v.Organization, dictID)
				writeLabel(row, 32, 18, v.ISP, dictID)
			case 5:
				v := r.Usage
				if v.Type != 0 {
					p32(row, 0, bits(5))
					row[4] = v.Type
				}
				if v.Assignment != 0 {
					p32(row, 0, u32(row, 0)|bits(6))
					row[5] = v.Assignment
				}
				if v.Anycast != nil {
					p32(row, 0, u32(row, 0)|bits(7))
					if *v.Anycast {
						row[6] |= 1
					}
				}
				if v.DirectedBroadcast != nil {
					if !r.Prefix.Addr().Is4() {
						return out, fail("record")
					}
					p32(row, 0, u32(row, 0)|bits(8))
					if *v.DirectedBroadcast {
						row[6] |= 2
					}
				}
			case 6:
				v := r.Quality
				if r.Prefix.Addr().Is6() && v.Neighbors != nil {
					return out, fail("record")
				}
				p32(row, 0, bits(14))
				p32(row, 4, v.Reasons)
				if v.Score != nil {
					if !r.Prefix.Addr().Is4() {
						return out, fail("record")
					}
					p32(row, 0, u32(row, 0)|bits(9))
					row[8] = 1
					row[9] = *v.Score
					row[10] = v.Confidence
					if v.Exact == nil || v.Prefix == nil || v.ASN == nil || v.Neighbors == nil {
						return out, fail("record")
					}
					risk := *v.Exact + *v.Prefix + *v.ASN + *v.Neighbors
					if risk < 0 {
						risk = 0
					}
					if risk > 1 {
						risk = 1
					}
					if *v.Score != uint8(math.Floor(100*(1-risk)+.5)) {
						return out, fail("record")
					}
				}
				for i, value := range []*float64{v.Exact, v.Prefix, v.ASN, v.Neighbors} {
					if value != nil {
						q, err := millionths(value, []float64{.55, .18, .15, .12}[i])
						if err != nil {
							return out, err
						}
						p32(row, 0, u32(row, 0)|bits(uint(10+i)))
						p32(row, 12+i*4, q)
					}
				}
			case 7:
				if !r.Prefix.Addr().Is4() || r.Prefix.Bits() != 24 {
					return out, fail("record")
				}
				v := r.Profile
				cells := append([]CellData(nil), v.Cells...)
				sort.Slice(cells, func(i, j int) bool { return cells[i].Address.Unmap().Less(cells[j].Address.Unmap()) })
				p32(row, 0, bits(21))
				p32(row, 4, uint32(len(cellRows)))
				p16(row, 8, uint16(len(cells)))
				p32(row, 16, v.DominantASN)
				assessed, positive, sum := 0, 0, 0
				minimumConfidence := uint8(3)
				for i, cell := range cells {
					addr := cell.Address.Unmap()
					if !addr.Is4() || !r.Prefix.Contains(addr) || i > 0 && addr == cells[i-1].Address.Unmap() {
						return out, fail("record")
					}
					c := make([]byte, 32)
					a := addr.As4()
					c[0] = a[3]
					nullRef(c, 16)
					if cell.Usage != 0 {
						c[1] |= 1
						c[2] = cell.Usage
					}
					if cell.Assignment != 0 {
						c[1] |= 2
						c[3] = cell.Assignment
					}
					c[1] |= 4
					p32(c, 4, cell.Reasons)
					if cell.Reasons != 0 {
						positive++
					}
					if cell.Score != nil {
						c[1] |= 8
						c[8] = *cell.Score
						c[9] = cell.Confidence
						sum += int(*cell.Score)
						assessed++
						if cell.Confidence < minimumConfidence {
							minimumConfidence = cell.Confidence
						}
					}
					if cell.ExactRisk != nil {
						value, err := millionths(cell.ExactRisk, 1)
						if err != nil {
							return out, err
						}
						c[1] |= 16
						p32(c, 12, value)
					}
					if cell.Anycast != nil {
						c[1] |= 64
						if *cell.Anycast {
							c[24] |= 1
						}
					}
					if cell.DirectedBroadcast != nil {
						c[1] |= 128
						if *cell.DirectedBroadcast {
							c[24] |= 2
						}
					}
					if cell.AttachNetwork {
						network, ok := out.Destinations[4]
						if !ok {
							return out, fail("record")
						}
						n, _, ok := network.Shard.findPrefix(addr)
						if !ok {
							return out, fail("record")
						}
						ordinal, found := networkOrdinals[string(n)]
						if !found {
							return out, fail("record")
						}
						c[1] |= 32
						stringRef(c, 16, objectID(network), ordinal)
					}
					cellRows = append(cellRows, c)
				}
				p16(row, 10, uint16(assessed))
				p16(row, 12, uint16(positive))
				if assessed == 256 && len(cells) == 256 {
					p32(row, 0, u32(row, 0)|bits(22))
					row[20] = byte((sum + 128) / 256)
					row[21] = minimumConfidence
				}
			case 8:
				v := r.ASNAggregate
				p32(row, 4, r.ASN)
				writeLabel(row, 8, 16, v.Name, dictID)
				writeLabel(row, 16, 17, v.Organization, dictID)
				country, err := countryNumber(v.Country)
				if err != nil {
					return out, err
				}
				if country != 0 {
					p32(row, 0, u32(row, 0)|bits(31))
					p16(row, 24, country)
				}
				if v.Risk != nil {
					risk, err := millionths(v.Risk, 1)
					if err != nil {
						return out, err
					}
					p32(row, 0, u32(row, 0)|bits(23))
					p32(row, 28, risk)
					row[26] = 1
					if risk >= 333334 {
						row[26] = 2
					}
					if risk >= 666667 {
						row[26] = 3
					}
					row[27] = v.Confidence
				}
				if v.Reasons != 0 {
					p32(row, 0, u32(row, 0)|bits(14))
					p32(row, 32, v.Reasons)
				}
				if v.CustomerCone != nil {
					p32(row, 0, u32(row, 0)|bits(25))
					p32(row, 44, *v.CustomerCone)
				}
				if v.TransitDegree != nil {
					p32(row, 0, u32(row, 0)|bits(26))
					p32(row, 48, *v.TransitDegree)
				}
				if v.NetworkClass != 0 {
					p32(row, 0, u32(row, 0)|bits(27))
					row[52] = v.NetworkClass
				}
				if v.Stability != 0 {
					p32(row, 0, u32(row, 0)|bits(28))
					row[53] = v.Stability
				}
				if v.Prefixes != nil {
					p32(row, 0, u32(row, 0)|bits(24))
					p32(row, 36, uint32(len(pageRows)))
					p32(row, 40, uint32(len(pagesByASN[r.ASN])))
					for _, page := range pagesByASN[r.ASN] {
						p := make([]byte, 16)
						p32(p, 0, objectID(page))
						prefixes, _ := page.Shard.Rows(11)
						p32(p, 8, uint32(len(prefixes)/24))
						pageRows = append(pageRows, p)
					}
				}
			case 9:
				p32(row, 0, bits(20))
				p32(row, 4, r.ASN)
				row[8] = r.RPKI.Status
				row[9] = r.RPKI.MaximumLength
			case 10:
				values, err := normalizedASNs(r.Origins.ASNs)
				if err != nil {
					return out, err
				}
				p32(row, 0, bits(19))
				first, count := appendInts(values)
				p32(row, 4, first)
				p32(row, 8, count)
			case 11:
				v := r.Path
				if len(v.Segments) > 255 {
					return out, fail("record")
				}
				p32(row, 0, bits(29))
				p32(row, 4, r.ASN)
				p32(row, 8, uint32(len(segmentRows)))
				p16(row, 12, uint16(len(v.Segments)))
				if v.GraphEligible {
					row[14] = 1
				}
				row[15] = v.Visibility
				for _, segment := range v.Segments {
					values := append([]uint32(nil), segment.ASNs...)
					if segment.Type == 2 || segment.Type == 4 {
						sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
					}
					s := make([]byte, 12)
					s[0] = segment.Type
					first, count := appendInts(values)
					p32(s, 4, first)
					p32(s, 8, count)
					segmentRows = append(segmentRows, s)
				}
			case 12:
				p32(row, 0, bits(30))
				p32(row, 4, r.ASN)
				p32(row, 8, r.Relationship.To)
				row[12] = r.Relationship.Relation
				if r.Relationship.Observed {
					row[13] |= 1
				}
				if r.Relationship.Inferred {
					row[13] |= 2
				}
			case 13:
				p32(row, 0, bits(27, 28))
				p32(row, 4, r.ASN)
				row[8] = r.Tier1.NetworkClass
				row[9] = r.Tier1.Stability
			}
			rows = append(rows, row)
		}
		shard := newShard(kind, rows...)
		if shard.Section(1) != nil {
			shard.set(1, Vector(32, index...))
		}
		if shard.Section(8) != nil {
			shard.set(8, Vector(32, overlays...))
		}
		if shard.Section(2) != nil {
			shard.set(2, Vector(8, asnIndex...))
		}
		if shard.Section(4) != nil {
			shard.set(4, Vector(4, integerRows...))
		}
		if shard.Section(7) != nil {
			shard.set(7, directory)
		}
		if shard.Section(9) != nil {
			shard.set(9, Vector(12, segmentRows...))
		}
		if shard.Section(10) != nil {
			shard.set(10, Vector(32, cellRows...))
		}
		if shard.Section(12) != nil {
			shard.set(12, Vector(16, pageRows...))
		}
		object, err := add(shard, input.Partition)
		if err != nil {
			return out, err
		}
		out.Destinations[kind] = object
	}
	if err := validateAnycastFacts(out); err != nil {
		return CompiledPartition{}, err
	}
	return out, nil
}

// Public input is already fused. Reject inconsistent anycast materialization;
// manufacturing a parent value from a point lookup could import a descendant.
func validateAnycastFacts(partition CompiledPartition) error {
	usage, ok := partition.Destinations[5]
	if !ok {
		return nil
	}
	boundaries := make(map[string]netip.Prefix)
	for _, kind := range []uint16{2, 3, 5} {
		object, ok := partition.Destinations[kind]
		if !ok {
			continue
		}
		for _, id := range []uint16{1, 8} {
			rows, _ := object.Shard.Rows(id)
			for p := 0; p < len(rows); p += 32 {
				row := rows[p : p+32]
				addr, _ := keyAddr(row)
				prefix := netip.PrefixFrom(addr, int(row[1]))
				boundaries[prefix.String()] = prefix
			}
		}
	}
	for _, scope := range boundaries {
		use, _, known := usage.Shard.findPrefixWithin(scope.Addr(), scope.Bits())
		if !known || !present(use, 7) || use[6]&1 == 0 {
			continue
		}
		if geo, ok := partition.Destinations[2]; ok {
			row, _, known := geo.Shard.findPrefixWithin(scope.Addr(), scope.Bits())
			if known && present(row, 3) {
				return fail("record")
			}
		}
		if coords, ok := partition.Destinations[3]; ok {
			row, _, known := coords.Shard.findPrefixWithin(scope.Addr(), scope.Bits())
			if known && present(row, 4) {
				return fail("record")
			}
		}
	}
	return nil
}

// Build creates an immutable release from bounded typed partitions. It does not
// fetch/admit sources. Production requires the caller's independent eligibility
// gate both before compilation and immediately before the manifest is emitted.
func Build(ctx context.Context, input CompileInput) (BuiltRelease, error) {
	if input.Mode != "synthetic" && input.Mode != "production" || input.Clock < 0 || input.ValidUntil <= input.Clock || input.ValidUntil-input.Clock > 720*3600 || input.ValidUntil > 9007199254740991 {
		return BuiltRelease{}, fail("manifest")
	}
	if input.Mode == "production" {
		if input.ProductionGate == nil {
			return BuiltRelease{}, fail("production_blocked")
		}
		if err := input.ProductionGate(ctx); err != nil {
			return BuiltRelease{}, err
		}
	}
	var objects []BuiltObject
	var compiled []CompiledPartition
	for _, partition := range input.Partitions {
		c, err := CompilePartition(ctx, partition)
		if err != nil {
			return BuiltRelease{}, err
		}
		for kind := range c.Destinations {
			if (kind == 8 || kind >= 11) && len(partition.ASNRoutes) == 0 || (kind != 8 && kind < 11) && len(partition.PrefixRoutes) == 0 {
				return BuiltRelease{}, fail("record")
			}
		}
		compiled = append(compiled, c)
		objects = append(objects, c.Objects...)
	}
	var references []BuiltObject
	for _, c := range compiled {
		for _, object := range c.Destinations {
			references = append(references, object)
		}
	}
	uniqueRefs := make(map[string]BuiltObject)
	for _, object := range references {
		uniqueRefs[object.Info.SHA256] = object
	}
	references = references[:0]
	for _, object := range uniqueRefs {
		references = append(references, object)
	}
	directory, objectID := makeObjectDir(references...)
	router := newShard(1)
	router.set(7, directory)
	var rows, integers, prefixes, asns [][]byte
	for i, partition := range input.Partitions {
		c := compiled[i]
		route := func(asn bool) uint32 {
			var kinds []int
			for kind := range c.Destinations {
				isASN := kind == 8 || kind >= 11
				if isASN == asn {
					kinds = append(kinds, int(kind))
				}
			}
			sort.Ints(kinds)
			row := make([]byte, 16)
			p32(row, 0, uint32(len(integers)))
			p16(row, 4, uint16(len(kinds)))
			for _, kind := range kinds {
				v := make([]byte, 4)
				p32(v, 0, objectID(c.Destinations[uint16(kind)]))
				integers = append(integers, v)
			}
			ordinal := uint32(len(rows))
			rows = append(rows, row)
			return ordinal
		}
		if len(partition.PrefixRoutes) > 0 {
			ordinal := route(false)
			for _, prefix := range partition.PrefixRoutes {
				if !prefix.IsValid() {
					return BuiltRelease{}, fail("record")
				}
				prefixes = append(prefixes, PrefixKey(prefix, false, ordinal))
			}
		}
		if len(partition.ASNRoutes) > 0 {
			ordinal := route(true)
			for _, asn := range partition.ASNRoutes {
				if !facts.PublicASN(asn) {
					return BuiltRelease{}, fail("record")
				}
				row := make([]byte, 8)
				p32(row, 0, asn)
				p32(row, 4, ordinal)
				asns = append(asns, row)
			}
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return keyCompare(prefixes[i], prefixes[j]) < 0 })
	sort.Slice(asns, func(i, j int) bool { return u32(asns[i], 0) < u32(asns[j], 0) })
	// Rebuild record/vector ordinals from canonical first-referring keys. Sorting
	// only the indexes would leave partition input order embedded in row offsets.
	newRows, newIntegers := make([][]byte, 0, len(rows)), make([][]byte, 0, len(integers))
	ordinals := make(map[uint32]uint32, len(rows))
	remap := func(old uint32) uint32 {
		if value, ok := ordinals[old]; ok {
			return value
		}
		row := append([]byte(nil), rows[old]...)
		first, count := u32(row, 0), uint32(u16(row, 4))
		p32(row, 0, uint32(len(newIntegers)))
		newIntegers = append(newIntegers, integers[first:first+count]...)
		value := uint32(len(newRows))
		newRows = append(newRows, row)
		ordinals[old] = value
		return value
	}
	for _, key := range prefixes {
		p32(key, 20, remap(u32(key, 20)))
	}
	for _, key := range asns {
		p32(key, 4, remap(u32(key, 4)))
	}
	rows, integers = newRows, newIntegers
	router.set(1, Vector(32, prefixes...))
	router.set(2, Vector(8, asns...))
	router.set(3, Vector(16, rows...))
	router.set(4, Vector(4, integers...))
	bytes, err := Write(ctx, router)
	if err != nil {
		return BuiltRelease{}, err
	}
	if err := ValidatePublicProfile(router); err != nil {
		return BuiltRelease{}, err
	}
	objects = append(objects, BuiltObject{Info: ObjectInfo{Bytes: len(bytes), Kind: 1, Partition: "all", SHA256: Hash(bytes)}, Bytes: bytes, Shard: router})
	byHash := make(map[string]BuiltObject)
	for _, object := range objects {
		if previous, ok := byHash[object.Info.SHA256]; ok && previous.Info.Partition != object.Info.Partition {
			return BuiltRelease{}, fail("ambiguous_partition")
		}
		byHash[object.Info.SHA256] = object
	}
	objects = objects[:0]
	for _, object := range byHash {
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Info.SHA256 < objects[j].Info.SHA256 })
	if len(objects) >= 18500 {
		return BuiltRelease{}, fail("partition_budget")
	}
	infos := make([]ObjectInfo, len(objects))
	for i, object := range objects {
		infos[i] = object.Info
	}
	descriptor := Descriptor{Codec: "zstd-1", FormatVersion: 3, Mode: input.Mode, Objects: infos, SchemaVersion: 3, ValidFrom: input.Clock, ValidUntil: input.ValidUntil}
	id := Hash(canonical(descriptor))
	manifest := Manifest{Codec: descriptor.Codec, FormatVersion: 3, Mode: descriptor.Mode, Objects: infos, ReleaseID: id, SchemaVersion: 3, ValidFrom: input.Clock, ValidUntil: input.ValidUntil}
	pointer := Pointer{FormatVersion: 3, ManifestPath: "/_atlas/releases/" + id + "/manifest.json", ManifestSHA256: Hash(canonical(manifest)), ReleaseID: id}
	if input.Mode == "production" {
		if err := input.ProductionGate(ctx); err != nil {
			return BuiltRelease{}, err
		}
	}
	return BuiltRelease{Descriptor: descriptor, Manifest: manifest, Pointer: pointer, Objects: objects}, nil
}
