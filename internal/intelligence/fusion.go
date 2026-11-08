package intelligence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"vansail-ip-atlas/internal/facts"
)

type Coordinates struct {
	Latitude, Longitude float64
	Precision           uint8
}
type GeoEvidence struct {
	Family                                             string
	Weight                                             float64
	Prefix                                             netip.Prefix
	PhysicalCountry, RegistrationCountry, Region, City string
	Coordinates                                        *Coordinates
	Current                                            bool
}
type GeoResult struct {
	PhysicalCountry, RegistrationCountry, Region, City *string
	Coordinates                                        *Coordinates
}
type GeoIndex struct {
	records map[netip.Prefix][]GeoEvidence
	policy  Policy
}

func NewGeoIndex(policy Policy, records []GeoEvidence) (*GeoIndex, error) {
	index := &GeoIndex{records: map[netip.Prefix][]GeoEvidence{}, policy: policy}
	for _, v := range records {
		if !v.Current {
			continue
		}
		prefix, err := canonicalPrefix(v.Prefix)
		if err != nil {
			return nil, errors.New("geo prefix required")
		}
		if v.Coordinates != nil {
			copy := *v.Coordinates
			v.Coordinates = &copy
		}
		key := prefix
		v.Prefix = prefix
		index.records[key] = append(index.records[key], v)
	}
	return index, nil
}
func (g *GeoIndex) Lookup(addr netip.Addr, anycast bool) (GeoResult, error) {
	if addr.Zone() != "" {
		return GeoResult{}, errors.New("zoned geo query rejected")
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" {
		return GeoResult{}, errors.New("invalid geo query")
	}
	records := []GeoEvidence{}
	for bits := addr.BitLen(); bits >= 0; bits-- {
		records = append(records, g.records[netip.PrefixFrom(addr, bits).Masked()]...)
	}
	return FuseGeo(g.policy, records, anycast)
}

// FuseGeo consumes one bounded partition's applicable mapping observations. An
// index performs LPM first; source names and family IDs never enter GeoResult.
func FuseGeo(policy Policy, records []GeoEvidence, anycast bool) (GeoResult, error) {
	byFamily := map[string][]GeoEvidence{}
	for _, v := range records {
		if !v.Current {
			continue
		}
		if v.Family == "" || !finite(v.Weight) || v.Weight < 0 || v.Weight > 100 {
			return GeoResult{}, errors.New("invalid geo vote")
		}
		if v.Weight == 0 {
			continue
		}
		v.PhysicalCountry = country(v.PhysicalCountry)
		v.RegistrationCountry = country(v.RegistrationCountry)
		v.Region = SafeLabel(v.Region)
		v.City = SafeLabel(v.City)
		if v.Prefix.IsValid() {
			prefix, err := canonicalPrefix(v.Prefix)
			if err != nil {
				return GeoResult{}, err
			}
			v.Prefix = prefix
		}
		byFamily[v.Family] = append(byFamily[v.Family], v)
	}
	selectVotes := func(field func(GeoEvidence) string, eligible func(GeoEvidence) bool) []geoVote {
		votes := []geoVote{}
		families := make([]string, 0, len(byFamily))
		for family := range byFamily {
			families = append(families, family)
		}
		sort.Strings(families)
		for _, family := range families {
			best := -1.0
			longest := -2
			values := map[string]struct{}{}
			for _, v := range byFamily[family] {
				value := field(v)
				if !eligible(v) || value == "" {
					continue
				}
				prefixBits := v.Prefix.Bits()
				if prefixBits < longest {
					continue
				}
				if prefixBits > longest {
					longest = prefixBits
					best = -1
					values = map[string]struct{}{}
				}
				if v.Weight > best {
					best = v.Weight
					values = map[string]struct{}{value: {}}
				} else if v.Weight == best {
					values[value] = struct{}{}
				}
			}
			if len(values) == 1 {
				for value := range values {
					votes = append(votes, geoVote{family, value, best})
				}
			}
		}
		return votes
	}
	all := func(GeoEvidence) bool { return true }
	result := GeoResult{}
	physical, _ := winningPlace(selectVotes(func(v GeoEvidence) string { return v.PhysicalCountry }, all), 1, 0)
	registration, _ := winningPlace(selectVotes(func(v GeoEvidence) string { return v.RegistrationCountry }, all), 1, 0)
	if physical != "" {
		result.PhysicalCountry = &physical
	}
	if registration != "" {
		result.RegistrationCountry = &registration
	}
	if physical == "" {
		return result, nil
	}
	region, _ := winningPlace(selectVotes(func(v GeoEvidence) string { return v.Region }, func(v GeoEvidence) bool { return v.PhysicalCountry == physical }), policy.GeoSupport[0], policy.GeoMargin)
	if region == "" {
		return result, nil
	}
	result.Region = &region
	if anycast {
		return result, nil
	}
	city, agreeing := winningPlace(selectVotes(func(v GeoEvidence) string { return v.City }, func(v GeoEvidence) bool { return v.PhysicalCountry == physical && v.Region == region }), policy.GeoSupport[1], policy.GeoMargin)
	if city == "" {
		return result, nil
	}
	result.City = &city
	type candidate struct {
		weight  float64
		value   Coordinates
		encoded [9]byte
	}
	candidates := []candidate{}
	for family := range agreeing {
		for _, v := range byFamily[family] {
			if v.PhysicalCountry != physical || v.Region != region || v.City != city || v.Coordinates == nil {
				continue
			}
			c := *v.Coordinates
			if !finite(c.Latitude) || !finite(c.Longitude) || c.Latitude < -90 || c.Latitude > 90 || c.Longitude < -180 || c.Longitude > 180 || c.Precision < 1 || c.Precision > 4 {
				continue
			}
			c.Latitude = math.Round(c.Latitude*1000) / 1000
			c.Longitude = math.Round(c.Longitude*1000) / 1000
			encoded := [9]byte{}
			binary.LittleEndian.PutUint32(encoded[0:4], uint32(int32(math.Round(c.Latitude*1000))))
			binary.LittleEndian.PutUint32(encoded[4:8], uint32(int32(math.Round(c.Longitude*1000))))
			encoded[8] = c.Precision
			candidates = append(candidates, candidate{v.Weight, c, encoded})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.weight != b.weight {
			return a.weight > b.weight
		}
		if a.value.Precision != b.value.Precision {
			return a.value.Precision > b.value.Precision
		}
		return bytes.Compare(a.encoded[:], b.encoded[:]) < 0
	})
	if len(candidates) > 0 {
		result.Coordinates = &candidates[0].value
	}
	return result, nil
}

type geoVote struct {
	family, value string
	weight        float64
}

func winningPlace(votes []geoVote, support int, margin float64) (string, map[string]struct{}) {
	total := 0.0
	weights := map[string]float64{}
	families := map[string]map[string]struct{}{}
	for _, v := range votes {
		total += v.weight
		weights[v.value] += v.weight
		addFamily(families, v.value, v.family)
	}
	places := make([]string, 0, len(weights))
	for place := range weights {
		places = append(places, place)
	}
	sort.Slice(places, func(i, j int) bool {
		if weights[places[i]] != weights[places[j]] {
			return weights[places[i]] > weights[places[j]]
		}
		return places[i] < places[j]
	})
	if len(places) == 0 {
		return "", nil
	}
	winner := places[0]
	second := 0.0
	if len(places) > 1 {
		second = weights[places[1]]
	}
	if weights[winner] == second || len(families[winner]) < support || (weights[winner]-second)/total < margin {
		return "", nil
	}
	return winner, families[winner]
}
func country(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !facts.CountryValid(value) {
		return ""
	}
	return value
}

// SafeLabel is deliberately lossy: labels are descriptive facts, never a place
// to preserve a URL, e-mail address, hostname, credential, or invalid UTF-8.
func SafeLabel(value string) string {
	if !utf8.ValidString(value) || len(value) > 1024 {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ""
		}
	}
	words := strings.Fields(norm.NFC.String(value))
	safe := words[:0]
	for _, word := range words {
		trim := strings.Trim(word, "()[]{}.,;\"'")
		if strings.ContainsAny(trim, "@:/\\") || strings.Contains(trim, "://") {
			continue
		}
		parts := strings.Split(trim, ".")
		domain := len(parts) > 1
		for _, part := range parts {
			if part == "" {
				domain = false
				break
			}
			for _, r := range part {
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
					domain = false
					break
				}
			}
		}
		if domain && len(parts[len(parts)-1]) >= 2 {
			continue
		}
		clean := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, word)
		if clean != "" {
			safe = append(safe, clean)
		}
	}
	result := strings.Join(safe, " ")
	for len(result) > 256 {
		_, size := utf8.DecodeLastRuneInString(result)
		result = result[:len(result)-size]
	}
	return result
}

type UsageEvidence struct {
	Family, Type, Assignment   string
	Anycast, DirectedBroadcast *bool
	Current                    bool
}
type UsageResult struct {
	Type, Assignment           string
	Anycast, DirectedBroadcast *bool
}

func FuseUsage(records []UsageEvidence) UsageResult {
	types, assignments := map[string]struct{}{}, map[string]struct{}{}
	anycasts, broadcasts := map[bool]struct{}{}, map[bool]struct{}{}
	for _, v := range records {
		if !v.Current || v.Family == "" {
			continue
		}
		switch v.Type {
		case "residential", "business", "mobile", "datacenter", "hosting", "education", "government":
			types[v.Type] = struct{}{}
		}
		switch v.Assignment {
		case "native", "broadcast_or_routed":
			assignments[v.Assignment] = struct{}{}
		}
		if v.Anycast != nil {
			anycasts[*v.Anycast] = struct{}{}
		}
		if v.DirectedBroadcast != nil {
			broadcasts[*v.DirectedBroadcast] = struct{}{}
		}
	}
	result := UsageResult{Type: "unknown", Assignment: "unknown"}
	if len(types) == 1 {
		for value := range types {
			result.Type = value
		}
	}
	if len(assignments) == 1 {
		for value := range assignments {
			result.Assignment = value
		}
	}
	if len(anycasts) == 1 {
		for value := range anycasts {
			copy := value
			result.Anycast = &copy
		}
	}
	if len(broadcasts) == 1 {
		for value := range broadcasts {
			copy := value
			result.DirectedBroadcast = &copy
		}
	}
	return result
}

type Cell struct {
	Address netip.Addr
	Reasons uint32
	Quality QualityResult
	Origins []uint32
}
type Profile24 struct {
	Prefix                       netip.Prefix
	Cells                        []Cell
	PositiveCount, AssessedCount uint16
	AggregateScore               *uint8
	DominantASN                  *uint32
}

func (e *Engine) Profile24(addr netip.Addr) (Profile24, error) {
	if addr.Zone() != "" {
		return Profile24{}, errors.New("zoned profile query rejected")
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return Profile24{}, errors.New("class C is IPv4 only")
	}
	prefix := netip.PrefixFrom(addr, 24).Masked()
	out := Profile24{Prefix: prefix}
	counts := map[uint32]int{}
	sum := 0
	ambiguous := false
	// Only observed exact addresses become cells. There is no 256-host imputation.
	for host := prefix.Addr(); prefix.Contains(host); host = host.Next() {
		fact, ok := e.exact[host]
		if !ok {
			continue
		}
		quality, err := e.Lookup(host)
		if err != nil {
			return out, err
		}
		origins := e.Origins(host)
		out.Cells = append(out.Cells, Cell{host, fact.layer.Reasons, quality, origins})
		if fact.layer.Reasons != 0 {
			out.PositiveCount++
		}
		if quality.Score != nil {
			out.AssessedCount++
			sum += int(*quality.Score)
		}
		if len(origins) > 1 {
			ambiguous = true
		}
		if len(origins) == 1 {
			counts[origins[0]]++
		}
	}
	if out.AssessedCount == 256 {
		score := uint8(math.Floor(float64(sum)/256 + .5))
		out.AggregateScore = &score
	}
	best, tie := 0, false
	var winner uint32
	for asn, count := range counts {
		if count > best {
			winner, best, tie = asn, count, false
		} else if count == best {
			tie = true
		}
	}
	if best > 0 && !tie && !ambiguous {
		out.DominantASN = &winner
	}
	return out, nil
}
