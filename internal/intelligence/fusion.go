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
	// With two complementary country observations, only the physical-country
	// voter can support its region. A two-family region policy therefore
	// resolves both countries independently and stops before place voting.
	countryPair := len(records) == 2 && policy.GeoSupport[0] > 1 &&
		(records[0].PhysicalCountry == "" && records[1].RegistrationCountry == "" ||
			records[1].PhysicalCountry == "" && records[0].RegistrationCountry == "")
	var physicalOnly, registrationOnly string
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
		if v.Prefix.IsValid() {
			prefix, err := canonicalPrefix(v.Prefix)
			if err != nil {
				return GeoResult{}, err
			}
			v.Prefix = prefix
		}
		// One positive observation supplies both country votes independently.
		// A policy requiring two families for a region also excludes city and
		// coordinates, so their labels and coordinate candidates are unused.
		if len(records) == 1 && policy.GeoSupport[0] > 1 {
			return geoCountries(v.PhysicalCountry, v.RegistrationCountry), nil
		}
		if countryPair {
			if v.PhysicalCountry != "" {
				physicalOnly = v.PhysicalCountry
			}
			if v.RegistrationCountry != "" {
				registrationOnly = v.RegistrationCountry
			}
			continue
		}
		v.Region = SafeLabel(v.Region)
		v.City = SafeLabel(v.City)
		byFamily[v.Family] = append(byFamily[v.Family], v)
	}
	if countryPair {
		return geoCountries(physicalOnly, registrationOnly), nil
	}
	if len(byFamily) == 0 {
		return GeoResult{}, nil
	}
	families := make([]string, 0, len(byFamily))
	for family := range byFamily {
		families = append(families, family)
	}
	sort.Strings(families)
	selectVotes := func(field func(GeoEvidence) string, eligible func(GeoEvidence) bool) []geoVote {
		votes := []geoVote{}
		for _, family := range families {
			best := -1.0
			longest := -2
			selected := ""
			conflict := false
			for _, v := range byFamily[family] {
				value := field(v)
				if !eligible(v) || value == "" {
					continue
				}
				prefixBits := v.Prefix.Bits()
				if prefixBits < longest {
					continue
				}
				if prefixBits > longest || v.Weight > best {
					longest, best = prefixBits, v.Weight
					selected, conflict = value, false
				} else if v.Weight == best && value != selected {
					conflict = true
				}
			}
			if selected != "" && !conflict {
				votes = append(votes, geoVote{family, selected, best})
			}
		}
		return votes
	}
	all := func(GeoEvidence) bool { return true }
	physical := winningPlace(selectVotes(func(v GeoEvidence) string { return v.PhysicalCountry }, all), 1, 0)
	registration := winningPlace(selectVotes(func(v GeoEvidence) string { return v.RegistrationCountry }, all), 1, 0)
	result := geoCountries(physical, registration)
	if physical == "" {
		return result, nil
	}
	region := winningPlace(selectVotes(func(v GeoEvidence) string { return v.Region }, func(v GeoEvidence) bool { return v.PhysicalCountry == physical }), policy.GeoSupport[0], policy.GeoMargin)
	if region == "" {
		return result, nil
	}
	result.Region = &region
	if anycast {
		return result, nil
	}
	cityVotes := selectVotes(func(v GeoEvidence) string { return v.City }, func(v GeoEvidence) bool { return v.PhysicalCountry == physical && v.Region == region })
	city := winningPlace(cityVotes, policy.GeoSupport[1], policy.GeoMargin)
	if city == "" {
		return result, nil
	}
	result.City = &city
	type candidate struct {
		weight  float64
		value   Coordinates
		encoded [9]byte
	}
	agreeing := make(map[string]struct{})
	for _, vote := range cityVotes {
		if vote.value == city {
			agreeing[vote.family] = struct{}{}
		}
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

func geoCountries(physical, registration string) GeoResult {
	result := GeoResult{}
	if physical != "" {
		result.PhysicalCountry = &physical
	}
	if registration != "" {
		result.RegistrationCountry = &registration
	}
	return result
}

type geoVote struct {
	family, value string
	weight        float64
}

// selectVotes supplies at most one positive-weight vote per independent family.
func winningPlace(votes []geoVote, support int, margin float64) string {
	if len(votes) == 0 || len(votes) < support {
		return ""
	}
	if len(votes) == 1 {
		if margin > 1 {
			return ""
		}
		return votes[0].value
	}
	type tally struct {
		weight   float64
		families int
	}
	total := 0.0
	places := make(map[string]tally)
	for _, v := range votes {
		total += v.weight
		t := places[v.value]
		t.weight += v.weight
		t.families++
		places[v.value] = t
	}
	winner := ""
	var first, second float64
	for place, t := range places {
		if t.weight > first {
			second = first
			first = t.weight
			winner = place
		} else if t.weight > second {
			second = t.weight
		}
	}
	if first == second || places[winner].families < support || (first-second)/total < margin {
		return ""
	}
	return winner
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
		if facts.UnsafeLabelToken(word) {
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
	Contextual                 bool  `json:",omitempty"`
	ContextPrefixBits          uint8 `json:",omitempty"`
}
type UsageResult struct {
	Type, Assignment           string
	Anycast, DirectedBroadcast *bool
}

func FuseUsage(records []UsageEvidence) UsageResult {
	result := UsageResult{Type: "unknown", Assignment: "unknown"}
	if len(records) == 0 {
		return result
	}
	var usageType, assignment string
	var typeConflict, assignmentConflict bool
	var anycasts, broadcasts uint8
	directType, contextualBits := false, -1
	for _, v := range records {
		if !v.Current || v.Family == "" {
			continue
		}
		if !v.Contextual && v.Type != "" {
			directType = true
		}
		if v.Contextual && int(v.ContextPrefixBits) > contextualBits {
			contextualBits = int(v.ContextPrefixBits)
		}
	}
	for _, v := range records {
		if !v.Current || v.Family == "" {
			continue
		}
		typeValue := v.Type
		if v.Contextual && (directType || int(v.ContextPrefixBits) != contextualBits) {
			typeValue = ""
		}
		switch typeValue {
		case "residential", "business", "mobile", "datacenter", "hosting", "education", "government":
			if usageType != "" && usageType != typeValue {
				typeConflict = true
			}
			usageType = typeValue
		}
		switch v.Assignment {
		case "native", "broadcast_or_routed":
			if assignment != "" && assignment != v.Assignment {
				assignmentConflict = true
			}
			assignment = v.Assignment
		}
		anycasts |= usageBoolVote(v.Anycast)
		broadcasts |= usageBoolVote(v.DirectedBroadcast)
	}
	if !typeConflict && usageType != "" {
		result.Type = usageType
	}
	if !assignmentConflict && assignment != "" {
		result.Assignment = assignment
	}
	if anycasts == 1 || anycasts == 2 {
		value := anycasts == 2
		result.Anycast = &value
	}
	if broadcasts == 1 || broadcasts == 2 {
		value := broadcasts == 2
		result.DirectedBroadcast = &value
	}
	return result
}

func usageBoolVote(value *bool) uint8 {
	if value == nil {
		return 0
	}
	if *value {
		return 2
	}
	return 1
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
	ScoredCount                  uint16
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
	first := sort.Search(len(e.exactAddresses), func(i int) bool { return !e.exactAddresses[i].Less(prefix.Addr()) })
	for _, host := range e.exactAddresses[first:] {
		if !prefix.Contains(host) {
			break
		}
		fact := e.exact[host]
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
			out.ScoredCount++
			sum += int(*quality.Score)
		}
		if quality.CoverageComplete {
			out.AssessedCount++
		}
		if len(origins) > 1 {
			ambiguous = true
		}
		if len(origins) == 1 {
			counts[origins[0]]++
		}
	}
	if out.ScoredCount > 0 {
		score := uint8(math.Floor(float64(sum)/float64(out.ScoredCount) + .5))
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
