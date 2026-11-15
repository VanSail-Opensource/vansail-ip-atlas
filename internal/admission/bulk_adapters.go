package admission

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

// These schemas describe observed file layouts, not reviewed sources. Selecting
// an adapter never establishes rights, freshness, completeness or independence.
func selectBulkAdapter(s Source) bool {
	switch s.Parser.ID {
	case "country-range-csv":
		return s.Parser.Schema == "start-end-country-csv-v1" && s.Category == "geolocation" && s.Scope == "prefix" && s.Coverage == "mapping" && s.Format == "range-csv" && fieldsEqual(s.PublicFields, "physical_country") && mappedFields(s, map[string]string{"country_code": "physical_country"})
	case "city-range-csv":
		return (s.Parser.Schema == "dbip-city-eight-columns-v1" || s.Parser.Schema == "sapics-city-ten-columns-v1") && s.Category == "geolocation" && s.Scope == "prefix" && s.Coverage == "mapping" && (s.Format == "csv" || s.Format == "csv-gz" || s.Format == "range-csv") && fieldsEqual(s.PublicFields, "physical_country", "region", "city", "latitude", "longitude") && mappedFields(s, map[string]string{"country_code": "physical_country", "region": "region", "city": "city", "latitude": "latitude", "longitude": "longitude"})
	case "ip-country-asn-tsv":
		return s.Parser.Schema == "start-end-asn-country-description-tsv-v1" && s.Category == "bgp" && s.Scope == "prefix" && s.Coverage == "mapping" && (s.Format == "tsv" || s.Format == "tsv-gz") && fieldsEqual(s.PublicFields, "origins") && mappedFields(s, map[string]string{"asn": "origins"})
	case "literal-prefix-text":
		if s.Parser.Schema != "one-literal-ip-or-prefix-per-line-v1" || s.Coverage != "positive_only" || s.Scope != "prefix" && s.Scope != "exact_ip" || s.Format != "cidr-text" && s.Format != "txt" || !fieldsEqual(s.PublicFields, "reason_flags") || len(s.Signals) != 1 {
			return false
		}
		switch s.Signals[0] {
		case "malware", "botnet", "c2", "abuse", "fraud", "scanner", "spam", "tor", "vpn", "proxy", "datacenter", "hosting":
			return mappedFields(s, map[string]string{s.Signals[0]: "reason_flags"})
		}
	case "caida-relationships":
		return s.Parser.Schema == "asn-asn-relation-pipe-v1" && s.Category == "bgp" && s.Scope == "asn_edge" && s.Coverage == "mapping" && (s.Format == "text" || s.Format == "text-bz2") && fieldsEqual(s.PublicFields, "as_relationships") && mappedFields(s, map[string]string{"as_relationship": "as_relationships"})
	}
	return false
}

func parseBulkPayload(ctx context.Context, input io.Reader, s Source, published time.Time, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	if !selectBulkAdapter(s) || emit == nil || maximum <= 0 || maximum > 100_000_000 {
		return errors.New("unsupported bounded bulk schema")
	}
	r := &io.LimitedReader{R: contextReader{ctx, input}, N: (3 << 30) + 1}
	rows, records := 0, 0
	sink := func(v intelligence.NormalizedRecord) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		records++
		if records > maximum {
			return errors.New("bulk normalized record budget exceeded")
		}
		return emit(v)
	}
	row := func(values []string) error {
		rows++
		if rows > maximum {
			return errors.New("bulk input row budget exceeded")
		}
		for _, value := range values {
			if len(value) > 1<<20 || !utf8.ValidString(value) {
				return errors.New("bulk UTF-8 field budget exceeded")
			}
		}
		if s.Parser.ID == "literal-prefix-text" {
			return emitLiteral(values[0], s, published, sink)
		}
		if s.Parser.ID == "caida-relationships" {
			return emitRelationship(values, sink)
		}
		var a, b netip.Addr
		if len(values) < 3 {
			return errors.New("bulk range column count")
		}
		a, err := netip.ParseAddr(values[0])
		if err != nil || a.Zone() != "" {
			return errors.New("bulk range start invalid")
		}
		b, err = netip.ParseAddr(values[1])
		if err != nil || b.Zone() != "" {
			return errors.New("bulk range end invalid")
		}
		a, b = a.Unmap(), b.Unmap()
		if a.BitLen() != b.BitLen() || a.Compare(b) > 0 {
			return errors.New("bulk range reversed or mixed family")
		}
		if s.Parser.ID == "ip-country-asn-tsv" {
			if len(values) != 5 {
				return errors.New("ASN range column count")
			}
			n, err := strconv.ParseUint(values[2], 10, 32)
			if err != nil {
				return errors.New("ASN range number invalid")
			}
			if !intelligence.IsPublicASN(uint32(n)) {
				return nil
			}
			// Country and description are intentionally not ASN identity evidence.
			return rangePrefixes(a, b, func(p netip.Prefix) error {
				return sink(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: p, Origins: []uint32{uint32(n)}}})
			})
		}
		country, region, city := values[2], "", ""
		var coordinates *intelligence.Coordinates
		if s.Parser.ID == "country-range-csv" {
			if len(values) != 3 {
				return errors.New("country range column count")
			}
		} else {
			latColumn, lonColumn := 6, 7
			if s.Parser.Schema == "dbip-city-eight-columns-v1" {
				if len(values) != 8 {
					return errors.New("city range column count")
				}
				country, region, city = values[3], values[4], values[5]
			} else {
				if len(values) != 10 {
					return errors.New("city range column count")
				}
				region, city = values[3], values[5]
				latColumn, lonColumn = 7, 8
			}
			if !safePlace(region) || !safePlace(city) {
				return errors.New("city display label invalid")
			}
			if values[latColumn] != "" || values[lonColumn] != "" {
				lat, e1 := strconv.ParseFloat(values[latColumn], 64)
				lon, e2 := strconv.ParseFloat(values[lonColumn], 64)
				if e1 != nil || e2 != nil || math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) || math.Abs(lat) > 90 || math.Abs(lon) > 180 {
					return errors.New("city coordinates invalid")
				}
				// CSV city coordinates are centroids. No street-level accuracy claim.
				coordinates = &intelligence.Coordinates{Latitude: lat, Longitude: lon, Precision: 3}
			}
		}
		if country == "" || country == "ZZ" {
			return nil
		}
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
			return errors.New("country code invalid")
		}
		return rangePrefixes(a, b, func(p netip.Prefix) error {
			return sink(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: s.Family, Weight: s.Weight, Prefix: p, PhysicalCountry: country, Region: region, City: city, Coordinates: coordinates, Current: true}})
		})
	}
	if s.Parser.ID == "literal-prefix-text" || s.Parser.ID == "caida-relationships" {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			values := []string{line}
			if s.Parser.ID == "caida-relationships" {
				values = strings.Split(line, "|")
			}
			if err := row(values); err != nil {
				return err
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	} else {
		// The observed publisher schemas use one record per physical line. Parse
		// each bounded line independently: an unterminated quoted field cannot
		// make encoding/csv accumulate the rest of a decompression bomb.
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		var lineInput bytes.Reader
		lineBuffer := bufio.NewReader(&lineInput)
		reader := csv.NewReader(lineBuffer)
		reader.FieldsPerRecord = -1
		reader.ReuseRecord = true
		if s.Parser.ID == "ip-country-asn-tsv" {
			reader.Comma = '\t'
		}
		for scanner.Scan() {
			lineInput.Reset(scanner.Bytes())
			lineBuffer.Reset(&lineInput)
			values, err := reader.Read()
			if err != nil {
				return errors.New("bulk CSV syntax invalid")
			}
			// ScanLines removes the only possible LF, so this isolated input
			// contains exactly one physical record. An incomplete quoted field
			// meets EOF here rather than reading the next line. encoding/csv
			// owns its returned strings; only the temporary field slice is reused.
			if err = row(values); err != nil {
				return err
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}
	if r.N <= 0 {
		return errors.New("bulk decoded byte budget exceeded")
	}
	if records == 0 {
		return errors.New("bulk source contains no accepted records")
	}
	return ctx.Err()
}

func safePlace(value string) bool {
	if len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

func emitLiteral(line string, s Source, published time.Time, emit func(intelligence.NormalizedRecord) error) error {
	if strings.ContainsAny(line, " \t\r\n") {
		return errors.New("literal list must contain one address or prefix")
	}
	v := intelligence.Evidence{Family: s.Family, Signal: intelligence.Signal(s.Signals[0]), SourcePublishedAt: published, Current: true}
	if strings.Contains(line, "/") {
		p, err := netip.ParsePrefix(line)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() || p != p.Masked() {
			return errors.New("literal prefix invalid")
		}
		if s.Scope != "prefix" {
			return errors.New("unexpected prefix in exact list")
		}
		if !subscription.Public(p.Addr()) || !subscription.Public(lastAddress(p)) {
			return nil
		}
		v.Scope = intelligence.ExplicitPrefix
		v.Prefix = p
	} else {
		a, err := netip.ParseAddr(line)
		if err != nil || a.Zone() != "" {
			return errors.New("literal address invalid")
		}
		a = a.Unmap()
		if !subscription.Public(a) {
			return nil
		}
		v.Scope = intelligence.Exact
		v.Address = a
	}
	return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &v})
}
func emitRelationship(values []string, emit func(intelligence.NormalizedRecord) error) error {
	if len(values) != 3 && len(values) != 4 {
		return errors.New("relationship column count")
	}
	a, e1 := strconv.ParseUint(values[0], 10, 32)
	b, e2 := strconv.ParseUint(values[1], 10, 32)
	if e1 != nil || e2 != nil || !intelligence.IsPublicASN(uint32(a)) || !intelligence.IsPublicASN(uint32(b)) || a == b {
		return errors.New("relationship ASN invalid")
	}
	var relation intelligence.Relation
	switch values[2] {
	case "-1":
		relation = intelligence.Customer
	case "0":
		relation = intelligence.Peer
	default:
		return errors.New("relationship code unsupported")
	}
	return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordRelationship, Relationship: &intelligence.RelationshipRecord{From: uint32(a), To: uint32(b), Relation: relation}})
}
func lastAddress(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	raw := a.As16()
	offset := 0
	if a.Is4() {
		offset = 96
	}
	for bit := offset + p.Bits(); bit < 128; bit++ {
		raw[bit/8] |= 1 << uint(7-bit%8)
	}
	v := netip.AddrFrom16(raw)
	if a.Is4() {
		v = v.Unmap()
	}
	return v
}

// rangePrefixes produces the minimal CIDR cover without enumerating addresses.
func rangePrefixes(start, end netip.Addr, emit func(netip.Prefix) error) error {
	for start.IsValid() && start.Compare(end) <= 0 {
		bits := start.BitLen()
		for bits > 0 {
			candidate := netip.PrefixFrom(start, bits-1)
			if candidate.Masked().Addr() != start || lastAddress(candidate).Compare(end) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(start, bits)
		if err := emit(p); err != nil {
			return err
		}
		last := lastAddress(p)
		if last == end {
			return nil
		}
		start = last.Next()
	}
	return nil
}
