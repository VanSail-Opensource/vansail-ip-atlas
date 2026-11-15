package admission

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"vansail-ip-atlas/internal/intelligence"
)

const ipapiHeader = "ip_version,start_ip,end_ip,continent,country_code,country,state,city,zip,timezone,latitude,longitude,accuracy,source"

type geoCSVStats struct{ Rows, AcceptedRows, EmittedRecords, UnknownCountry, CitySuppressed, CountryOnly uint64 }

func parseIPAPIFreeCSV(ctx context.Context, input io.Reader, source Source, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	_, err := parseIPAPIFreeCSVStats(ctx, input, source, maximum, emit)
	return err
}
func parseIPAPIFreeCSVStats(ctx context.Context, input io.Reader, source Source, maximum int, emit func(intelligence.NormalizedRecord) error) (geoCSVStats, error) {
	var stats geoCSVStats
	member, ok := ipapiCSVMember(source)
	if !ok || !selectGeoProvider(source) || maximum <= 0 || maximum > 100_000_000 || emit == nil {
		return stats, errors.New("bounded IPAPI free geolocation contract required")
	}
	version := "4"
	if strings.Contains(member, "IPv6") {
		version = "6"
	}
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: (3 << 30) + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	if !scanner.Scan() || scanner.Text() != ipapiHeader {
		return stats, errors.New("IPAPI free CSV header mismatch")
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		stats.Rows++
		if stats.Rows > uint64(maximum) {
			return stats, errors.New("IPAPI row budget exceeded")
		}
		line := scanner.Text()
		if !utf8.ValidString(line) {
			return stats, errors.New("IPAPI CSV UTF-8 invalid")
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.FieldsPerRecord = 14
		values, err := reader.Read()
		if err != nil {
			return stats, errors.New("IPAPI CSV row invalid")
		}
		if _, err = reader.Read(); err != io.EOF {
			return stats, errors.New("IPAPI CSV physical row invalid")
		}
		if values[0] != version {
			return stats, errors.New("IPAPI IP version mismatch")
		}
		start, e1 := netip.ParseAddr(values[1])
		end, e2 := netip.ParseAddr(values[2])
		if e1 != nil || e2 != nil || start.Zone() != "" || end.Zone() != "" || start.BitLen() != end.BitLen() || start.Compare(end) > 0 || version == "4" && !start.Is4() || version == "6" && !start.Is6() {
			return stats, errors.New("IPAPI range invalid")
		}
		start, end = start.Unmap(), end.Unmap()
		if start.BitLen() != end.BitLen() {
			return stats, errors.New("IPAPI mapped address family mismatch")
		}
		country := values[4]
		if country == "" || country == "ZZ" {
			stats.UnknownCountry++
			continue
		}
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
			return stats, errors.New("IPAPI country code invalid")
		}
		accuracy, err := strconv.Atoi(values[12])
		if err != nil || accuracy < 1 || accuracy > 5 {
			return stats, errors.New("IPAPI accuracy code invalid")
		}
		region, city := values[6], values[7]
		if !safePlace(region) || !safePlace(city) {
			return stats, errors.New("IPAPI location label invalid")
		}
		var coordinates *intelligence.Coordinates
		// Publisher accuracy 3 is not reliable at city level; 4/5 are country-only.
		// Accuracy is never an anycast classifier or a public extra fact.
		if accuracy >= 3 {
			city = ""
			stats.CitySuppressed++
		}
		if accuracy >= 4 {
			region = ""
			stats.CountryOnly++
		}
		if accuracy <= 2 && city != "" && (values[10] != "" || values[11] != "") {
			lat, a := strconv.ParseFloat(values[10], 64)
			lon, b := strconv.ParseFloat(values[11], 64)
			if a != nil || b != nil || math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) || math.Abs(lat) > 90 || math.Abs(lon) > 180 {
				return stats, errors.New("IPAPI coordinates invalid")
			}
			coordinates = &intelligence.Coordinates{Latitude: lat, Longitude: lon, Precision: 3}
		}
		stats.AcceptedRows++
		if err = rangePrefixes(start, end, func(prefix netip.Prefix) error {
			stats.EmittedRecords++
			if stats.EmittedRecords > uint64(maximum) {
				return errors.New("IPAPI normalized record budget exceeded")
			}
			return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: source.Family, Weight: source.Weight, Prefix: prefix, PhysicalCountry: country, Region: region, City: city, Coordinates: coordinates, Current: true}})
		}); err != nil {
			return stats, err
		}
	}
	if err := scanner.Err(); err != nil {
		return stats, err
	}
	if limited.N <= 0 {
		return stats, errors.New("IPAPI decoded byte budget exceeded")
	}
	if stats.EmittedRecords == 0 {
		return stats, errors.New("IPAPI CSV contains no accepted geography")
	}
	return stats, ctx.Err()
}
