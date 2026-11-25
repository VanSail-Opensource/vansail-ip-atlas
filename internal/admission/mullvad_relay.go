package admission

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const mullvadList = "https://api.mullvad.net/app/v1/relays"
const mullvadTimestamp = "https://api.mullvad.net/trl/v1/timestamps/latest"
const mullvadData = "https://api.mullvad.net/trl/v1/data/"
const mullvadLimit = 4 << 20

var errMullvad = errors.New("invalid operator relay location snapshot")
var mullvadLocationCode = regexp.MustCompile(`^[a-z]{2}-[a-z0-9]{2,8}$`)

func mullvadSource(s Source) bool {
	return s.ID == intelligence.MullvadRelaySourceID && s.Family == "mullvad-relay-locations" && s.Category == "geolocation" && s.Scope == "exact_ip" && s.Coverage == "mapping" &&
		s.Parser == (Parser{intelligence.MullvadRelaySourceID, "mullvad-transparent-relay-json-v1", 1}) && s.Format == "json" && s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= mullvadLimit &&
		s.URL == mullvadList && s.Publication == (Publication{"snapshot_metadata", mullvadTimestamp, "sigsum.timestamp.digest"}) && s.MaxAge > 0 && s.MaxAge <= 720*time.Hour &&
		len(s.Signals) == 0 && fieldsEqual(s.Fields, "location", "city", "latitude", "longitude", "active", "include_in_country", "ipv4_addr_in", "ipv6_addr_in") &&
		fieldsEqual(s.PublicFields, "physical_country", "region", "city", "latitude", "longitude") && len(s.FieldMappings) == 4 && fieldsEqual(s.FieldMappings["location"], "physical_country") &&
		fieldsEqual(s.FieldMappings["city"], "region", "city") && fieldsEqual(s.FieldMappings["latitude"], "latitude") && fieldsEqual(s.FieldMappings["longitude"], "longitude")
}

// Only provider-supplied US postal subdivisions are expanded. Country alone
// cannot supply an administrative region, even for well-known named cities.
var usRelayStates = map[string]string{
	"AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "DC": "District of Columbia",
	"FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
	"ME": "Maine", "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
	"NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma", "OR": "Oregon",
	"PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia",
	"WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
}

type mullvadPlace struct {
	country, region, city string
	coords                intelligence.Coordinates
}
type mullvadLocations map[string]mullvadPlace

func (m *mullvadLocations) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if first, err := dec.ReadToken(); err != nil || first.Kind() != '{' {
		return errMullvad
	}
	*m = make(mullvadLocations)
	for dec.PeekKind() != '}' {
		if len(*m) >= 1024 {
			return errMullvad
		}
		key, err := dec.ReadToken()
		if err != nil || key.Kind() != '"' || !mullvadLocationCode.MatchString(key.String()) {
			return errMullvad
		}
		code := key.String()
		country := strings.ToUpper(code[:2])
		var v struct {
			City      string   `json:"city"`
			Latitude  *float64 `json:"latitude"`
			Longitude *float64 `json:"longitude"`
		}
		if err := jsonv2.UnmarshalDecode(dec, &v); err != nil {
			return errMullvad
		}
		if !facts.CountryValid(country) || !safePlace(v.City) || v.City == "" || len(v.City) > 128 || strings.TrimSpace(v.City) != v.City {
			return errMullvad
		}
		if v.Latitude == nil || v.Longitude == nil || math.Abs(*v.Latitude) > 90 || math.Abs(*v.Longitude) > 180 {
			return errMullvad
		}
		p := mullvadPlace{country: country, city: v.City, coords: intelligence.Coordinates{Latitude: *v.Latitude, Longitude: *v.Longitude, Precision: 3}}
		if country == "US" {
			if city, abbreviation, ok := strings.Cut(v.City, ", "); ok {
				state, known := usRelayStates[abbreviation]
				if !known || city == "" {
					return errMullvad
				}
				p.city, p.region = city, state
			}
		}
		(*m)[code] = p
	}
	_, err := dec.ReadToken()
	return err
}

type mullvadRelay struct {
	Location string `json:"location"`
	Active   *bool  `json:"active"`
	Included *bool  `json:"include_in_country"`
	IPv4     string `json:"ipv4_addr_in"`
	IPv6     string `json:"ipv6_addr_in"`
}
type mullvadRelays []mullvadRelay

func (m *mullvadRelays) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if first, err := dec.ReadToken(); err != nil || first.Kind() != '[' {
		return errMullvad
	}
	for dec.PeekKind() != ']' {
		var r mullvadRelay
		if len(*m) >= intelligence.MullvadMaxHosts/2 || jsonv2.UnmarshalDecode(dec, &r) != nil || r.Active == nil || r.Included == nil {
			return errMullvad
		}
		*m = append(*m, r)
	}
	_, err := dec.ReadToken()
	return err
}

func parseMullvadRelays(ctx context.Context, reader io.Reader, s Source, maximum int, emit func(intelligence.NormalizedRecord) error) (intelligence.MullvadRelayDigest, error) {
	var digest intelligence.MullvadRelayDigest
	var doc struct {
		Locations mullvadLocations `json:"locations"`
		Wireguard struct {
			Relays mullvadRelays `json:"relays"`
		} `json:"wireguard"`
	}
	if !mullvadSource(s) || maximum <= 0 {
		return digest, errMullvad
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, reader}, s.MaxCompressedBytes+1))
	if err != nil || int64(len(data)) > s.MaxCompressedBytes || jsonv2.Unmarshal(data, &doc) != nil || len(doc.Locations) == 0 {
		return digest, errMullvad
	}
	hosts := make(map[netip.Addr]mullvadPlace)
	for _, relay := range doc.Wireguard.Relays {
		if !*relay.Active || !*relay.Included {
			continue
		}
		place, ok := doc.Locations[relay.Location]
		if !ok || relay.IPv4 == "" && relay.IPv6 == "" {
			return digest, errMullvad
		}
		for index, raw := range []string{relay.IPv4, relay.IPv6} {
			if raw == "" {
				continue
			}
			addr, err := netip.ParseAddr(raw)
			if err != nil || addr.Is4() != (index == 0) || addr.Zone() != "" || addr.Is4In6() || !subscription.Public(addr) {
				return digest, errMullvad
			}
			if _, exists := hosts[addr]; exists || len(hosts) >= maximum {
				return digest, errMullvad
			}
			hosts[addr] = place
		}
	}
	if len(hosts) == 0 {
		return digest, errMullvad
	}
	for _, addr := range slices.SortedFunc(maps.Keys(hosts), netip.Addr.Compare) {
		if err := ctx.Err(); err != nil {
			return digest, err
		}
		place := hosts[addr]
		r := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordGeo, Geo: &intelligence.GeoEvidence{Family: s.Family, Weight: s.Weight, Prefix: netip.PrefixFrom(addr, addr.BitLen()), PhysicalCountry: place.country, Region: place.region, City: place.city, Coordinates: &place.coords, Current: true}}
		if err := digest.Add(r); err != nil {
			return digest, err
		}
		if emit != nil {
			if err := emit(r); err != nil {
				return digest, err
			}
		}
	}
	return digest, nil
}

func (e *Engine) fetchMullvad(ctx context.Context, path string, s Source, now time.Time) (*intelligence.MullvadRelayProof, time.Time, error) {
	meta := filepath.Join(filepath.Dir(path), "signed-location-timestamp")
	if _, err := e.fetch.Fetch(ctx, mullvadTimestamp, meta, intelligence.MullvadMaxEnvelope); err != nil {
		return nil, time.Time{}, err
	}
	envelope, err := boundedFile(ctx, meta, intelligence.MullvadMaxEnvelope)
	if err != nil {
		return nil, time.Time{}, err
	}
	hash, signed, err := intelligence.VerifyMullvadEnvelope(string(envelope))
	if err != nil || now.Before(signed) || !now.Before(signed.Add(24*time.Hour)) {
		return nil, time.Time{}, errMullvad
	}
	body, err := e.fetch.Fetch(ctx, mullvadData+hashString(hash), path, s.MaxCompressedBytes)
	if err != nil || body.SHA256 != hashString(hash) {
		return nil, time.Time{}, errMullvad
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	content := sha256.New()
	digest, err := parseMullvadRelays(ctx, io.TeeReader(file, content), s, intelligence.MullvadMaxHosts, nil)
	closeErr := file.Close()
	if err != nil || closeErr != nil || [32]byte(content.Sum(nil)) != hash {
		return nil, time.Time{}, errMullvad
	}
	n, projection := digest.Sum()
	p := &intelligence.MullvadRelayProof{Envelope: string(envelope), AcquiredAt: now.UTC(), Hosts: n, Projection: projection}
	return p, signed, nil
}
