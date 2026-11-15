package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"vansail-ip-atlas/internal/intelligence"
)

const dbipPublisherPage = "https://db-ip.com/db/download/ip-to-city-lite"
const ipapiCSVSchema = "ipapi-free-fourteen-columns-v1"
const ipapiNoticeName = "LICENSE-free-geolocation-database.txt"
const approvedIPAPINoticeSHA256 = "e55343cf9a98006af5266c3814f5175fb26c0570ca016fba5442b2d17308daa6"

func dbipProvider(source Source) bool {
	return source.Parser.ID == "city-range-csv" && source.Parser.Schema == "dbip-city-eight-columns-v1" && source.Format == "csv-gz" && source.URL == "" && source.Publication.Kind == "snapshot_metadata" && source.Publication.Locator == dbipPublisherPage && source.Publication.Field == "csv.sha1-md5.month"
}
func ipapiCSVMember(source Source) (string, bool) {
	if source.Parser.ID != "ipapi-free-city-csv" || source.Parser.Schema != ipapiCSVSchema || source.Format != "zip" || source.Publication.Kind != "embedded" || source.Publication.Field != "zip.csv.extended_timestamp" || source.Publication.Locator != source.URL {
		return "", false
	}
	switch source.URL {
	case "https://ipapi.is/data/geolocationDatabaseIPv4.csv.zip":
		return "geolocationDatabaseIPv4.csv", true
	case "https://ipapi.is/data/geolocationDatabaseIPv6.csv.zip":
		return "geolocationDatabaseIPv6.csv", true
	}
	return "", false
}
func selectGeoProvider(source Source) bool {
	_, ok := ipapiCSVMember(source)
	return ok && source.Category == "geolocation" && source.Scope == "prefix" && source.Coverage == "mapping" && fieldsEqual(source.PublicFields, "physical_country", "region", "city", "latitude", "longitude") && mappedFields(source, map[string]string{"country_code": "physical_country", "region": "region", "city": "city", "latitude": "latitude", "longitude": "longitude"})
}
func decodedGeoClockKey(digest [32]byte) [32]byte {
	data := append([]byte("atlas-decoded-geo-v1\x00"), digest[:]...)
	return sha256.Sum256(data)
}

// A decoded schema fixture is observed source data, never ZIP freshness proof.
// Actual intake still verifies the full CRC, hashes, notice and UTC member clock.
func parseGeoProviderFixture(ctx context.Context, input io.Reader, source Source, maximum int, emit func(intelligence.NormalizedRecord) error) error {
	if source.Parser.ID == "ipapi-free-city-csv" {
		return parseIPAPIFreeCSV(ctx, input, source, maximum, emit)
	}
	if dbipProvider(source) {
		source.Format = "csv"
		return parseBulkPayload(ctx, input, source, time.Time{}, maximum, emit)
	}
	return errors.New("unsupported decoded provider fixture")
}

func validateStoredGeoSource(source Source, stored intelligence.StoredSource, now time.Time) error {
	isDBIP := dbipProvider(source)
	member, isIPAPI := ipapiCSVMember(source)
	if !isDBIP && !isIPAPI {
		return nil
	}
	if stored.Receipt == nil || stored.Receipt.GeoProof == nil {
		return errors.New("publisher-bound geolocation proof required")
	}
	proof := stored.Receipt.GeoProof
	if proof.Version != 1 || proof.DecodedSHA256 == ([32]byte{}) || proof.DecodedBytes <= 0 || proof.DecodedBytes > 3<<30 || proof.UpstreamClock.IsZero() || proof.UpstreamClock.After(now.Add(24*time.Hour)) || stored.Receipt.PublishedAt.After(proof.UpstreamClock) || !now.Before(stored.Receipt.PublishedAt.Add(source.MaxAge)) {
		return errors.New("geolocation proof clock or payload invalid")
	}
	if isIPAPI {
		if proof.AssetURL != source.URL || proof.CSVMember != member || hashString(proof.LicenseSHA256) != approvedIPAPINoticeSHA256 {
			return errors.New("IPAPI archive proof does not match source")
		}
	}
	if isDBIP {
		if proof.PageSHA256 == ([32]byte{}) || proof.CSVMember != "" || !validDBIPAsset(proof.AssetURL, proof.UpstreamClock) {
			return errors.New("DB-IP monthly proof does not match source")
		}
	}
	return nil
}
