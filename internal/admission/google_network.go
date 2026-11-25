package admission

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"
	"time"

	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

const googleNetworkURL = "https://www.gstatic.com/ipranges/goog.json"
const googleNetworkLimit = 1 << 20

var errGoogleNetwork = errors.New("invalid Google-owned network prefix report")

func googleNetworkSource(s Source) bool {
	return s.ID == intelligence.GoogleNetworkSourceID && s.Family == "google-network-owner" && s.URL == googleNetworkURL &&
		s.Category == "network_identity" && s.Format == "json" && s.Scope == "prefix" && s.Coverage == "positive_only" &&
		s.MaxCompressedBytes > 0 && s.MaxCompressedBytes <= googleNetworkLimit && len(s.Signals) == 0 &&
		s.Parser == (Parser{"google-network-organization", "google-owned-ip-ranges-v1", 1}) &&
		s.Publication == (Publication{"embedded", googleNetworkURL, "syncToken"}) &&
		fieldsEqual(s.PublicFields, "network_organization") && fieldsEqual(s.Fields, "syncToken", "creationTime", "ipv4Prefix", "ipv6Prefix") &&
		mappedFields(s, map[string]string{"ipv4Prefix": "network_organization", "ipv6Prefix": "network_organization"})
}

// Google pairs a millisecond Unix token with a local civil publication time.
// Comparing the civil representation of the token handles both Pacific offsets
// and the repeated hour at the end of daylight saving time without guessing.
func googleNetworkClock(token, creation string) (time.Time, error) {
	ms, err := strconv.ParseInt(token, 10, 64)
	if err != nil || len(token) != 13 || strconv.FormatInt(ms, 10) != token {
		return time.Time{}, errGoogleNetwork
	}
	published := time.UnixMilli(ms).UTC()
	pacific, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		return time.Time{}, err
	}
	civil, err := time.Parse("2006-01-02T15:04:05.999999999", creation)
	const millis = "2006-01-02T15:04:05.000"
	if err != nil || len(creation) < len(millis) || len(creation) > len(millis)+6 || creation[19] != '.' || civil.Format(millis) != published.In(pacific).Format(millis) {
		return time.Time{}, errGoogleNetwork
	}
	return published, nil
}

func parseGoogleNetwork(ctx context.Context, reader io.Reader, source Source, clock time.Time, maxRecords int, emit func(intelligence.NormalizedRecord) error) (intelligence.GoogleNetworkProof, error) {
	var proof intelligence.GoogleNetworkProof
	if !googleNetworkSource(source) || clock.IsZero() || maxRecords <= 0 {
		return proof, errGoogleNetwork
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, reader}, source.MaxCompressedBytes+1))
	if err != nil {
		return proof, err
	}
	if int64(len(data)) > source.MaxCompressedBytes {
		return proof, errGoogleNetwork
	}
	var report map[string]json.RawMessage
	var token, creation string
	var entries []map[string]string
	if strictJSON(data, &report) != nil || len(report) != 3 || json.Unmarshal(report["syncToken"], &token) != nil || json.Unmarshal(report["creationTime"], &creation) != nil || json.Unmarshal(report["prefixes"], &entries) != nil || len(entries) == 0 || len(entries) > min(maxRecords, intelligence.GoogleNetworkMaxPrefixes) {
		return proof, errGoogleNetwork
	}
	published, err := googleNetworkClock(token, creation)
	if err != nil || published.After(clock) {
		return proof, errGoogleNetwork
	}
	proof.PublishedAt, proof.PayloadHash = published, sha256.Sum256(data)
	var digest intelligence.GoogleNetworkDigest
	seen := make(map[netip.Prefix]bool, len(entries))
	for _, row := range entries {
		if err := ctx.Err(); err != nil {
			return proof, err
		}
		literal, ipv4 := row["ipv4Prefix"]
		if !ipv4 {
			literal = row["ipv6Prefix"]
		}
		prefix, err := netip.ParsePrefix(literal)
		if len(row) != 1 || err != nil || prefix.String() != literal || !subscription.PublicPrefix(prefix) || prefix.Addr().Is4() != ipv4 || seen[prefix] {
			return proof, errGoogleNetwork
		}
		seen[prefix] = true
		if ipv4 {
			proof.IPv4++
		} else {
			proof.IPv6++
		}
		record := intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordNetworkOrganization, NetworkOrganization: &intelligence.NetworkOrganizationRecord{Prefix: prefix, Organization: "Google"}}
		if err := digest.Add(record); err != nil {
			return proof, err
		}
		if emit != nil {
			if err := emit(record); err != nil {
				return proof, err
			}
		}
	}
	proof.Prefixes, proof.Projection = digest.Sum()
	return proof, proof.Validate(clock, published, proof.PayloadHash)
}

func verifyGoogleNetwork(ctx context.Context, path string, source Source, hash [32]byte, now time.Time) (*intelligence.GoogleNetworkProof, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	proof, err := parseGoogleNetwork(ctx, file, source, now, intelligence.GoogleNetworkMaxPrefixes, nil)
	if err != nil {
		return nil, err
	}
	if proof.PayloadHash != hash {
		return nil, errGoogleNetwork
	}
	return &proof, nil
}
