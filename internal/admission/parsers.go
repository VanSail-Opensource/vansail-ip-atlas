package admission

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/subscription"
)

type adapter uint8

const (
	vrpCSV adapter = iota + 1
	vrpJSON
	mrtRIB
	subscriptionSyntax
	asnIdentityCSV
)

// Adapter IDs describe implemented schemas, not source certification. None is
// enabled by this registry; reviewed per-source fixture evidence is still needed.
func selectAdapter(source Source) (adapter, bool) {
	if source.Parser.Version != 1 || source.Coverage != "mapping" && source.Coverage != "positive_only" {
		// These parsers cannot establish absence-as-clean assessment coverage.
		return 0, false
	}
	switch source.Parser.ID {
	case "asn-identity-csv":
		return asnIdentityCSV, source.Parser.Schema == "asn-handle-description-country-csv-v1" && source.Category == "asn" && source.Coverage == "mapping" && source.Scope == "asn" && fieldsEqual(source.PublicFields, "asn", "as_name", "organization", "asn_country") && mappedFields(source, map[string]string{"asn": "asn", "handle": "as_name", "description": "organization", "country-code": "asn_country"}) && (source.Format == "csv" || source.Format == "csv-gz")
	case "vrp-csv":
		return vrpCSV, source.Parser.Schema == "asn-prefix-maxLength-csv-v1" && source.Category == "rpki" && source.Coverage == "mapping" && source.Scope == "prefix" && fieldsEqual(source.PublicFields, "rpki_status") && mappedFields(source, map[string]string{"roa": "rpki_status"}) && (source.Format == "csv" || source.Format == "csv-gz")
	case "vrp-json":
		return vrpJSON, source.Parser.Schema == "roas-json-v1" && source.Category == "rpki" && source.Coverage == "mapping" && source.Scope == "prefix" && fieldsEqual(source.PublicFields, "rpki_status") && mappedFields(source, map[string]string{"roa": "rpki_status"}) && (source.Format == "json" || source.Format == "json-gz")
	case "mrt-table-dump-v2":
		return mrtRIB, source.Parser.Schema == "mrt-table-dump-v2-unicast-v1" && source.Category == "bgp" && source.Coverage == "mapping" && source.Scope == "path" && fieldsEqual(source.PublicFields, "bgp_origins", "bgp_paths") && mappedFields(source, map[string]string{"asn": "bgp_origins", "as_path": "bgp_paths"}) && (source.Format == "mrt" || source.Format == "mrt-gz" || source.Format == "mrt-bz2")
	case "subscription-literal":
		return subscriptionSyntax, source.Parser.Schema == "literal-ip-subscription-v1" && source.Category == "proxy_subscription_ip" && source.Family == "public-subscription-aggregators" && source.Scope == "exact_ip" && source.Coverage == "positive_only" && fieldsEqual(source.PublicFields, "reason_flags") && (source.Format == "txt" || source.Format == "base64" || source.Format == "mihomo-yaml" || source.Format == "sing-box-json")
	default:
		return 0, false
	}
}

func mappedFields(source Source, required map[string]string) bool {
	if len(source.FieldMappings) != len(required) {
		return false
	}
	declared := map[string]bool{}
	for _, field := range source.Fields {
		if declared[field] {
			return false
		}
		declared[field] = true
	}
	for input, output := range required {
		if !declared[input] || !fieldsEqual(source.FieldMappings[input], output) {
			return false
		}
	}
	return true
}

func fieldsEqual(values []string, required ...string) bool {
	if len(values) != len(required) {
		return false
	}
	values = append([]string(nil), values...)
	required = append([]string(nil), required...)
	sort.Strings(values)
	sort.Strings(required)
	for i := range values {
		if values[i] != required[i] {
			return false
		}
	}
	return true
}

func parsePayload(ctx context.Context, file *os.File, size int64, source Source, implementation adapter, published time.Time, asnStats ...*intelligence.ASNIdentityStats) ([]intelligence.NormalizedRecord, error) {
	if implementation == subscriptionSyntax {
		return nil, errors.New("per-item publication verifier required")
	}
	format := "plain"
	if strings.HasSuffix(source.Format, "-gz") {
		format = "gzip"
	} else if strings.HasSuffix(source.Format, "-bz2") {
		format = "bzip2"
	}
	limits := acquire.ArchiveLimits{CompressedBytes: source.MaxCompressedBytes, DecodedBytes: 3 << 30, EntryBytes: 3 << 30, Entries: 1, NameBytes: 4096}
	output := make([]intelligence.NormalizedRecord, 0)
	bytes := int64(0)
	emit := func(record intelligence.NormalizedRecord) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if len(output) >= 100000 || record.Validate() != nil {
			return errors.New("normalized source partition budget exceeded")
		}
		encoded, err := json.Marshal(record)
		if err != nil || len(encoded) > 1<<20 {
			return errors.New("normalized source record invalid")
		}
		bytes += int64(len(encoded))
		if bytes > 64<<20 {
			return errors.New("normalized source partition byte budget exceeded")
		}
		output = append(output, record)
		return nil
	}
	parse := func(_ string, reader io.Reader) error {
		limits := intelligence.ParseLimits{Bytes: 3 << 30, Records: 100000, LineBytes: 1 << 20}
		switch implementation {
		case asnIdentityCSV:
			stats, err := intelligence.ParseASNIdentityCSV(ctx, reader, limits, func(value intelligence.ASNIdentityEvidence) error {
				return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordASNIdentity, ASNIdentity: &value})
			})
			if len(asnStats) > 0 && asnStats[0] != nil {
				*asnStats[0] = stats
			}
			return err
		case vrpCSV, vrpJSON:
			sink := func(value intelligence.VRP) error {
				if !value.Prefix.IsValid() || value.Prefix.Addr().Is4In6() || value.Prefix.Addr().Zone() != "" || value.ASN != 0 && !intelligence.IsPublicASN(value.ASN) {
					return errors.New("VRP facts invalid")
				}
				return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordVRP, VRP: &value})
			}
			if implementation == vrpCSV {
				return intelligence.ParseVRPCSV(ctx, reader, limits, sink)
			}
			limits.Bytes = 64 << 20
			return intelligence.ParseVRPJSON(ctx, reader, limits, sink)
		case mrtRIB:
			return intelligence.ParseMRT(ctx, reader, intelligence.MRTLimits{Bytes: 3 << 30, FrameBytes: 8 << 20, Records: 50000, Peers: 65535}, func(value intelligence.MRTRecord) error {
				if !intelligence.IsPublicASN(value.Origin) || !value.Prefix.IsValid() || value.Prefix.Addr().Is4In6() || value.Prefix.Addr().Zone() != "" || value.ObservedAt.After(published.Add(24*time.Hour)) || !published.Before(value.ObservedAt.Add(source.MaxAge)) {
					return errors.New("unrepresentable or expired MRT observation")
				}
				if err := emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordOrigins, Origins: &intelligence.OriginMapping{Prefix: value.Prefix, Origins: []uint32{value.Origin}}}); err != nil {
					return err
				}
				return emit(intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordPath, Path: &intelligence.ScopedPath{Prefix: value.Prefix, Observation: intelligence.PathObservation{Origin: value.Origin, Segments: value.Segments, Family: source.Family, Current: true, OriginOutward: false}}})
			})
		default:
			return errors.New("unsupported source adapter")
		}
	}
	if err := acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: file, ReaderAt: file, Size: size}, format, limits, parse); err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, errors.New("source contains no accepted records")
	}
	return output, nil
}

// LiteralEvidence converts only the decoder's stripped record after a separate
// trusted item-clock verifier has established its publication time. Ingest does
// not call this until such a verifier is implemented. The function rejects zero
// clocks; callers cannot replace them with fetch/metadata time implicitly.
func LiteralEvidence(record subscription.Record, sourcePublished, verifiedItemPublished, now time.Time) (intelligence.NormalizedRecord, error) {
	if !subscription.Public(record.IP) || !record.Proxy || record.Family != "public-subscription-aggregators" || sourcePublished.IsZero() || verifiedItemPublished.IsZero() || now.IsZero() || sourcePublished.After(now.Add(24*time.Hour)) || verifiedItemPublished.After(now.Add(24*time.Hour)) || !now.Before(sourcePublished.Add(168*time.Hour)) || !now.Before(verifiedItemPublished.Add(168*time.Hour)) {
		return intelligence.NormalizedRecord{}, errors.New("verified current literal-IP publication required")
	}
	return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordEvidence, Evidence: &intelligence.Evidence{Family: "public-subscription-aggregators", Signal: "proxy", Scope: intelligence.Exact, Address: record.IP.Unmap(), Prefix: netip.Prefix{}, SourcePublishedAt: sourcePublished, ItemPublishedAt: verifiedItemPublished, Current: true, SubscriptionLiteral: true}}, nil
}
