package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

// BuildMappings is the safe mapping-only entry point. A release cannot outlive
// the earliest admitted receipt, and this incomplete product subset is always
// visibly synthetic even if a caller supplies an otherwise successful gate.
func BuildMappings(ctx context.Context, options Options, state intelligence.BuildState, policy intelligence.Policy) (Candidate, error) {
	if options.Mode != "synthetic" {
		return Candidate{}, &via3.Error{Code: "production_blocked"}
	}
	clock := time.Unix(options.Clock, 0).UTC()
	if !state.EvaluatedAt.Equal(clock) {
		return Candidate{}, errors.New("mapping release clock differs from reconciliation")
	}
	deadline := time.Unix(options.ValidUntil, 0).UTC()
	for _, source := range state.Sources {
		if deadline.After(source.ExpiresAt) {
			return Candidate{}, errors.New("mapping release would outlive a source receipt")
		}
	}
	return Build(ctx, options, MappingProducer(state, policy, clock))
}

// MappingProducer is a low-level callback; prefer BuildMappings for the source
// receipt validity bound. It materializes the complete Geo/Usage/Origins subset from a
// revalidated private reconciliation state. Unsupported record kinds are an
// error, never silently dropped. This subset cannot qualify full production.
//
// Each geo/usage change boundary is fused using ONLY its ancestors and local
// observations. Sampling an unrestricted point lookup at prefix.Addr() would
// incorrectly let a descendant at that address contaminate its broad parent.
// Empty rows and explicit coordinate tombstones prevent unknown/conflicting
// child facts from falling through to stale affirmative parent values.
func MappingProducer(state intelligence.BuildState, policy intelligence.Policy, clock time.Time) Producer {
	return mappingProducer(state, policy, clock, nil, false, netip.Prefix{})
}

// mappingProducer accepts lengths only from IntelligenceProducer's owned,
// already bounded mapping subset. Exported entry points always encode inputs.
func mappingProducer(state intelligence.BuildState, policy intelligence.Policy, clock time.Time, encodedLengths []int, omitInherited bool, scope netip.Prefix) Producer {
	return func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		if err := checkOwnedRecordLengths(state, encodedLengths); err != nil {
			return err
		}
		state, joinErr := joinASNUsage(ctx, state)
		if joinErr != nil {
			return joinErr
		}
		if emit == nil {
			return errors.New("mapping output sink is required")
		}
		if state.Version != 1 || state.PolicyHash == ([32]byte{}) || clock.IsZero() || !state.EvaluatedAt.Equal(clock) {
			return errors.New("mapping materialization requires a same-clock reconciled state")
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		geo := map[netip.Prefix][]intelligence.GeoEvidence{}
		usage := map[netip.Prefix][]intelligence.UsageEvidence{}
		origins := map[netip.Prefix][]uint32{}
		boundaries := map[netip.Prefix]struct{}{}
		seen := map[string]struct{}{}
		var bytes, count int
		for _, source := range state.Sources {
			if err := ctx.Err(); err != nil {
				return err
			}
			if source.ID == "" || len(source.ID) > 256 || source.Fingerprint == ([32]byte{}) || !clock.Before(source.ExpiresAt) {
				return errors.New("mapping source receipt is missing or expired")
			}
			if _, ok := seen[source.ID]; ok {
				return errors.New("duplicate mapping source receipt")
			}
			seen[source.ID] = struct{}{}
			if len(seen) > 1000 {
				return errors.New("mapping source receipt count exceeded")
			}
			for _, record := range source.Records {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := record.Validate(); err != nil {
					return err
				}
				if record.Kind != intelligence.RecordGeo && record.Kind != intelligence.RecordUsage && record.Kind != intelligence.RecordOrigins {
					return errors.New("mapping-only materializer cannot discard risk, coverage, RPKI, path or relationship facts")
				}
				// Reject huge nested fields before allocating their JSON encoding.
				if record.Geo != nil && (len(record.Geo.Family) > 256 || len(record.Geo.Region) > 1024 || len(record.Geo.City) > 1024 || len(record.Geo.PhysicalCountry) > 2 || len(record.Geo.RegistrationCountry) > 2) {
					return errors.New("mapping field size exceeded")
				}
				if record.Usage != nil && (len(record.Usage.Evidence.Family) > 256 || len(record.Usage.Evidence.Type) > 32 || len(record.Usage.Evidence.Assignment) > 32) {
					return errors.New("mapping field size exceeded")
				}
				if record.Origins != nil && len(record.Origins.Origins) > via3.PublicOrigins {
					return errors.New("mapping origin count exceeded")
				}
				size, err := normalizedRecordBytes(record, encodedLengths, count)
				if err != nil {
					return err
				}
				bytes += size + 512
				count++
				if bytes > 96<<20 || count > 200000 {
					return errors.New("bounded mapping materialization partition exceeded")
				}
				var prefix netip.Prefix
				switch record.Kind {
				case intelligence.RecordGeo:
					prefix = record.Geo.Prefix
				case intelligence.RecordUsage:
					prefix = record.Usage.Prefix
				case intelligence.RecordOrigins:
					prefix = record.Origins.Prefix
				}
				prefix, err = canonicalMappingPrefix(prefix)
				if err != nil {
					return err
				}
				switch record.Kind {
				case intelligence.RecordGeo:
					v := *record.Geo
					v.Prefix = prefix
					if !v.Current {
						return errors.New("mapping state contains noncurrent geo record")
					}
					geo[prefix] = append(geo[prefix], v)
					boundaries[prefix] = struct{}{}
				case intelligence.RecordUsage:
					v := record.Usage.Evidence
					if !v.Current || v.Family == "" {
						return errors.New("mapping state contains noncurrent or unbound usage record")
					}
					if _, ok := usageType(v.Type); !ok {
						return errors.New("invalid normalized usage type")
					}
					if _, ok := assignmentType(v.Assignment); !ok {
						return errors.New("invalid normalized assignment")
					}
					usage[prefix] = append(usage[prefix], v)
					boundaries[prefix] = struct{}{}
				case intelligence.RecordOrigins:
					for _, asn := range record.Origins.Origins {
						if !facts.PublicASN(asn) {
							return errors.New("invalid normalized origin")
						}
					}
					if _, ok := origins[prefix]; !ok {
						origins[prefix] = []uint32{}
					}
					origins[prefix] = append(origins[prefix], record.Origins.Origins...)
				}
			}
		}
		keys := make([]netip.Prefix, 0, len(boundaries))
		for prefix := range boundaries {
			keys = append(keys, prefix)
		}
		sortPrefixes(keys)
		// Address order, with the shortest prefix first on a tie, visits each
		// ancestor before its descendants and keeps its entire subtree together.
		// Remember the applicable evidence at each level of the active chain.
		type mappingAncestor struct {
			prefix               netip.Prefix
			geoStart, usageStart int
			geo                  via3.GeoData
			coords               via3.CoordinateData
			usage                [4]uint8
		}
		var packed locationRows
		emitLocation := emit
		if omitInherited {
			emitLocation = packed.collect
		}
		var ancestors []mappingAncestor
		var applicableGeo []intelligence.GeoEvidence
		var applicableUsage []intelligence.UsageEvidence
		for _, prefix := range keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			for len(ancestors) > 0 {
				last := ancestors[len(ancestors)-1]
				if last.prefix.Contains(prefix.Addr()) {
					break
				}
				applicableGeo = applicableGeo[:last.geoStart]
				applicableUsage = applicableUsage[:last.usageStart]
				ancestors = ancestors[:len(ancestors)-1]
			}
			localGeo, localUsage := geo[prefix], usage[prefix]
			if len(applicableGeo)+len(localGeo) > 8192 || len(applicableUsage)+len(localUsage) > 8192 {
				return errors.New("mapping boundary working set exceeded")
			}
			current := mappingAncestor{prefix: prefix, geoStart: len(applicableGeo), usageStart: len(applicableUsage)}
			applicableGeo = append(applicableGeo, localGeo...)
			applicableUsage = append(applicableUsage, localUsage...)
			u := intelligence.FuseUsage(applicableUsage)
			g, err := intelligence.FuseGeo(policy, applicableGeo, u.Anycast != nil && *u.Anycast)
			if err != nil {
				return err
			}
			geoRecord := via3.GeoData{}
			if g.PhysicalCountry != nil {
				geoRecord.Country = *g.PhysicalCountry
			}
			if g.RegistrationCountry != nil {
				geoRecord.RegistrationCountry = *g.RegistrationCountry
			}
			if g.Region != nil {
				geoRecord.Region = *g.Region
			}
			if g.City != nil {
				geoRecord.City = *g.City
			}
			coordinates := via3.CoordinateData{Unknown: true}
			if g.Coordinates != nil {
				coordinates = via3.CoordinateData{Latitude: g.Coordinates.Latitude, Longitude: g.Coordinates.Longitude, Precision: g.Coordinates.Precision}
			}
			typeID, _ := usageType(u.Type)
			assignmentID, _ := assignmentType(u.Assignment)
			current.geo, current.coords = geoRecord, coordinates
			current.usage = [4]uint8{typeID, assignmentID, optionalBoolCode(u.Anycast), optionalBoolCode(u.DirectedBroadcast)}
			// Public location lookups return the selected values. Only network and
			// BGP origin answers expose their matching prefix. Retain the first
			// row of each location kind, including an explicit unknown, and every
			// change from the nearest ancestor's value.
			var parent *mappingAncestor
			if omitInherited && len(ancestors) > 0 {
				parent = &ancestors[len(ancestors)-1]
			}
			if parent == nil || parent.geo != current.geo {
				if err := emitLocation(via3.PublicRecord{Version: 3, Kind: 2, Prefix: prefix, Geo: &geoRecord}); err != nil {
					return err
				}
			}
			if parent == nil || parent.coords != current.coords {
				if err := emitLocation(via3.PublicRecord{Version: 3, Kind: 3, Prefix: prefix, Coordinates: &coordinates}); err != nil {
					return err
				}
			}
			if parent == nil || parent.usage != current.usage {
				usageRecord := via3.UsageData{Type: typeID, Assignment: assignmentID, Anycast: u.Anycast, DirectedBroadcast: u.DirectedBroadcast}
				if err := emitLocation(via3.PublicRecord{Version: 3, Kind: 5, Prefix: prefix, Usage: &usageRecord}); err != nil {
					return err
				}
			}
			ancestors = append(ancestors, current)
		}
		if omitInherited {
			if err := packed.emit(ctx, scope, emit); err != nil {
				return err
			}
		}
		keys = keys[:0]
		for prefix := range origins {
			keys = append(keys, prefix)
		}
		sortPrefixes(keys)
		for _, prefix := range keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			asns := origins[prefix]
			sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
			asns = compact(asns)
			if len(asns) > via3.PublicOrigins {
				return errors.New("merged mapping origin count exceeded")
			}
			// These keys remain the actual observed origin prefix. They are not
			// replaced by geo-fusion boundaries or router partition prefixes.
			if err := emit(via3.PublicRecord{Version: 3, Kind: 4, Prefix: prefix, Network: &via3.NetworkData{Origins: asns}}); err != nil {
				return err
			}
			if err := emit(via3.PublicRecord{Version: 3, Kind: 10, Prefix: prefix, Origins: &via3.OriginsData{ASNs: asns}}); err != nil {
				return err
			}
		}
		return nil
	}
}

// The three possible values must stay distinct in lookup results.
func optionalBoolCode(value *bool) uint8 {
	if value == nil {
		return 0
	}
	if *value {
		return 2
	}
	return 1
}

func usageType(value string) (uint8, bool) {
	switch value {
	case "", "unknown":
		return 0, true
	case "residential":
		return 1, true
	case "business":
		return 2, true
	case "mobile":
		return 3, true
	case "datacenter":
		return 4, true
	case "hosting":
		return 5, true
	case "education":
		return 6, true
	case "government":
		return 7, true
	default:
		return 0, false
	}
}
func assignmentType(value string) (uint8, bool) {
	switch value {
	case "", "unknown":
		return 0, true
	case "native":
		return 1, true
	case "broadcast_or_routed":
		return 2, true
	default:
		return 0, false
	}
}

func canonicalMappingPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("mapping prefix invalid")
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New("mapping prefix crosses address families")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}
func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})
}
