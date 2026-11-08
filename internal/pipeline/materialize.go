package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

// MaterializationInputs describes completeness that cannot be inferred from a
// positive VRP row. It is an engineering input, never source certification.
// Missing or partial VRP snapshots must leave VRPComplete false.
type MaterializationInputs struct{ VRPComplete bool }

// BuildIntelligence connects all eight normalized record kinds to the bounded
// public-fact planner. This engineering entry point refuses production: its
// BuildState lacks certified Tier-1 history and ASN-identity records, and does
// not replace the real-source admission/capability gate.
func BuildIntelligence(ctx context.Context, options Options, state intelligence.BuildState, policy intelligence.Policy, inputs ...MaterializationInputs) (Candidate, error) {
	if options.Mode != "synthetic" {
		return Candidate{}, &via3.Error{Code: "production_blocked"}
	}
	clock := time.Unix(options.Clock, 0).UTC()
	if !state.EvaluatedAt.Equal(clock) {
		return Candidate{}, errors.New("intelligence release clock differs from reconciliation")
	}
	for _, source := range state.Sources {
		if time.Unix(options.ValidUntil, 0).UTC().After(source.ExpiresAt) {
			return Candidate{}, errors.New("intelligence release would outlive a source receipt")
		}
	}
	return Build(ctx, options, IntelligenceProducer(state, policy, clock, inputs...))
}

// IntelligenceProducer recomputes facts from only surviving source receipts.
// Quality records cover disjoint constant regions, so sampling an exact-IP child
// at an ancestor's first address can never propagate its exact risk. Original
// network/announcement prefixes are kept independently of these derived regions.
func IntelligenceProducer(state intelligence.BuildState, policy intelligence.Policy, clock time.Time, inputs ...MaterializationInputs) Producer {
	return func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		if emit == nil || len(inputs) > 1 {
			return errors.New("one materialization policy and an output sink are required")
		}
		sink := emit
		emit = func(record via3.PublicRecord) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return sink(record)
		}
		if state.Version != 1 || state.PolicyHash == ([32]byte{}) || clock.IsZero() || !state.EvaluatedAt.Equal(clock) {
			return errors.New("same-clock reconciled intelligence state required")
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		mappings := state
		mappings.Sources = make([]intelligence.StoredSource, 0, len(state.Sources))
		var evidence []intelligence.Evidence
		var coverage []intelligence.Coverage
		var origins []intelligence.OriginMapping
		var vrps []intelligence.VRP
		var observations []intelligence.PathObservation
		usage := map[netip.Prefix][]intelligence.UsageEvidence{}
		asnPrefixes := map[uint32][]netip.Prefix{}
		asns := map[uint32]struct{}{}
		edges := map[intelligence.ASNEdge]bool{}
		relations := intelligence.NewRelationships(true)
		profiles := map[netip.Prefix]struct{}{}
		exacts := map[netip.Addr]struct{}{}
		var regions qualityRegions
		seen := map[string]struct{}{}
		count, bytes := 0, 0
		for _, source := range state.Sources {
			if err := ctx.Err(); err != nil {
				return err
			}
			if source.ID == "" || len(source.ID) > 256 || source.Fingerprint == ([32]byte{}) || !clock.Before(source.ExpiresAt) {
				return errors.New("intelligence source receipt missing or expired")
			}
			if _, ok := seen[source.ID]; ok {
				return errors.New("duplicate intelligence source receipt")
			}
			seen[source.ID] = struct{}{}
			if len(seen) > 1000 {
				return errors.New("intelligence source count exceeded")
			}
			mapping := source
			mapping.Records = nil
			for _, record := range source.Records {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := record.Validate(); err != nil {
					return err
				}
				if err := boundedNormalizedRecord(record); err != nil {
					return err
				}
				encoded, err := json.Marshal(record)
				if err != nil {
					return err
				}
				count++
				bytes += len(encoded) + 512
				if count > 200000 || bytes > 96<<20 {
					return errors.New("bounded intelligence working input exceeded")
				}
				switch record.Kind {
				case intelligence.RecordGeo, intelligence.RecordUsage, intelligence.RecordOrigins:
					mapping.Records = append(mapping.Records, record)
				}
				switch record.Kind {
				case intelligence.RecordEvidence:
					v := *record.Evidence
					if !v.Current {
						return errors.New("noncurrent normalized evidence")
					}
					evidence = append(evidence, v)
					switch v.Scope {
					case intelligence.Exact:
						if !v.Address.IsValid() || v.Address.Zone() != "" {
							return errors.New("invalid exact intelligence address")
						}
						addr := v.Address.Unmap()
						exacts[addr] = struct{}{}
						if err := regions.add(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
							return err
						}
						if addr.Is4() {
							p := netip.PrefixFrom(addr, 24).Masked()
							profiles[p] = struct{}{}
							if err := regions.add(p); err != nil {
								return err
							}
						}
					case intelligence.ExplicitPrefix:
						if err := regions.add(v.Prefix); err != nil {
							return err
						}
					case intelligence.ASN:
						asns[v.ASN] = struct{}{}
					default:
						return errors.New("invalid evidence scope")
					}
				case intelligence.RecordCoverage:
					v := *record.Coverage
					if !v.Current || v.Layer > intelligence.Neighbors24 {
						return errors.New("noncurrent normalized coverage")
					}
					coverage = append(coverage, v)
					if v.Layer == intelligence.ASN {
						asns[v.ASN] = struct{}{}
					} else if err := regions.add(v.Prefix); err != nil {
						return err
					}
					if v.Layer == intelligence.Neighbors24 {
						p, err := canonicalMappingPrefix(v.Prefix)
						if err != nil {
							return err
						}
						if p.Addr().Is4() && p.Bits() > 24 {
							if err := regions.add(netip.PrefixFrom(p.Addr(), 24).Masked()); err != nil {
								return err
							}
						}
					}
				case intelligence.RecordUsage:
					p, err := canonicalMappingPrefix(record.Usage.Prefix)
					if err != nil {
						return err
					}
					usage[p] = append(usage[p], record.Usage.Evidence)
				case intelligence.RecordOrigins:
					v := *record.Origins
					p, err := canonicalMappingPrefix(v.Prefix)
					if err != nil {
						return err
					}
					v.Prefix = p
					origins = append(origins, v)
					if err := regions.add(p); err != nil {
						return err
					}
					for _, asn := range v.Origins {
						asns[asn] = struct{}{}
						asnPrefixes[asn] = append(asnPrefixes[asn], p)
					}
				case intelligence.RecordVRP:
					v := *record.VRP
					p, err := canonicalMappingPrefix(v.Prefix)
					if err != nil {
						return err
					}
					if v.Prefix.Addr().Is4In6() {
						if v.MaxLength < 96 {
							return errors.New("mapped VRP maximum length invalid")
						}
						v.MaxLength -= 96
					}
					v.Prefix = p
					vrps = append(vrps, v)
				case intelligence.RecordPath:
					if _, err := canonicalMappingPrefix(record.Path.Prefix); err != nil {
						return err
					}
					v := record.Path.Observation
					if !v.Current {
						return errors.New("noncurrent normalized path")
					}
					observations = append(observations, v)
					asns[v.Origin] = struct{}{}
				case intelligence.RecordRelationship:
					v := record.Relationship
					if err := relations.Add(v.From, v.To, v.Relation); err != nil {
						return err
					}
					edges[intelligence.ASNEdge{From: v.From, To: v.To}] = false
					edges[intelligence.ASNEdge{From: v.To, To: v.From}] = false
					asns[v.From] = struct{}{}
					asns[v.To] = struct{}{}
				}
			}
			mappings.Sources = append(mappings.Sources, mapping)
		}
		engine, err := intelligence.NewEngine(policy, evidence, coverage, origins, clock)
		if err != nil {
			return err
		}
		completeVRP := len(vrps) > 0 && len(inputs) == 1 && inputs[0].VRPComplete
		vrpIndex, err := intelligence.NewVRPIndex(vrps, completeVRP)
		if err != nil {
			return err
		}
		vrpsByPrefix := map[netip.Prefix][]intelligence.VRP{}
		for _, vrp := range vrps {
			key := vrp.Prefix.Masked()
			vrpsByPrefix[key] = append(vrpsByPrefix[key], vrp)
		}
		paths, err := intelligence.RankPaths(observations, relations)
		if err != nil {
			return err
		}
		for _, p := range paths {
			// Nonlinear/looped/private-ASN observations are retained verbatim in
			// their typed path row, but cannot create displayed graph edges.
			if !p.GraphEligible {
				continue
			}
			previous := uint32(0)
			for _, segment := range p.Segments {
				if segment.Type != intelligence.ASSequence {
					previous = 0
					continue
				}
				for _, asn := range segment.ASNs {
					asns[asn] = struct{}{}
					if previous != 0 && previous != asn {
						edges[intelligence.ASNEdge{From: previous, To: asn}] = true
						edges[intelligence.ASNEdge{From: asn, To: previous}] = true
					}
					previous = asn
				}
			}
		}
		for asn := range asns {
			if !facts.PublicASN(asn) {
				return errors.New("invalid intelligence ASN")
			}
		}
		if err := MappingProducer(mappings, policy, clock)(ctx, emit); err != nil {
			return err
		}
		if err := regions.visit(ctx, func(p netip.Prefix) error {
			q, err := engine.Lookup(p.Addr())
			if err != nil {
				return err
			}
			_, exact := exacts[p.Addr()]
			return emit(via3.PublicRecord{Version: 3, Kind: 6, Prefix: p, Exact: exact && p.Bits() == p.Addr().BitLen(), Quality: qualityData(q)})
		}); err != nil {
			return err
		}
		profileKeys := make([]netip.Prefix, 0, len(profiles))
		for p := range profiles {
			profileKeys = append(profileKeys, p)
		}
		sortPrefixes(profileKeys)
		for _, prefix := range profileKeys {
			if err := ctx.Err(); err != nil {
				return err
			}
			profile, err := engine.Profile24(prefix.Addr())
			if err != nil {
				return err
			}
			out := via3.ProfileData{}
			if profile.DominantASN != nil {
				out.DominantASN = *profile.DominantASN
			}
			for _, cell := range profile.Cells {
				var applicable []intelligence.UsageEvidence
				for bits := 0; bits <= 32; bits++ {
					applicable = append(applicable, usage[netip.PrefixFrom(cell.Address, bits).Masked()]...)
					if len(applicable) > 8192 {
						return errors.New("profile usage working set exceeded")
					}
				}
				u := intelligence.FuseUsage(applicable)
				typeID, _ := usageType(u.Type)
				assignmentID, _ := assignmentType(u.Assignment)
				v := via3.CellData{Address: cell.Address, Usage: typeID, Assignment: assignmentID, Anycast: u.Anycast, DirectedBroadcast: u.DirectedBroadcast, Reasons: cell.Reasons, Score: cell.Quality.Score, Confidence: confidenceID(cell.Quality.Confidence), AttachNetwork: len(cell.Origins) > 0}
				if cell.Quality.Contributions[0] != nil {
					risk := *cell.Quality.Contributions[0] / policy.Weights[0]
					v.ExactRisk = &risk
				}
				out.Cells = append(out.Cells, v)
			}
			if err := emit(via3.PublicRecord{Version: 3, Kind: 7, Prefix: prefix, Profile: &out}); err != nil {
				return err
			}
		}
		asnKeys := make([]uint32, 0, len(asns))
		for asn := range asns {
			asnKeys = append(asnKeys, asn)
		}
		sort.Slice(asnKeys, func(i, j int) bool { return asnKeys[i] < asnKeys[j] })
		for _, asn := range asnKeys {
			if err := ctx.Err(); err != nil {
				return err
			}
			prefixes := asnPrefixes[asn]
			sortPrefixes(prefixes)
			prefixes = uniquePrefixes(prefixes)
			out := via3.ASNData{Prefixes: prefixes}
			context := engine.ASNContext(asn)
			if context.Present {
				out.Risk = &context.Risk
				if context.Contribution > 0 {
					out.Reasons = intelligence.ReasonASNContext
				}
			}
			if err := emit(via3.PublicRecord{Version: 3, Kind: 8, ASN: asn, ASNAggregate: &out}); err != nil {
				return err
			}
		}
		announcements := map[netip.Prefix]map[uint32]struct{}{}
		for _, mapping := range origins {
			if announcements[mapping.Prefix] == nil {
				announcements[mapping.Prefix] = map[uint32]struct{}{}
			}
			for _, asn := range mapping.Origins {
				announcements[mapping.Prefix][asn] = struct{}{}
			}
		}
		prefixes := make([]netip.Prefix, 0, len(announcements))
		for p := range announcements {
			prefixes = append(prefixes, p)
		}
		sortPrefixes(prefixes)
		for _, p := range prefixes {
			keys := make([]uint32, 0, len(announcements[p]))
			for asn := range announcements[p] {
				keys = append(keys, asn)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, asn := range keys {
				status := uint8(0)
				maximumLength := uint8(0)
				switch vrpIndex.Validate(p, asn) {
				case intelligence.RPKIValid:
					status = 1
					for bits := p.Bits(); bits >= 0; bits-- {
						for _, vrp := range vrpsByPrefix[netip.PrefixFrom(p.Addr(), bits).Masked()] {
							if vrp.ASN == asn && int(vrp.MaxLength) >= p.Bits() && vrp.MaxLength > maximumLength {
								maximumLength = vrp.MaxLength
							}
						}
					}
				case intelligence.RPKIInvalid:
					status = 2
				case intelligence.RPKINotFound:
					status = 3
				}
				if err := emit(via3.PublicRecord{Version: 3, Kind: 9, Prefix: p, ASN: asn, RPKI: &via3.RPKIData{Status: status, MaximumLength: maximumLength}}); err != nil {
					return err
				}
			}
		}
		ranks := map[uint32]uint16{}
		for _, path := range paths {
			data := via3.PathData{GraphEligible: path.GraphEligible, Visibility: path.VisibilityBand}
			for _, segment := range path.Segments {
				data.Segments = append(data.Segments, via3.SegmentData{Type: uint8(segment.Type), ASNs: segment.ASNs})
			}
			if err := emit(via3.PublicRecord{Version: 3, Kind: 11, ASN: path.Origin, Rank: ranks[path.Origin], Path: &data}); err != nil {
				return err
			}
			ranks[path.Origin]++
		}
		edgeKeys := make([]intelligence.ASNEdge, 0, len(edges))
		for edge := range edges {
			edgeKeys = append(edgeKeys, edge)
		}
		sort.Slice(edgeKeys, func(i, j int) bool {
			if edgeKeys[i].From != edgeKeys[j].From {
				return edgeKeys[i].From < edgeKeys[j].From
			}
			return edgeKeys[i].To < edgeKeys[j].To
		})
		for _, edge := range edgeKeys {
			relation := relations.Relation(edge.From, edge.To)
			if err := emit(via3.PublicRecord{Version: 3, Kind: 12, ASN: edge.From, Relationship: &via3.RelationshipData{To: edge.To, Relation: uint8(relation), Observed: edges[edge], Inferred: relation != intelligence.UnknownRelation}}); err != nil {
				return err
			}
		}
		return nil
	}
}

func confidenceID(value string) uint8 {
	switch value {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}
func qualityData(q intelligence.QualityResult) *via3.QualityData {
	return &via3.QualityData{Score: q.Score, Confidence: confidenceID(q.Confidence), Reasons: q.Reasons, Exact: q.Contributions[0], Prefix: q.Contributions[1], ASN: q.Contributions[2], Neighbors: q.Contributions[3]}
}
func uniquePrefixes(values []netip.Prefix) []netip.Prefix {
	out := values[:0]
	for _, p := range values {
		if len(out) == 0 || out[len(out)-1] != p {
			out = append(out, p)
		}
	}
	return out
}

func boundedNormalizedRecord(record intelligence.NormalizedRecord) error {
	bad := false
	if v := record.Evidence; v != nil {
		bad = len(v.Family) > 256 || len(v.Signal) > 32
	}
	if v := record.Coverage; v != nil {
		bad = len(v.Family) > 256
	}
	if v := record.Geo; v != nil {
		bad = len(v.Family) > 256 || len(v.Region) > 1024 || len(v.City) > 1024 || len(v.PhysicalCountry) > 2 || len(v.RegistrationCountry) > 2
	}
	if v := record.Usage; v != nil {
		bad = len(v.Evidence.Family) > 256 || len(v.Evidence.Type) > 32 || len(v.Evidence.Assignment) > 32
	}
	if v := record.Origins; v != nil {
		bad = len(v.Origins) > via3.PublicOrigins
	}
	if v := record.Path; v != nil {
		bad = len(v.Observation.Family) > 256 || len(v.Observation.Segments) > 255
		total := 0
		for _, segment := range v.Observation.Segments {
			total += len(segment.ASNs)
		}
		bad = bad || total > via3.PublicPathASNs
	}
	if bad {
		return errors.New("normalized materialization field limit")
	}
	return nil
}

// A bounded binary radix partitions the union of change boundaries into
// disjoint regions. Missing siblings are emitted only under a covered ancestor.
// Its depth is bounded by the address width and never scans individual hosts.
type qualityNode struct {
	covered  bool
	children [2]*qualityNode
}
type qualityRegions struct {
	roots [2]*qualityNode
	nodes int
}

func (r *qualityRegions) add(prefix netip.Prefix) error {
	p, err := canonicalMappingPrefix(prefix)
	if err != nil {
		return err
	}
	family := 0
	if p.Addr().Is6() {
		family = 1
	}
	newNode := func() (*qualityNode, error) {
		r.nodes++
		if r.nodes > 1000000 {
			return nil, errors.New("quality change-boundary node limit")
		}
		return &qualityNode{}, nil
	}
	if r.roots[family] == nil {
		r.roots[family], err = newNode()
		if err != nil {
			return err
		}
	}
	node := r.roots[family]
	raw := p.Addr().As16()
	offset := 0
	if family == 0 {
		offset = 96
	}
	for bit := 0; bit < p.Bits(); bit++ {
		position := offset + bit
		branch := int((raw[position/8] >> uint(7-position%8)) & 1)
		if node.children[branch] == nil {
			node.children[branch], err = newNode()
			if err != nil {
				return err
			}
		}
		node = node.children[branch]
	}
	node.covered = true
	return nil
}
func (r *qualityRegions) visit(ctx context.Context, emit func(netip.Prefix) error) error {
	var walk func(*qualityNode, netip.Prefix, bool) error
	walk = func(node *qualityNode, prefix netip.Prefix, covered bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if node == nil {
			if covered {
				return emit(prefix)
			}
			return nil
		}
		covered = covered || node.covered
		if node.children[0] == nil && node.children[1] == nil {
			if covered {
				return emit(prefix)
			}
			return nil
		}
		raw := prefix.Addr().As16()
		offset := 0
		if prefix.Addr().Is4() {
			offset = 96
		}
		position := offset + prefix.Bits()
		raw[position/8] |= 1 << uint(7-position%8)
		addr := netip.AddrFrom16(raw)
		if prefix.Addr().Is4() {
			addr = addr.Unmap()
		}
		if err := walk(node.children[0], netip.PrefixFrom(prefix.Addr(), prefix.Bits()+1), covered); err != nil {
			return err
		}
		return walk(node.children[1], netip.PrefixFrom(addr, prefix.Bits()+1), covered)
	}
	if err := walk(r.roots[0], netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0), false); err != nil {
		return err
	}
	return walk(r.roots[1], netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0), false)
}
