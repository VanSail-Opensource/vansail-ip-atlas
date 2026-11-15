package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

// ProductionInputs cannot be manufactured from completeness booleans. Both
// qualified objects independently bind the sealed real-source state and clock.
type ProductionInputs struct {
	Qualification *admission.ProductionQualification
	Tier1         *intelligence.QualifiedTier1
}

// BuildStreamedIntelligence is an explicitly synthetic engineering entry for
// full partitioned private state. It cannot assert complete VRP coverage or
// create source-qualified Tier-1 history and never accepts production mode.
func BuildStreamedIntelligence(ctx context.Context, options Options, state intelligence.BuildState, policy intelligence.Policy) (Candidate, error) {
	if options.Mode != "synthetic" {
		return Candidate{}, &via3.Error{Code: "production_blocked"}
	}
	if containsAdmittedData(state) {
		options.Mode = "engineering"
	}
	clock := time.Unix(options.Clock, 0).UTC()
	if (state.Version != 1 && state.Version != 2) || state.PolicyHash == ([32]byte{}) || !state.EvaluatedAt.Equal(clock) {
		return Candidate{}, errors.New("same-clock private state required")
	}
	if err := policy.Validate(); err != nil {
		return Candidate{}, err
	}
	for _, source := range state.Sources {
		if source.ID == "" || source.Fingerprint == ([32]byte{}) || !clock.Before(source.ExpiresAt) || time.Unix(options.ValidUntil, 0).After(source.ExpiresAt) {
			return Candidate{}, errors.New("invalid or expired source receipt")
		}
	}
	return buildStreamedCandidate(ctx, options, state, policy, ProductionInputs{})
}

func BuildProductionIntelligence(ctx context.Context, options Options, state intelligence.BuildState, policy intelligence.Policy, inputs ProductionInputs) (Candidate, error) {
	if options.Mode != "production" || options.ProductionGate == nil || inputs.Qualification == nil || inputs.Tier1 == nil {
		return Candidate{}, &via3.Error{Code: "production_blocked"}
	}
	clock := time.Unix(options.Clock, 0).UTC()
	if !state.EvaluatedAt.Equal(clock) {
		return Candidate{}, errors.New("production state clock mismatch")
	}
	if err := policy.Validate(); err != nil {
		return Candidate{}, err
	}
	if err := inputs.Qualification.Validate(state, clock); err != nil {
		return Candidate{}, err
	}
	if err := inputs.Tier1.Validate(state, clock); err != nil {
		return Candidate{}, err
	}
	if time.Unix(options.ValidUntil, 0).After(inputs.Tier1.ValidUntil()) {
		return Candidate{}, errors.New("production candidate outlives authenticated Tier-1 observation or stability anchor")
	}
	for _, source := range state.Sources {
		if !clock.Before(source.ExpiresAt) || time.Unix(options.ValidUntil, 0).After(source.ExpiresAt) {
			return Candidate{}, errors.New("production candidate outlives source receipt")
		}
	}
	originalGate := options.ProductionGate
	options.ProductionGate = func(gateCtx context.Context) error {
		if err := inputs.Qualification.Validate(state, clock); err != nil {
			return err
		}
		if err := inputs.Tier1.Validate(state, clock); err != nil {
			return err
		}
		return originalGate(gateCtx)
	}
	return buildStreamedCandidate(ctx, options, state, policy, inputs)
}
func buildStreamedCandidate(ctx context.Context, options Options, state intelligence.BuildState, policy intelligence.Policy, inputs ProductionInputs) (candidate Candidate, returnErr error) {
	clock := time.Unix(options.Clock, 0).UTC()
	if options.Limits == (Limits{}) {
		options.Limits = DefaultLimits()
	}
	if err := options.Limits.validate(); err != nil {
		return Candidate{}, err
	}
	disk, err := stateDiskBytes(options.Workspace)
	if err != nil {
		return Candidate{}, err
	}
	if disk >= options.Limits.ScratchBytes {
		return Candidate{}, errors.New("normalized state exhausted scratch budget")
	}
	var used atomic.Uint64
	spool, err := newBulkSpool(options.Workspace, clock, state.PolicyHash, options.Limits.ScratchBytes, func() uint64 { return disk + used.Load() })
	if err != nil {
		return Candidate{}, err
	}
	defer func() {
		if spool.prefixFile != nil {
			returnErr = errors.Join(returnErr, spool.prefixFile.Close())
		}
		returnErr = errors.Join(returnErr, os.RemoveAll(spool.root))
	}()
	options.scratchUsage = used.Store
	options.prefixProvider = spool.providePrefixes
	options.externalScratch = func() uint64 {
		extra := disk
		if spool.store != nil {
			extra += spool.store.DiskBytes()
		}
		extra += spool.pathBytes
		return extra
	}
	return Build(ctx, options, bulkIntelligenceProducer(options.Workspace, state, policy, clock, inputs, spool))
}

type globalASNSummary struct {
	mass        float64
	count       uint64
	families    [3]string
	familyCount int
	explicit    float64
	present     bool
}
type globalASNAggregates struct {
	values   map[uint32]*globalASNSummary
	families map[string]string
}

func (g *globalASNAggregates) value(asn uint32) (*globalASNSummary, error) {
	v := g.values[asn]
	if v == nil {
		if len(g.values) >= 200000 {
			return nil, errors.New("global ASN risk population exceeded")
		}
		v = &globalASNSummary{}
		g.values[asn] = v
	}
	return v, nil
}
func (g *globalASNAggregates) family(v *globalASNSummary, family string) error {
	if v.familyCount >= 3 {
		return nil
	}
	for i := 0; i < v.familyCount; i++ {
		if v.families[i] == family {
			return nil
		}
	}
	name, ok := g.families[family]
	if !ok {
		if len(g.families) >= 1000 || len(family) > 256 {
			return errors.New("global evidence-family budget exceeded")
		}
		name = family
		g.families[family] = name
	}
	v.families[v.familyCount] = name
	v.familyCount++
	return nil
}
func bulkIntelligenceProducer(workspace string, state intelligence.BuildState, policy intelligence.Policy, clock time.Time, inputs ProductionInputs, spool *bulkSpool) Producer {
	return func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		if inputs.Tier1 != nil {
			spool.relations = nil
		}
		spatial, asnRoot, err := spool.seed(ctx, workspace, state)
		if err != nil {
			return err
		}
		var relations intelligence.RelationResolver = inputs.Tier1
		if inputs.Tier1 == nil {
			relations = spool.relations
		}
		if err = spool.preparePrefixes(ctx); err != nil {
			return err
		}
		if err = spool.reducePaths(ctx, relations, func(path intelligence.Path, rank uint16) error {
			data := via3.PathData{GraphEligible: path.GraphEligible, Visibility: path.VisibilityBand}
			var previous uint32
			for _, segment := range path.Segments {
				data.Segments = append(data.Segments, via3.SegmentData{Type: uint8(segment.Type), ASNs: segment.ASNs})
				if path.GraphEligible {
					for _, asn := range segment.ASNs {
						if err := spool.addASN(asn); err != nil {
							return err
						}
						if previous != 0 && previous != asn {
							if err := spool.addEdge(intelligence.ASNEdge{From: previous, To: asn}, true); err != nil {
								return err
							}
							if err := spool.addEdge(intelligence.ASNEdge{From: asn, To: previous}, true); err != nil {
								return err
							}
						}
						previous = asn
					}
				}
			}
			return emit(via3.PublicRecord{Version: 3, Kind: 11, ASN: path.Origin, Rank: rank, Path: &data})
		}); err != nil {
			return err
		}
		aggregates := globalASNAggregates{values: map[uint32]*globalASNSummary{}, families: map[string]string{}}
		// The first spatial pass computes exact-IP mass in canonical global address
		// order. No partial per-bucket ASN context is allowed to reach public output.
		if spool.hasExact {
			spatial, err = spool.leaves(ctx, spatial, false, func(bucket *bulkBucket, part intelligence.BuildState) error {
				prepare := func(engine *intelligence.Engine) error {
					return engine.WalkExactRisks(ctx, func(_ netip.Addr, risk float64, families []string, origins []uint32) error {
						for _, asn := range origins {
							v, err := aggregates.value(asn)
							if err != nil {
								return err
							}
							v.mass += risk
							v.count++
							v.present = true
							for _, family := range families {
								if err = aggregates.family(v, family); err != nil {
									return err
								}
							}
						}
						return nil
					})
				}
				return IntelligenceProducer(part, policy, clock, MaterializationInputs{scope: bucket.prefix, prepare: prepare, prepareOnly: true})(ctx, func(via3.PublicRecord) error { return nil })
			})
		}
		if err != nil {
			return err
		}
		asnLeaves := []*bulkBucket{asnRoot}
		if spool.hasASNDirect {
			asnLeaves, err = spool.leaves(ctx, asnLeaves, false, func(_ *bulkBucket, part intelligence.BuildState) error {
				prepare := func(engine *intelligence.Engine) error {
					for _, source := range part.Sources {
						for _, record := range source.Records {
							if v := record.Evidence; v != nil && v.Scope == intelligence.ASN {
								summary, err := aggregates.value(v.ASN)
								if err != nil {
									return err
								}
								current := engine.ASNContext(v.ASN)
								if current.Present {
									summary.explicit = current.Risk
									summary.present = true
									if v.Weight > 0 {
										if err = aggregates.family(summary, v.Family); err != nil {
											return err
										}
									}
								}
							}
						}
					}
					return nil
				}
				return IntelligenceProducer(part, policy, clock, MaterializationInputs{prepare: prepare, prepareOnly: true})(ctx, func(via3.PublicRecord) error { return nil })
			})
		}
		if err != nil {
			return err
		}
		contexts := make(map[uint32]intelligence.ASNContext, len(aggregates.values))
		for asn, value := range aggregates.values {
			if value.present {
				contexts[asn] = policy.AggregateASNContext(value.mass, value.count, value.familyCount, value.explicit)
			}
		}
		aggregates.values = nil
		aggregates.families = nil
		spatial, err = spool.leaves(ctx, spatial, true, func(bucket *bulkBucket, part intelligence.BuildState) error {
			return IntelligenceProducer(part, policy, clock, MaterializationInputs{VRPComplete: inputs.Qualification.VRPComplete(), verifiedEmptyVRP: inputs.Qualification.VRPComplete(), scope: bucket.prefix, contexts: contexts, resolver: relations})(ctx, func(record via3.PublicRecord) error {
				if record.Kind >= 8 && record.Kind != 9 {
					return nil
				}
				if record.Kind == 6 || record.Kind == 7 {
					if !bucket.prefix.Contains(record.Prefix.Addr()) || record.Prefix.Bits() < bucket.prefix.Bits() {
						return nil
					}
				}
				return emit(record)
			})
		})
		if err != nil {
			return err
		}
		_ = spatial
		emitted := map[uint32]bool{}
		_, err = spool.leaves(ctx, asnLeaves, false, func(bucket *bulkBucket, part intelligence.BuildState) error {
			return IntelligenceProducer(part, policy, clock, MaterializationInputs{contexts: contexts, resolver: relations})(ctx, func(record via3.PublicRecord) error {
				switch record.Kind {
				case 8:
					if record.ASN < bucket.first || record.ASN > bucket.last {
						return nil
					}
					applyTier1(&record, inputs.Tier1.Result(record.ASN))
					emitted[record.ASN] = true
					return emit(record)
				case 11:
					if record.Path.GraphEligible {
						for _, segment := range record.Path.Segments {
							for _, asn := range segment.ASNs {
								if err := spool.addASN(asn); err != nil {
									return err
								}
							}
						}
					}
					return emit(record)
				case 12:
					return spool.addEdge(intelligence.ASNEdge{From: record.ASN, To: record.Relationship.To}, record.Relationship.Observed)
				}
				return nil
			})
		})
		if err != nil {
			return err
		}
		for _, asn := range sortedASNs(spool.known) {
			if err := ctx.Err(); err != nil {
				return err
			}
			result := inputs.Tier1.Result(asn)
			if !emitted[asn] {
				out := via3.ASNData{}
				if risk := contexts[asn]; risk.Present {
					out.Risk = &risk.Risk
					if risk.Contribution > 0 {
						out.Reasons = intelligence.ReasonASNContext
					}
				}
				record := via3.PublicRecord{Version: 3, Kind: 8, ASN: asn, ASNAggregate: &out}
				applyTier1(&record, result)
				if err = emit(record); err != nil {
					return err
				}
			}
			if err = emit(via3.PublicRecord{Version: 3, Kind: 13, ASN: asn, Tier1: &via3.TierData{NetworkClass: networkClassID(result.Class), Stability: stabilityID(result.Stability)}}); err != nil {
				return err
			}
		}
		edges := make([]intelligence.ASNEdge, 0, len(spool.edges))
		for edge := range spool.edges {
			edges = append(edges, edge)
		}
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].From != edges[j].From {
				return edges[i].From < edges[j].From
			}
			return edges[i].To < edges[j].To
		})
		for _, edge := range edges {
			relation := relations.Relation(edge.From, edge.To)
			if err = emit(via3.PublicRecord{Version: 3, Kind: 12, ASN: edge.From, Relationship: &via3.RelationshipData{To: edge.To, Relation: uint8(relation), Observed: spool.edges[edge], Inferred: relation != intelligence.UnknownRelation}}); err != nil {
				return err
			}
		}
		return nil
	}
}
func networkClassID(value string) uint8 {
	switch value {
	case "tier1_candidate":
		return 1
	case "global_transit":
		return 2
	case "regional_transit":
		return 3
	case "access_network":
		return 4
	}
	return 0
}
func stabilityID(value string) uint8 {
	switch value {
	case "pending":
		return 1
	case "stable":
		return 2
	}
	return 0
}
func applyTier1(record *via3.PublicRecord, result intelligence.Tier1Result) {
	out := record.ASNAggregate
	out.NetworkClass = networkClassID(result.Class)
	out.Stability = stabilityID(result.Stability)
	if result.StatisticsKnown {
		cone, degree := result.CustomerCone, result.TransitDegree
		out.CustomerCone = &cone
		out.TransitDegree = &degree
	}
}
