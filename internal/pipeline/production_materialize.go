package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"vansail-ip-atlas/internal/admission"
	"vansail-ip-atlas/internal/intelligence"
	"vansail-ip-atlas/internal/via3"
)

// ProductionInputs cannot be manufactured from completeness booleans. Source qualification
// and the authenticated Tier-1 observation bind the complete state and clock.
// Missing routing observations remain unknown, never caller-supplied completeness.
type ProductionInputs struct {
	Qualification *admission.ProductionQualification
	Tier1         *intelligence.QualifiedTier1
}

// BuildEngineeringBenchmark exercises the production materializer with isolated
// benchmark records. The original authenticated baseline determines routing
// availability; transformed inputs can never create a production artifact or
// receipt. With empty inputs, expiry/withdrawal scenarios retain unknown routing
// completeness. Callers must separately prove their measured record transition.
func BuildEngineeringBenchmark(ctx context.Context, options Options, baseline, state intelligence.BuildState, policy intelligence.Policy, inputs ProductionInputs) (Candidate, error) {
	if options.Mode != "engineering" || options.ProductionGate != nil {
		return Candidate{}, &via3.Error{Code: "production_blocked"}
	}
	clock := time.Unix(options.Clock, 0).UTC()
	if (state.Version != 1 && state.Version != 2) || state.PolicyHash == ([32]byte{}) || !state.EvaluatedAt.Equal(clock) {
		return Candidate{}, errors.New("same-clock benchmark state required")
	}
	if err := policy.Validate(); err != nil {
		return Candidate{}, err
	}
	if inputs.Qualification != nil || inputs.Tier1 != nil {
		if inputs.Qualification == nil || inputs.Tier1 == nil || !baseline.EvaluatedAt.Equal(clock) {
			return Candidate{}, errors.New("qualified baseline pair required")
		}
		if err := inputs.Qualification.Validate(baseline, clock); err != nil {
			return Candidate{}, err
		}
		if err := inputs.Tier1.ValidateObservation(baseline, clock); err != nil {
			return Candidate{}, err
		}
		if time.Unix(options.ValidUntil, 0).After(inputs.Tier1.ValidUntil()) {
			return Candidate{}, errors.New("benchmark outlives baseline routing qualification")
		}
	}
	for _, source := range state.Sources {
		if source.ID == "" || source.Fingerprint == ([32]byte{}) || !clock.Before(source.ExpiresAt) || time.Unix(options.ValidUntil, 0).After(source.ExpiresAt) {
			return Candidate{}, errors.New("invalid or expired benchmark source")
		}
	}
	return buildStreamedCandidate(ctx, options, state, policy, inputs)
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
	if err := inputs.Tier1.ValidateObservation(state, clock); err != nil {
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
	options.PrivateLabelValues = inputs.Qualification.PrivateLabelValues()
	originalGate := options.ProductionGate
	options.ProductionGate = func(gateCtx context.Context) error {
		if err := inputs.Qualification.Validate(state, clock); err != nil {
			return err
		}
		if err := inputs.Tier1.ValidateObservation(state, clock); err != nil {
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
	cache, err := openMaterializationCache(ctx, options, state, policy, inputs)
	if err != nil {
		return Candidate{}, err
	}
	options.materializationCache = cache
	disk, err := stateDiskBytes(options.Workspace)
	if err != nil {
		return Candidate{}, err
	}
	disk += cache.bytes
	if disk >= options.Limits.ScratchBytes {
		return Candidate{}, errors.New("normalized state exhausted scratch budget")
	}
	var used atomic.Uint64
	var reuse *spatialCache
	cacheBytes := func() uint64 {
		if reuse != nil {
			return reuse.DiskBytes()
		}
		return 0
	}
	spool, err := newBulkSpool(options.Workspace, clock, state.PolicyHash, options.Limits.ScratchBytes, func() uint64 { return disk + used.Load() + cacheBytes() })
	if err != nil {
		return Candidate{}, err
	}
	spool.observe = options.ObserveStage
	defer func() {
		if spool.prefixFile != nil {
			returnErr = errors.Join(returnErr, spool.prefixFile.Close())
		}
		returnErr = errors.Join(returnErr, os.RemoveAll(spool.root))
	}()
	executable, err := os.Executable()
	if err != nil {
		return Candidate{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return Candidate{}, err
	}
	implementation, err := cacheFileHash(ctx, executable, 256<<20)
	if err != nil {
		return Candidate{}, err
	}
	contract, err := spatialReuseKey("contract", struct {
		Implementation [32]byte
		PrivateLabels  []string
		Limits         Limits
		Mode           string
		Schema         int
	}{implementation, options.PrivateLabelValues, options.Limits, options.Mode, 5})
	if err != nil {
		return Candidate{}, err
	}
	reuse, err = openSpatialCache(ctx, options.Workspace, contract, options.Limits.ScratchBytes/4, func(prospective uint64) bool {
		other := disk + used.Load() + spool.pathBytes
		if spool.store != nil {
			other += spool.store.DiskBytes()
		}
		return other < options.Limits.ScratchBytes && prospective < options.Limits.ScratchBytes-other
	})
	if err != nil {
		return Candidate{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, reuse.Abort()) }()
	if canReuseSpatialState(state) {
		spool.reuse = reuse
		options.spatialSpool = spool
		options.compiledReuse = reuse
		var dependencies [32]byte
		dependenciesBound := false
		options.partitionDependencies = func(ctx context.Context) ([32]byte, error) {
			if dependenciesBound {
				return dependencies, ctx.Err()
			}
			var err error
			dependencies, err = spool.compiledDependencies(ctx)
			dependenciesBound = err == nil
			return dependencies, err
		}
		options.prepareSpatialCache = func(ctx context.Context) error {
			if !spool.started {
				return nil
			}
			if dependenciesBound {
				actual, err := spool.compiledDependencies(ctx)
				if err != nil || actual != dependencies {
					return errors.Join(err, errors.New("ASN prefix provider changed during compilation"))
				}
			}
			return reuse.Prepare(ctx)
		}
		options.commitSpatialCache = func(ctx context.Context) error {
			if !spool.started {
				return nil
			}
			return reuse.Commit(ctx)
		}
	}
	options.scratchUsage = used.Store
	options.prefixProvider = spool.providePrefixes
	options.externalScratch = func() uint64 {
		extra := disk + cacheBytes()
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
	families    [4]string
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
	if v.familyCount >= 4 {
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
	return func(ctx context.Context, emit func(via3.PublicRecord) error) (returnErr error) {
		spool.started = true
		if inputs.Tier1 != nil {
			spool.relations = nil
		}
		seedPhase := spool.stage(ctx, StageSeed)
		spatial, asnRoot, err := spool.seed(ctx, workspace, state)
		seedPhase(err == nil)
		if err != nil {
			return err
		}
		var relations intelligence.RelationResolver = inputs.Tier1
		if inputs.Tier1 == nil {
			relations = spool.relations
		}
		pathsPhase := spool.stage(ctx, StagePaths)
		if err = spool.preparePrefixes(ctx); err != nil {
			pathsPhase(false)
			return err
		}
		err = spool.reducePaths(ctx, relations, func(path intelligence.Path, rank uint16) error {
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
		})
		pathsPhase(err == nil)
		if err != nil {
			return err
		}
		riskPhase := spool.stage(ctx, StageASNRisk)
		aggregates := globalASNAggregates{values: map[uint32]*globalASNSummary{}, families: map[string]string{}}
		// The first spatial pass computes exact-IP mass in canonical global address
		// order. No partial per-bucket ASN context is allowed to reach public output.
		// Without any observed origin mapping no exact IP can contribute ASN
		// mass. The final IP risk and /24 pass still processes every observation.
		observedAt, coverageValidUntil, completeVRP := inputs.Qualification.RPKIObservation()
		dependencies := spatialDependencies{Policy: policy, PolicyHash: state.PolicyHash, Clock: clock,
			Usage: spool.usage, Coverage: spool.coverage, VRPComplete: completeVRP,
			RPKIObservedAt: observedAt, RPKICoverageValidUntil: coverageValidUntil}
		if spool.hasExact && len(spool.prefixIndex) > 0 {
			accumulate := func(event spatialRiskEvent) error {
				for _, asn := range event.Origins {
					value, err := aggregates.value(asn)
					if err != nil {
						return err
					}
					value.mass += event.Risk
					value.count++
					value.present = true
					for _, family := range event.Families {
						if err = aggregates.family(value, family); err != nil {
							return err
						}
					}
				}
				return nil
			}
			riskRoots, separateRisk := spool.routedRiskRoots(spatial)
			var reuse *bulkLeafReuse
			if spool.reuse != nil {
				scoreKey, err := exactRiskDependencies(policy, clock)
				if err != nil {
					return err
				}
				// Separate risk roots exclude joined roles. A shared public root
				// still sizes those rows when it chooses its fixed geometry.
				roles := spool.usage
				if separateRisk {
					roles = nil
				}
				shapeKey, err := spatialReuseKey("exact-risk-shape", struct {
					Separate bool
					Usage    asnUsageIndex
				}{separateRisk, roles})
				if err != nil {
					return err
				}
				layoutKey, err := spatialReuseKey("exact-risk-layout", [2][32]byte{scoreKey, shapeKey})
				if err != nil {
					return err
				}
				reuse = &bulkLeafReuse{domain: "risk", dependencies: layoutKey, riskShape: shapeKey, riskPolicy: scoreKey, spool: spool, risk: accumulate}
			}
			var riskLeaves []*bulkBucket
			riskLeaves, err = spool.leavesReusing(ctx, riskRoots, false, reuse, func(bucket *bulkBucket, part intelligence.BuildState) error {
				if reuse != nil {
					return reuse.visitRisk(ctx, bucket, part, policy, clock)
				}
				prepare := func(engine *intelligence.Engine) error {
					return engine.WalkExactRisks(ctx, func(address netip.Addr, risk float64, families []string, origins []uint32) error {
						event := spatialRiskEvent{Address: address, Risk: risk, Families: families, Origins: origins}
						if err := reuse.recordRisk(event); err != nil {
							return err
						}
						return accumulate(event)
					})
				}
				return IntelligenceProducer(part, policy, clock, MaterializationInputs{scope: bucket.prefix, prepare: prepare, prepareOnly: true, encodedLengths: bucket.recordBytes})(ctx, func(via3.PublicRecord) error { return nil })
			})
			if separateRisk {
				for _, leaf := range riskLeaves {
					leaf.active = false
				}
			} else {
				spatial = riskLeaves
			}
		}
		if err != nil {
			riskPhase(false)
			return err
		}
		asnLeaves := []*bulkBucket{asnRoot}
		if spool.hasASNDirect {
			asnLeaves, err = spool.leaves(ctx, asnLeaves, false, func(bucket *bulkBucket, part intelligence.BuildState) error {
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
				return IntelligenceProducer(part, policy, clock, MaterializationInputs{prepare: prepare, prepareOnly: true, encodedLengths: bucket.recordBytes})(ctx, func(via3.PublicRecord) error { return nil })
			})
		}
		if err != nil {
			riskPhase(false)
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
		riskPhase(true)
		spatialPhase := spool.stage(ctx, StageSpatial)
		var publicReuse *bulkLeafReuse
		var locationPolicy [32]byte
		if spool.reuse != nil {
			locationPolicy, err = spatialReuseKey("location-policy", struct {
				Policy     intelligence.Policy
				PolicyHash [32]byte
			}{policy, state.PolicyHash})
			if err != nil {
				return err
			}
			key, keyErr := spatialReuseKey("public-origin-scoped-dependencies", dependencies)
			if keyErr != nil {
				return keyErr
			}
			coreInputs := dependencies
			coreInputs.VRPComplete, coreInputs.RPKIObservedAt, coreInputs.RPKICoverageValidUntil = false, time.Time{}, time.Time{}
			core, keyErr := spatialReuseKey(publicCoreDomain, coreInputs)
			if keyErr != nil {
				return keyErr
			}
			publicReuse = &bulkLeafReuse{domain: "public", dependencies: key, publicCore: core, withoutRPKI: !completeVRP, contexts: contexts, locationPolicy: locationPolicy, spool: spool, public: emit}
		}
		spatial, err = spool.leavesReusing(ctx, spatial, true, publicReuse, func(bucket *bulkBucket, part intelligence.BuildState) error {
			mappings := func(ctx context.Context, produce mappingProducerFactory, emit func(via3.PublicRecord) error) error {
				return spool.materializeMappings(ctx, bucket, locationPolicy, produce, emit)
			}
			return IntelligenceProducer(part, policy, clock, MaterializationInputs{mappings: mappings, geoReplay: bucket.geoReplay, VRPComplete: completeVRP, RPKIObservedAt: observedAt, RPKICoverageValidUntil: coverageValidUntil, verifiedEmptyVRP: completeVRP, scope: bucket.prefix, contexts: contexts, resolver: relations, encodedLengths: bucket.recordBytes, spatialOutputsOnly: true})(ctx, func(record via3.PublicRecord) error {
				if record.Kind >= 8 && record.Kind != 9 {
					return nil
				}
				if record.Kind == 6 || record.Kind == 7 {
					if !bucket.prefix.Contains(record.Prefix.Addr()) || record.Prefix.Bits() < bucket.prefix.Bits() {
						return nil
					}
				}
				spool.publicRows++
				return emit(record)
			})
		})
		spatialPhase(err == nil)
		if err != nil {
			return err
		}
		_ = spatial
		asnPhase := spool.stage(ctx, StageASN)
		defer func() { asnPhase(returnErr == nil) }()
		emitted := map[uint32]bool{}
		_, err = spool.leaves(ctx, asnLeaves, false, func(bucket *bulkBucket, part intelligence.BuildState) error {
			return IntelligenceProducer(part, policy, clock, MaterializationInputs{contexts: contexts, resolver: relations, encodedLengths: bucket.recordBytes})(ctx, func(record via3.PublicRecord) error {
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
