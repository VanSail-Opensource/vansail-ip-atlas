package intelligence

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"
)

type Tier1Result struct {
	ASN                         uint32
	Class, Stability            string
	CustomerCone, TransitDegree uint32
	StatisticsKnown             bool
}
type Tier1Snapshot struct {
	PublishedAt   time.Time
	PolicyHash    string
	Eligible      bool
	RawCandidates map[uint32]bool // build-private stability state, never a public allowlist
	Results       []Tier1Result
}

var ErrGraphBudget = errors.New("Tier-1 graph work budget exceeded")

// DeriveTier1 never consults an ASN membership list. It uses a bounded traversal
// budget instead of materializing an unbounded all-pairs customer-cone matrix.
// A budget failure is a failed build, never a smaller percentile population.
func DeriveTier1(ctx context.Context, relations *RelationshipIndex, paths []PathObservation, publishedAt, now time.Time, policyHash string, previous *Tier1Snapshot, maxWork int) (Tier1Snapshot, error) {
	out := Tier1Snapshot{PublishedAt: publishedAt, PolicyHash: policyHash, RawCandidates: map[uint32]bool{}}
	if relations == nil {
		return out, nil
	}
	nodes := make([]uint32, 0, len(relations.nodes))
	for asn := range relations.nodes {
		nodes = append(nodes, asn)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })
	unknown := func() {
		out.Results = make([]Tier1Result, len(nodes))
		for i, asn := range nodes {
			out.Results[i] = Tier1Result{ASN: asn, Class: "unknown", Stability: "unavailable"}
		}
	}
	unknown()
	if !relations.current || len(relations.conflicts) > 0 || len(nodes) == 0 || policyHash == "" || publishedAt.IsZero() || publishedAt.After(now.Add(24*time.Hour)) || !now.Before(publishedAt.Add(720*time.Hour)) {
		return out, nil
	}
	if maxWork <= 0 || len(nodes) > 200_000 {
		return out, ErrGraphBudget
	}
	families := map[string]struct{}{}
	visibility := map[uint32]map[string]struct{}{}
	incidentUnknown := map[uint32]bool{}
	for _, v := range paths {
		if !v.Current || v.Family == "" {
			continue
		}
		p, err := canonicalPath(v)
		if err != nil {
			return out, err
		}
		families[v.Family] = struct{}{}
		if !p.GraphEligible {
			continue
		}
		var prior uint32
		for _, segment := range p.Segments {
			for _, asn := range segment.ASNs {
				addFamily(visibility, asn, v.Family)
				if prior != 0 && prior != asn && relations.Relation(prior, asn) == UnknownRelation {
					incidentUnknown[prior] = true
					incidentUnknown[asn] = true
				}
				prior = asn
			}
		}
	}
	if len(families) < 2 {
		return out, nil
	}
	customers := map[uint32][]uint32{}
	upstreams := map[uint32]int{}
	indegree := map[uint32]int{}
	for edge, relation := range relations.edges {
		if relation == Customer {
			customers[edge.From] = append(customers[edge.From], edge.To)
			upstreams[edge.To]++
			indegree[edge.To]++
		}
	}
	for asn := range customers {
		sort.Slice(customers[asn], func(i, j int) bool { return customers[asn][i] < customers[asn][j] })
	}
	// Kahn cycle detection includes the entire fixed endpoint population.
	queue := []uint32{}
	for _, asn := range nodes {
		if indegree[asn] == 0 {
			queue = append(queue, asn)
		}
	}
	processed := 0
	for head := 0; head < len(queue); head++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		processed++
		for _, child := range customers[queue[head]] {
			indegree[child]--
			if indegree[child] == 0 {
				queue = append(queue, child)
			}
		}
	}
	if processed != len(nodes) {
		return out, nil
	}
	cone, degree := map[uint32]int{}, map[uint32]int{}
	conePopulation, degreePopulation := make([]int, 0, len(nodes)), make([]int, 0, len(nodes))
	work := 0
	for _, asn := range nodes {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		seen := map[uint32]struct{}{}
		stack := append([]uint32(nil), customers[asn]...)
		for len(stack) > 0 {
			work++
			if work > maxWork {
				return out, ErrGraphBudget
			}
			if work%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return out, err
				}
			}
			last := len(stack) - 1
			child := stack[last]
			stack = stack[:last]
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			stack = append(stack, customers[child]...)
		}
		cone[asn] = len(seen)
		degree[asn] = len(customers[asn]) + upstreams[asn]
		conePopulation = append(conePopulation, cone[asn])
		degreePopulation = append(degreePopulation, degree[asn])
	}
	p98 := func(values []int) int { sort.Ints(values); return values[int(math.Ceil(.98*float64(len(values))))-1] }
	coneThreshold, degreeThreshold := p98(conePopulation), p98(degreePopulation)
	pool := map[uint32]struct{}{}
	for _, asn := range nodes {
		if upstreams[asn] == 0 && cone[asn] > 0 && cone[asn] >= coneThreshold && degree[asn] >= degreeThreshold && len(visibility[asn]) >= 2 && !incidentUnknown[asn] {
			pool[asn] = struct{}{}
		}
	}
	for len(pool) >= 3 {
		threshold := int(math.Ceil(.80 * float64(len(pool)-1)))
		degrees := map[uint32]int{}
		lowest := int(^uint(0) >> 1)
		var remove uint32
		complete := true
		for asn := range pool {
			for other := range pool {
				if other != asn && relations.Relation(asn, other) == Peer {
					degrees[asn]++
				}
			}
			d := degrees[asn]
			if d < threshold {
				complete = false
			}
			if d < lowest || d == lowest && asn > remove {
				lowest, remove = d, asn
			}
		}
		if complete {
			break
		}
		delete(pool, remove)
	}
	if len(pool) < 3 {
		clear(pool)
	}
	for asn := range pool {
		out.RawCandidates[asn] = true
	}
	stableHistory := previous != nil && previous.Eligible && previous.PolicyHash == policyHash && publishedAt.Sub(previous.PublishedAt) >= 24*time.Hour && publishedAt.Sub(previous.PublishedAt) <= 720*time.Hour && now.Before(previous.PublishedAt.Add(720*time.Hour))
	out.Eligible = true
	out.Results = make([]Tier1Result, 0, len(nodes))
	for _, asn := range nodes {
		result := Tier1Result{ASN: asn, Class: "unknown", Stability: "unavailable", CustomerCone: uint32(cone[asn]), TransitDegree: uint32(degree[asn]), StatisticsKnown: true}
		if out.RawCandidates[asn] {
			result.Stability = "pending"
			if stableHistory && previous.RawCandidates[asn] {
				result.Class = "tier1_candidate"
				result.Stability = "stable"
			}
		} else if cone[asn] >= coneThreshold && degree[asn] >= degreeThreshold && upstreams[asn] > 0 {
			result.Class = "global_transit"
		} else if len(customers[asn]) > 0 {
			result.Class = "regional_transit"
		} else if upstreams[asn] > 0 {
			result.Class = "access_network"
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}
