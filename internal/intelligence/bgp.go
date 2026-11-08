package intelligence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"

	"vansail-ip-atlas/internal/facts"
)

type RPKIStatus string

// IsPublicASN matches the shared query/data contract, including reserved blocks.
func IsPublicASN(asn uint32) bool { return facts.PublicASN(asn) }

const (
	RPKIUnknown  RPKIStatus = "unknown"
	RPKIValid    RPKIStatus = "valid"
	RPKIInvalid  RPKIStatus = "invalid"
	RPKINotFound RPKIStatus = "not_found"
)

type VRP struct {
	Prefix    netip.Prefix
	MaxLength uint8
	ASN       uint32
}
type VRPIndex struct {
	records map[netip.Prefix][]VRP
	current bool
}

func NewVRPIndex(records []VRP, current bool) (*VRPIndex, error) {
	index := &VRPIndex{records: map[netip.Prefix][]VRP{}, current: current}
	for _, v := range records {
		if !v.Prefix.IsValid() || v.MaxLength < uint8(v.Prefix.Bits()) || int(v.MaxLength) > v.Prefix.Addr().BitLen() || v.ASN != 0 && !IsPublicASN(v.ASN) {
			return nil, errors.New("invalid VRP prefix length")
		}
		key := v.Prefix.Masked()
		v.Prefix = key
		index.records[key] = append(index.records[key], v)
	}
	return index, nil
}
func (v *VRPIndex) Validate(prefix netip.Prefix, origin uint32) RPKIStatus {
	if v == nil || !v.current || !prefix.IsValid() || origin == 0 {
		return RPKIUnknown
	}
	prefix = prefix.Masked()
	covering := false
	for bits := prefix.Bits(); bits >= 0; bits-- {
		key := netip.PrefixFrom(prefix.Addr(), bits).Masked()
		for _, roa := range v.records[key] {
			covering = true
			if roa.ASN == origin && prefix.Bits() <= int(roa.MaxLength) {
				return RPKIValid
			}
		}
	}
	if covering {
		return RPKIInvalid
	}
	return RPKINotFound
}

type Relation uint8

const (
	UnknownRelation Relation = iota
	TransitUpstream
	Peer
	Customer
	Sibling
)

func (r Relation) String() string {
	switch r {
	case TransitUpstream:
		return "transit_upstream"
	case Peer:
		return "peer"
	case Customer:
		return "customer"
	case Sibling:
		return "sibling"
	default:
		return "unknown"
	}
}

type ASNEdge struct{ From, To uint32 }
type RelationshipIndex struct {
	edges     map[ASNEdge]Relation
	conflicts map[ASNEdge]bool
	nodes     map[uint32]struct{}
	current   bool
}

func NewRelationships(current bool) *RelationshipIndex {
	return &RelationshipIndex{edges: map[ASNEdge]Relation{}, conflicts: map[ASNEdge]bool{}, nodes: map[uint32]struct{}{}, current: current}
}

// Add's relation is from A's perspective. Customer means A provides transit to B.
func (r *RelationshipIndex) Add(a, b uint32, relation Relation) error {
	if !IsPublicASN(a) || !IsPublicASN(b) || a == b || relation < TransitUpstream || relation > Sibling {
		return errors.New("invalid directed relationship")
	}
	r.nodes[a] = struct{}{}
	r.nodes[b] = struct{}{}
	reverse := relation
	if relation == Customer {
		reverse = TransitUpstream
	} else if relation == TransitUpstream {
		reverse = Customer
	}
	for _, item := range []struct {
		edge     ASNEdge
		relation Relation
	}{{ASNEdge{a, b}, relation}, {ASNEdge{b, a}, reverse}} {
		if old, ok := r.edges[item.edge]; ok && old != item.relation {
			r.conflicts[item.edge] = true
		}
		if r.conflicts[item.edge] {
			r.edges[item.edge] = UnknownRelation
		} else {
			r.edges[item.edge] = item.relation
		}
	}
	return nil
}
func (r *RelationshipIndex) Relation(a, b uint32) Relation {
	if r == nil || !r.current {
		return UnknownRelation
	}
	return r.edges[ASNEdge{a, b}]
}

type SegmentType uint8

const (
	ASSequence            SegmentType = 1
	ASSet                 SegmentType = 2
	ConfederationSequence SegmentType = 3
	ConfederationSet      SegmentType = 4
)

type PathSegment struct {
	Type SegmentType
	ASNs []uint32
}
type PathObservation struct {
	Origin                 uint32
	Segments               []PathSegment
	Family                 string
	Current, OriginOutward bool
}
type Path struct {
	Origin                           uint32
	Segments                         []PathSegment
	GraphEligible                    bool
	VisibilityBand                   uint8
	known, total, length, visibility int
	canonical                        []byte
}

func canonicalPath(v PathObservation) (Path, error) {
	if v.Origin == 0 || len(v.Segments) == 0 || len(v.Segments) > 255 {
		return Path{}, errors.New("bounded typed path required")
	}
	path := Path{Origin: v.Origin, GraphEligible: true}
	seen := map[uint32]bool{}
	previous := uint32(0)
	segments := v.Segments
	if !v.OriginOutward {
		segments = append([]PathSegment(nil), segments...)
		for i, j := 0, len(segments)-1; i < j; i, j = i+1, j-1 {
			segments[i], segments[j] = segments[j], segments[i]
		}
	}
	for _, segment := range segments {
		if segment.Type < ASSequence || segment.Type > ConfederationSet || len(segment.ASNs) == 0 {
			return Path{}, errors.New("unknown or empty AS path segment")
		}
		copy := PathSegment{Type: segment.Type, ASNs: append([]uint32(nil), segment.ASNs...)}
		path.length += len(copy.ASNs)
		if path.length > 4096 {
			return Path{}, errors.New("path ASN budget exceeded")
		}
		if copy.Type == ASSet || copy.Type == ConfederationSet {
			sort.Slice(copy.ASNs, func(i, j int) bool { return copy.ASNs[i] < copy.ASNs[j] })
			copy.ASNs = uniqueASNs(copy.ASNs)
		} else if !v.OriginOutward {
			for i, j := 0, len(copy.ASNs)-1; i < j; i, j = i+1, j-1 {
				copy.ASNs[i], copy.ASNs[j] = copy.ASNs[j], copy.ASNs[i]
			}
		}
		if copy.Type != ASSequence {
			path.GraphEligible = false
		}
		for _, asn := range copy.ASNs {
			if asn == 0 {
				return Path{}, errors.New("zero ASN in observed path")
			}
			if !IsPublicASN(asn) {
				path.GraphEligible = false
			}
			if asn != previous && seen[asn] {
				path.GraphEligible = false
			}
			seen[asn] = true
			previous = asn
		}
		path.Segments = append(path.Segments, copy)
		path.canonical = append(path.canonical, byte(copy.Type))
		path.canonical = binary.LittleEndian.AppendUint16(path.canonical, uint16(len(copy.ASNs)))
		for _, asn := range copy.ASNs {
			path.canonical = binary.LittleEndian.AppendUint32(path.canonical, asn)
		}
	}
	if path.GraphEligible && (len(path.Segments[0].ASNs) == 0 || path.Segments[0].ASNs[0] != path.Origin) {
		return Path{}, errors.New("origin does not match path orientation")
	}
	return path, nil
}
func RankPaths(observations []PathObservation, relations *RelationshipIndex) ([]Path, error) {
	if len(observations) > 100000 {
		return nil, errors.New("path partition budget exceeded")
	}
	type grouped struct {
		path     Path
		families map[string]struct{}
	}
	groups := map[string]*grouped{}
	for _, v := range observations {
		if !v.Current {
			continue
		}
		if v.Family == "" {
			return nil, errors.New("private path family required")
		}
		path, err := canonicalPath(v)
		if err != nil {
			return nil, err
		}
		key := string(binary.LittleEndian.AppendUint32(nil, path.Origin)) + string(path.canonical)
		group := groups[key]
		if group == nil {
			group = &grouped{path: path, families: map[string]struct{}{}}
			groups[key] = group
		}
		group.families[v.Family] = struct{}{}
	}
	paths := make([]Path, 0, len(groups))
	for _, g := range groups {
		p := g.path
		p.visibility = len(g.families)
		if p.visibility >= 3 {
			p.VisibilityBand = 3
		} else if p.visibility == 2 {
			p.VisibilityBand = 2
		} else {
			p.VisibilityBand = 1
		}
		previous := uint32(0)
		for _, segment := range p.Segments {
			if segment.Type != ASSequence {
				previous = 0
				continue
			}
			for _, asn := range segment.ASNs {
				if previous != 0 && previous != asn {
					p.total++
					if relations.Relation(previous, asn) != UnknownRelation {
						p.known++
					}
				}
				previous = asn
			}
		}
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		ad, bd := a.total, b.total
		if ad == 0 {
			ad = 1
		}
		if bd == 0 {
			bd = 1
		}
		if a.known*bd != b.known*ad {
			return a.known*bd > b.known*ad
		}
		if a.length != b.length {
			return a.length < b.length
		}
		if a.visibility != b.visibility {
			return a.visibility > b.visibility
		}
		return bytes.Compare(a.canonical, b.canonical) < 0
	})
	out := paths[:0]
	counts := map[uint32]int{}
	for _, p := range paths {
		if counts[p.Origin] < 12 {
			out = append(out, p)
			counts[p.Origin]++
		}
	}
	return out, nil
}

type ProjectedRoute struct {
	PathIndex         int
	Nodes             []uint32
	OriginalPositions []uint16
	Truncated         bool
}
type GraphEdge struct {
	From, To                        uint32
	Relation                        string
	Observed, RelationshipSupported bool
}
type Graph struct {
	Nodes     []uint32
	Edges     []GraphEdge
	Routes    []ProjectedRoute
	Truncated bool
}

func ProjectGraph(paths []Path, relations *RelationshipIndex) Graph {
	result := Graph{}
	protected := map[uint32]struct{}{}
	selected := []ProjectedRoute{}
	for i, path := range paths {
		if !path.GraphEligible {
			continue
		}
		route := ProjectedRoute{PathIndex: i}
		position := uint16(0)
		for _, segment := range path.Segments {
			for _, asn := range segment.ASNs {
				if len(route.Nodes) == 0 || route.Nodes[len(route.Nodes)-1] != asn {
					route.Nodes = append(route.Nodes, asn)
					route.OriginalPositions = append(route.OriginalPositions, position)
				}
				position++
			}
		}
		additional := 0
		for _, asn := range route.Nodes[:min(3, len(route.Nodes))] {
			if _, ok := protected[asn]; !ok {
				additional++
			}
		}
		if len(protected)+additional > 24 {
			result.Truncated = true
			continue
		}
		for _, asn := range route.Nodes[:min(3, len(route.Nodes))] {
			protected[asn] = struct{}{}
		}
		selected = append(selected, route)
	}
	nodes := protected
	exits := map[uint32]map[uint32]struct{}{}
	edges := map[ASNEdge]GraphEdge{}
	for _, route := range selected {
		visible := min(3, len(route.Nodes))
		for i := 3; i < len(route.Nodes); i++ {
			asn := route.Nodes[i]
			if _, ok := nodes[asn]; !ok && len(nodes) >= 24 {
				break
			}
			if i == 3 {
				second := route.Nodes[2]
				if exits[second] == nil {
					exits[second] = map[uint32]struct{}{}
				}
				if _, ok := exits[second][asn]; !ok && len(exits[second]) >= 3 {
					break
				}
				exits[second][asn] = struct{}{}
			}
			nodes[asn] = struct{}{}
			visible++
		}
		route.Truncated = visible < len(route.Nodes)
		result.Truncated = result.Truncated || route.Truncated
		route.Nodes = route.Nodes[:visible]
		route.OriginalPositions = route.OriginalPositions[:visible]
		for i := 1; i < len(route.Nodes); i++ {
			key := ASNEdge{route.Nodes[i-1], route.Nodes[i]}
			relation := relations.Relation(key.From, key.To)
			edges[key] = GraphEdge{key.From, key.To, relation.String(), true, relation != UnknownRelation}
		}
		result.Routes = append(result.Routes, route)
	}
	for asn := range nodes {
		result.Nodes = append(result.Nodes, asn)
	}
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i] < result.Nodes[j] })
	for _, edge := range edges {
		result.Edges = append(result.Edges, edge)
	}
	sort.Slice(result.Edges, func(i, j int) bool {
		a, b := result.Edges[i], result.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return result
}
