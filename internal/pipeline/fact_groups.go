package pipeline

import (
	"errors"
	"net/netip"
)

// A group is private packing metadata, never part of a public partition label.
// Keep cross-kind compiler validation and references in the same bounded leaf:
// geo/coordinates/usage validate anycast together; profile cells refer to the
// exact network object and record ordinal. The other kinds are independent.
type factGroup uint8

const (
	allFacts factGroup = iota // direct low-level partition tests only
	locationFacts
	networkFacts
	qualityFacts
	rpkiFacts
	originFacts
	aggregateFacts
	pathFacts
	relationshipFacts
	tierFacts
	factGroupCount = int(tierFacts)
)

func groupForKind(kind uint16) factGroup {
	switch kind {
	case 2, 3, 5:
		return locationFacts
	case 4, 7:
		return networkFacts
	case 6:
		return qualityFacts
	case 9:
		return rpkiFacts
	case 10:
		return originFacts
	case 8:
		return aggregateFacts
	case 11:
		return pathFacts
	case 12:
		return relationshipFacts
	case 13:
		return tierFacts
	default:
		return allFacts
	}
}

func (g factGroup) contains(kind uint16) bool {
	return groupForKind(kind) != allFacts && (g == allFacts || groupForKind(kind) == g)
}

type classifiedRun struct {
	path string
	scope
}

func classifiedScope(index int) scope {
	s := scope{group: factGroup(index%factGroupCount + 1)}
	switch index / factGroupCount {
	case 0:
		s.prefix = netip.MustParsePrefix("0.0.0.0/0")
	case 1:
		s.prefix = netip.MustParsePrefix("::/0")
	case 2:
		s.asn, s.last = true, ^uint32(0)
	default:
		panic("invalid private fact group index")
	}
	return s
}

var errFactGroup = errors.New("private partition fact group mismatch")
