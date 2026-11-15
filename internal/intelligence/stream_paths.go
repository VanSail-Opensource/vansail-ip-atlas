package intelligence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
)

func prepareRankedPath(p Path, visibility int, relations RelationResolver) Path {
	p.visibility = visibility
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
				if resolveRelation(relations, previous, asn) != UnknownRelation {
					p.known++
				}
			}
			previous = asn
		}
	}
	return p
}
func rankedPathLess(a, b Path) bool {

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
}

// PathGroupKey preserves the original canonical typed segment structure,
// including prepends, while ordering groups by their exact origin ASN.
func PathGroupKey(observation PathObservation) (string, error) {
	p, err := canonicalPath(observation)
	if err != nil {
		return "", err
	}
	key := binary.BigEndian.AppendUint32(nil, p.Origin)
	key = append(key, p.canonical...)
	return string(key), nil
}

// PathSelection keeps only the canonical best twelve distinct grouped paths
// for one origin. Family counts must come from correlated-family deduplication.
// It shares its comparator and relationship scoring with RankPaths.
type PathSelection struct {
	relations RelationResolver
	origin    uint32
	paths     []Path
}

func NewPathSelection(relations RelationResolver) *PathSelection {
	return &PathSelection{relations: relations}
}
func (s *PathSelection) Consider(observation PathObservation, families int) error {
	if !observation.Current || observation.Family == "" || families < 1 || families > 1000 {
		return errors.New("verified grouped path families required")
	}
	p, err := canonicalPath(observation)
	if err != nil {
		return err
	}
	if s.origin != 0 && s.origin != p.Origin {
		return errors.New("one origin per path selector required")
	}
	s.origin = p.Origin
	p = prepareRankedPath(p, families, s.relations)
	s.paths = append(s.paths, p)
	sort.Slice(s.paths, func(i, j int) bool { return rankedPathLess(s.paths[i], s.paths[j]) })
	if len(s.paths) > 12 {
		s.paths = s.paths[:12]
	}
	return nil
}
func (s *PathSelection) Paths() []Path { return append([]Path(nil), s.paths...) }
