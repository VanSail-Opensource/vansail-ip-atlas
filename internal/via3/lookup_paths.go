package via3

import "slices"

// Each origin retains at most twelve source paths. Plan their disjoint answer
// ranges before allocating so repeated path rows need only two backing arrays.
func (s *Shard) appendOriginPaths(paths []PathAnswer, asn uint32, budget *answerBudget) ([]PathAnswer, error) {
	first, end, ok := s.asnBounds(asn)
	if !ok {
		return paths, nil
	}
	const maxPaths = 12
	if end-first > maxPaths {
		return paths, fail("record")
	}
	type layout struct {
		row, segments []byte
		asns          int
	}
	var planned [maxPaths]layout
	count, totalASNs, totalSegments := 0, 0, 0
	var limitErr error
	segments, _ := s.Rows(9)
	ints, _ := s.Rows(4)
plan:
	for ordinal := first; ordinal < end; ordinal++ {
		row := s.Record(ordinal)
		start := int(u32(row, 8))
		n := int(u16(row, 12))
		segs := segments[start*12 : (start+n)*12]
		pathASNs := 0
		for off := 0; off < len(segs); off += 12 {
			length := int(u32(segs, off+8))
			if limitErr = budget.path(length); limitErr != nil {
				break plan
			}
			pathASNs += length
		}
		planned[count] = layout{row, segs, pathASNs}
		count++
		totalASNs += pathASNs
		totalSegments += n
	}
	// Preserve preceding complete paths if charging a later path failed.
	paths = slices.Grow(paths, count)
	segmentValues := make([]SegmentAnswer, totalSegments)
	asnValues := make([]uint32, 2*totalASNs)
	for _, plan := range planned[:count] {
		count := len(plan.segments) / 12
		flat := asnValues[:plan.asns:plan.asns]
		structured := asnValues[plan.asns : 2*plan.asns : 2*plan.asns]
		asnValues = asnValues[2*plan.asns:]
		segments := segmentValues[:count:count]
		segmentValues = segmentValues[count:]
		path := PathAnswer{Origin: asn, ASNs: flat, Visibility: []string{"unknown", "low", "medium", "high"}[plan.row[15]], GraphEligible: plan.row[14]&1 != 0, Segments: segments}
		start := 0
		for index := range segments {
			row := plan.segments[index*12 : (index+1)*12]
			end := start + int(u32(row, 8))
			values := structured[start:end:end]
			offset := int(u32(row, 4)) * 4
			for i := range values {
				values[i] = u32(ints, offset+4*i)
			}
			segments[index] = SegmentAnswer{Type: []string{"", "sequence", "set", "confederation_sequence", "confederation_set"}[row[0]], ASNs: values}
			start = end
		}
		copy(flat, structured)
		paths = append(paths, path)
	}
	return paths, limitErr
}
