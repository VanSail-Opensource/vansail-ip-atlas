package intelligence

import "errors"

const (
	maxMRTReplayUpdates = 1_000_000
	maxMRTReplayBytes   = 128 << 20
)

var errMRTReplayCold = errors.New("MRT replay requires a complete cold snapshot")

func replayRouteBytes(record MRTUpdate) int {
	// Includes changed-route map/key/value and sorted-key overhead. Full-run
	// RSS remains a measured acceptance gate rather than a count assertion.
	total := 512
	for _, segment := range record.Segments {
		total += 32 + 4*len(segment.ASNs)
	}
	return total
}

func cloneReplayRoute(record MRTUpdate) MRTUpdate {
	segments := make([]PathSegment, len(record.Segments))
	for i, segment := range record.Segments {
		segments[i] = PathSegment{Type: segment.Type, ASNs: append([]uint32(nil), segment.ASNs...)}
	}
	record.Segments = segments
	return record
}
