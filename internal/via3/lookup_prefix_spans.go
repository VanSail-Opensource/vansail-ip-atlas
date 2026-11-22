package via3

import "sort"

// A uint32 and a slice header occupy at most 32 bytes on supported platforms.
const prefixSpanHeaderBytes = 32

type cachedPrefixSpan struct {
	first  uint32
	labels []string
}

// Find the final span beginning no later than the requested starting prefix.
// No table proportional to the whole physical shard is allocated on a sparse
// access. A partially overlapping miss still formats the exact requested span.
func (s *Shard) cachedPrefixSpan(first, count uint32) []string {
	if s.lookup == nil || len(s.lookup.prefixSpans) == 0 {
		return nil
	}
	spans := s.lookup.prefixSpans
	i := sort.Search(len(spans), func(i int) bool { return spans[i].first > first }) - 1
	if i < 0 {
		return nil
	}
	start := first - spans[i].first
	if !rangeOK(start, count, len(spans[i].labels)) {
		return nil
	}
	return spans[i].labels[start : start+count]
}

// A string header occupies at most 16 bytes on supported platforms.
func prefixSpanBytes(labels []string) int {
	size := 16 * len(labels)
	for _, label := range labels {
		size += len(label)
	}
	return size
}

func (r *Release) chargeIndexedPrefixes(ref *objectReference, bytes int) {
	r.countNativeMetadata(bytes)
	ref.prefixLabelBytes += bytes
	ref.size += bytes
	r.cacheBytes += bytes
	r.activeBytes += bytes
	r.residentBytes += bytes
}

// Retain only the logical spans actually returned. Reserve peak old+new backing
// storage before growing the index; optional metadata never evicts cached data.
func (r *Release) retainPrefixSpan(ref *objectReference, first uint32, labels []string) {
	if !ref.query || !ref.cache || ref.shard == nil || ref.shard.lookup == nil {
		return
	}
	index := ref.shard.lookup
	spans := index.prefixSpans
	i := sort.Search(len(spans), func(i int) bool { return spans[i].first >= first })
	replace := i < len(spans) && spans[i].first == first
	if replace && len(spans[i].labels) >= len(labels) {
		return
	}
	newCapacity := 0
	if !replace && len(spans) == cap(spans) {
		newCapacity = max(1, 2*cap(spans))
	}
	extra := prefixSpanBytes(labels) + prefixSpanHeaderBytes*newCapacity
	if !r.mayKeepNativeMetadata(extra) || extra > PublicObjectDecoded-ref.size || extra > PublicCacheDecoded-r.cacheBytes || extra > PublicLiveDecoded-r.residentBytes {
		return
	}
	r.chargeIndexedPrefixes(ref, extra)
	released := 0
	if newCapacity != 0 {
		grown := make([]cachedPrefixSpan, len(spans), newCapacity)
		copy(grown, spans)
		released += prefixSpanHeaderBytes * cap(spans)
		spans = grown
	}
	if replace {
		released += prefixSpanBytes(spans[i].labels)
	} else {
		spans = spans[:len(spans)+1]
		copy(spans[i+1:], spans[i:])
	}
	owned := make([]string, len(labels))
	copy(owned, labels)
	spans[i] = cachedPrefixSpan{first, owned}
	index.prefixSpans = spans
	r.chargeIndexedPrefixes(ref, -released)
}
