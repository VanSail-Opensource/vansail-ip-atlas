package via3

import "encoding/json"

const (
	PublicObjectDecoded = 32 << 20
	PublicLiveDecoded   = 96 << 20
	PublicCacheDecoded  = 32 << 20
	PublicAnswerBytes   = 8 << 20
	PublicOrigins       = 4096
	PublicPathASNs      = 49152
)

func decodedSize(s *Shard) int {
	total := 0
	for _, section := range s.Sections {
		total += len(section.Data)
	}
	return total
}

// ValidatePublicProfile is narrower than the standalone VIA3 format inspector.
// Deployed objects must fit the common Go/browser profile and are repacked when
// they do not. No record, origin or path is silently truncated to fit a budget.
func ValidatePublicProfile(s Shard) error {
	if decodedSize(&s) > PublicObjectDecoded {
		return fail("resource_limit")
	}
	if s.Kind == 4 || s.Kind == 10 {
		records, width := s.Rows(3)
		for p := 0; p < len(records); p += width {
			if u32(records, p+8) > PublicOrigins {
				return fail("resource_limit")
			}
		}
	}
	return nil
}

type answerBudget struct{ bytes, paths, origins int }

func newAnswerBudget() *answerBudget { return &answerBudget{bytes: 1024} }
func (b *answerBudget) charge(bytes int) error {
	if bytes < 0 || bytes > PublicAnswerBytes-b.bytes {
		return fail("resource_limit")
	}
	b.bytes += bytes
	return nil
}
func (b *answerBudget) path(count int) error {
	if count > PublicPathASNs-b.paths {
		return fail("resource_limit")
	}
	b.paths += count
	return b.charge(16*count + 128)
}
func (b *answerBudget) cellOrigins(count int) error {
	if count > PublicOrigins-b.origins {
		return fail("resource_limit")
	}
	b.origins += count
	return b.charge(16 * count)
}
func answerFits(value any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(bytes) > PublicAnswerBytes {
		return fail("resource_limit")
	}
	return nil
}

func (r *Release) beginQuery() {
	r.endQuery()
}

func (r *Release) releaseReference(reference *objectReference) {
	if !reference.query && !reference.cache && !reference.router {
		r.residentBytes -= reference.size
		if reference.onsite != nil && reference.shard != nil {
			extra := reference.prefixLabelBytes
			if graph := reference.shard.lookup.graphIndex; graph != nil {
				extra += graph.bytes
			}
			r.countNativeMetadata(-extra)
		}
		reference.size = 0
		if reference.onsite != nil && reference.shard != nil {
			r.native.release(reference.onsite)
		}
		reference.prefixLabelBytes = 0
		reference.shard = nil
	}
}
func (r *Release) endQuery() {
	if r.native != nil {
		r.native.pages.next()
	}
	for _, reference := range r.usedReferences {
		reference.query = false
		r.releaseReference(reference)
	}
	// The backing array must not retain an evicted shard indirectly through a
	// slot added only for this query. Slots retain no decoded pointer unpinned.
	clear(r.usedReferences)
	r.usedReferences = r.usedReferences[:0]
	r.activeBytes = 0
}
func (r *Release) evictReference(reference *objectReference) {
	if !reference.cache {
		return
	}
	if reference.previous == nil {
		r.cacheHead = reference.next
	} else {
		reference.previous.next = reference.next
	}
	if reference.next == nil {
		r.cacheTail = reference.previous
	} else {
		reference.next.previous = reference.previous
	}
	reference.previous, reference.next = nil, nil
	r.cacheBytes -= reference.size
	reference.cache = false
	r.releaseReference(reference)
}
func (r *Release) admitReference(reference *objectReference, size int) error {
	if size < 0 || size > PublicObjectDecoded {
		return fail("resource_limit")
	}
	resident := reference.query || reference.cache || reference.router
	if resident && reference.size != size {
		return fail("record")
	}
	if reference.query {
		return nil
	}
	for !resident && size > PublicLiveDecoded-r.residentBytes && r.cacheHead != nil {
		r.evictReference(r.cacheHead)
	}
	if !resident && size > PublicLiveDecoded-r.residentBytes {
		r.releaseRouterASNs()
	}
	if !resident && size > PublicLiveDecoded-r.residentBytes {
		// Optional formatting metadata must never crowd a required decoded
		// object out of an otherwise valid query. Returned strings are immutable
		// copies, so dropping the shard's headers cannot invalidate an answer.
		for _, pinned := range r.usedReferences {
			r.releasePrefixMetadata(pinned)
			r.releaseGraphMetadata(pinned)
			if size <= PublicLiveDecoded-r.residentBytes {
				break
			}
		}
	}
	if !resident && size > PublicLiveDecoded-r.residentBytes {
		return fail("resource_limit")
	}
	if !resident {
		reference.size = size
		r.residentBytes += size
	}
	reference.query = true
	r.usedReferences = append(r.usedReferences, reference)
	r.activeBytes += size
	return nil
}

func (r *Release) releasePrefixMetadata(reference *objectReference) {
	size := reference.prefixLabelBytes
	if size == 0 {
		return
	}
	r.countNativeMetadata(-size)
	reference.prefixLabelBytes = 0
	reference.size -= size
	r.residentBytes -= size
	if reference.query {
		r.activeBytes -= size
	}
	if reference.cache {
		r.cacheBytes -= size
	}
	reference.shard.lookup.prefixLabels = nil
	reference.shard.lookup.prefixSpans = nil
}

// This optional derived metadata is installed only while a newly decoded
// object is query-pinned and before it enters the cache. Failure is a formatting
// fallback, never a relaxation of the original decoded-object or query limits.
func (r *Release) reservePrefixMetadata(reference *objectReference, size int) bool {
	if !reference.query || reference.cache || size <= 0 || size > PublicObjectDecoded-reference.size || size > PublicCacheDecoded-reference.size {
		return false
	}
	for size > PublicLiveDecoded-r.residentBytes && r.cacheHead != nil {
		r.evictReference(r.cacheHead)
	}
	if size > PublicLiveDecoded-r.residentBytes {
		return false
	}
	reference.size += size
	r.residentBytes += size
	r.activeBytes += size
	return true
}
func (r *Release) cacheReference(reference *objectReference) {
	if reference.cache {
		return
	}
	for r.cacheBytes+reference.size > PublicCacheDecoded && r.cacheHead != nil {
		r.evictReference(r.cacheHead)
	}
	reference.previous = r.cacheTail
	if r.cacheTail == nil {
		r.cacheHead = reference
	} else {
		r.cacheTail.next = reference
	}
	r.cacheTail = reference
	reference.cache = true
	r.cacheBytes += reference.size
}
