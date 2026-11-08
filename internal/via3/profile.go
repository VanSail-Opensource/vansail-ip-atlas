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
	if r.active == nil {
		r.active = make(map[string]bool)
	}
	if r.activeObjects == nil {
		r.activeObjects = make(map[string]*Shard)
	}
	r.activeBytes = 0
}

type resident struct {
	size                 int
	query, cache, router bool
}

func (r *Release) releaseResident(hash string) {
	entry := r.residents[hash]
	if entry != nil && !entry.query && !entry.cache && !entry.router {
		r.residentBytes -= entry.size
		delete(r.residents, hash)
	}
}
func (r *Release) endQuery() {
	for hash := range r.active {
		if entry := r.residents[hash]; entry != nil {
			entry.query = false
			r.releaseResident(hash)
		}
	}
	clear(r.active)
	clear(r.activeObjects)
	r.activeBytes = 0
}
func (r *Release) evictCache(hash string) {
	if object := r.cache[hash]; object != nil {
		r.cacheBytes -= decodedSize(object)
		delete(r.cache, hash)
	}
	if entry := r.residents[hash]; entry != nil {
		entry.cache = false
		r.releaseResident(hash)
	}
}
func (r *Release) admit(hash string, size int) error {
	if r.active[hash] {
		return nil
	}
	if size > PublicObjectDecoded {
		return fail("resource_limit")
	}
	if r.residents == nil {
		r.residents = make(map[string]*resident)
	}
	entry := r.residents[hash]
	if entry != nil && entry.size != size {
		return fail("record")
	}
	for entry == nil && size > PublicLiveDecoded-r.residentBytes && len(r.cacheOrder) > 0 {
		old := r.cacheOrder[0]
		r.cacheOrder = r.cacheOrder[1:]
		r.evictCache(old)
	}
	if entry == nil && size > PublicLiveDecoded-r.residentBytes {
		return fail("resource_limit")
	}
	if entry == nil {
		entry = &resident{size: size}
		r.residents[hash] = entry
		r.residentBytes += size
	}
	entry.query = true
	if r.active == nil {
		r.active = make(map[string]bool)
	}
	r.active[hash] = true
	r.activeBytes += size
	return nil
}
func (r *Release) cacheObject(hash string, s *Shard) {
	size := decodedSize(s)
	for r.cacheBytes+size > PublicCacheDecoded && len(r.cacheOrder) > 0 {
		old := r.cacheOrder[0]
		r.cacheOrder = r.cacheOrder[1:]
		r.evictCache(old)
	}
	r.cache[hash] = s
	r.cacheOrder = append(r.cacheOrder, hash)
	r.cacheBytes += size
	r.residents[hash].cache = true
}
