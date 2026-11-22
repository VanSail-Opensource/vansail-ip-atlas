package via3

import (
	"crypto/sha256"
	"os"
)

const rowPageSize = 4096

type nativePage struct {
	data        []byte
	number      int
	epoch       uint64
	old, recent *nativePage
}

type nativePageEntry struct {
	digest [sha256.Size]byte
	page   *nativePage
}

type nativePages struct {
	owner                           *Release
	routerBytes, metadata, borrowed int
	file                            *os.File
	total                           int64
	dir                             []nativePageEntry // digest and optional cache slot for each private file page
	oldest, newest                  *nativePage
	epoch                           uint64
	pages, limit, live              int
	reads                           int
}

type nativeReadError struct{ err error }

func recoverNativeRead(err *error) {
	switch v := recover().(type) {
	case nil:
	case nativeReadError:
		*err = v.err
	default:
		panic(v)
	}
}

// The eager disk reader exposes only verified component rows. Keep borrowed
// page bytes immutable until endQuery; a caller's label may outlive many other
// component reads in the same query. The 96 MiB logical shard check also runs.
func (p *nativePages) unlink(page *nativePage) {
	if page.old == nil {
		p.oldest = page.recent
	} else {
		page.old.recent = page.recent
	}
	if page.recent == nil {
		p.newest = page.old
	} else {
		page.recent.old = page.old
	}
	page.old, page.recent = nil, nil
}
func (p *nativePages) append(page *nativePage) {
	page.old = p.newest
	if p.newest == nil {
		p.oldest = page
	} else {
		p.newest.recent = page
	}
	p.newest = page
}
func (p *nativePages) setMetadata(delta int) {
	p.metadata += delta
	p.limit = max(0, (PublicCacheDecoded-p.routerBytes-p.metadata)/rowPageSize)
	p.live = max(0, (PublicLiveDecoded-p.routerBytes-p.metadata)/rowPageSize)
}
func (r *Release) mayKeepNativeMetadata(size int) bool {
	if r.native == nil {
		return true
	}
	p := r.native.pages
	return size <= PublicLiveDecoded-p.routerBytes-p.metadata-p.borrowed-p.pages*rowPageSize
}
func (r *Release) countNativeMetadata(size int) {
	if r.native != nil {
		r.native.pages.setMetadata(size)
	}
}
func (p *nativePages) next() {
	p.epoch++
	p.borrowed = 0
	// Query-pinned pages occupied the newest end. Keep the declared cache
	// ceiling between queries, even after a legitimately larger working set.
	for p.pages > p.limit {
		page := p.oldest
		p.unlink(page)
		p.dir[page.number].page = nil
		p.pages--
	}
}

// Called only when all ordinary page evictions have failed to admit a
// required read. Optional indexes must not change which answers fit.
func (p *nativePages) reclaimOptional() {
	if p.owner != nil {
		p.owner.releaseRouterASNs()
	}
}

func (p *nativePages) page(number int) []byte {
	page := p.dir[number].page
	if page != nil {
		if page.epoch != p.epoch {
			p.unlink(page)
			p.append(page)
			page.epoch = p.epoch
		}
		return page.data
	}
	if (p.pages >= p.limit || (p.pages+1)*rowPageSize+p.borrowed > p.live*rowPageSize) && p.oldest != nil && p.oldest.epoch != p.epoch {
		page = p.oldest
		p.unlink(page)
		p.dir[page.number].page = nil
	} else {
		if (p.pages+1)*rowPageSize+p.borrowed > p.live*rowPageSize {
			p.reclaimOptional()
		}
		if (p.pages+1)*rowPageSize+p.borrowed > p.live*rowPageSize {
			panic(nativeReadError{fail("resource_limit")})
		}
		page = &nativePage{data: make([]byte, rowPageSize)}
		p.pages++
	}
	offset := int64(number) * rowPageSize
	length := min(int64(rowPageSize), p.total-offset)
	_, err := p.file.ReadAt(page.data[:length], offset)
	if err != nil {
		p.pages--
		panic(nativeReadError{err})
	}
	if sha256.Sum256(page.data[:length]) != p.dir[number].digest {
		p.pages--
		panic(nativeReadError{fail("integrity")})
	}
	page.number, page.epoch = number, p.epoch
	p.dir[number].page = page
	p.append(page)
	p.reads++
	return page.data
}
func (p *nativePages) span(offset int64, n int) []byte {
	if n == 0 {
		return nil
	}
	number, within := int(offset/rowPageSize), int(offset%rowPageSize)
	page := p.page(number)
	if n <= rowPageSize-within {
		return page[within : within+n]
	}
	// A vector or record can straddle two pages. The joined bytes are
	// borrowed for this operation and count against the same live ceiling.
	for n > p.live*rowPageSize-p.pages*rowPageSize-p.borrowed && p.oldest != nil && p.oldest.epoch != p.epoch {
		page := p.oldest
		p.unlink(page)
		p.dir[page.number].page = nil
		p.pages--
	}
	if n > p.live*rowPageSize-p.pages*rowPageSize-p.borrowed {
		p.reclaimOptional()
	}
	if n > p.live*rowPageSize-p.pages*rowPageSize-p.borrowed {
		panic(nativeReadError{fail("resource_limit")})
	}
	p.borrowed += n
	out := make([]byte, n)
	at := copy(out, page[within:])
	for at < n {
		number++
		at += copy(out[at:], p.page(number))
	}
	return out
}

func (s *Shard) rowCount(id uint16) int {
	if s.disk != nil {
		w := s.lookup.widths[id]
		if w == 0 {
			return 0
		}
		return (s.disk.sections[id].size - 8) / w
	}
	rows, w := s.Rows(id)
	if w == 0 {
		return 0
	}
	return len(rows) / w
}
func (s *Shard) row(id uint16, i uint32) []byte { return s.rowSpan(id, i, 1) }
func (s *Shard) rowSpan(id uint16, first, count uint32) []byte {
	if count == 0 {
		return nil
	}
	if s.disk != nil {
		w := s.lookup.widths[id]
		return s.disk.pages.span(s.disk.base+int64(s.disk.sections[id].offset+8)+int64(first)*int64(w), int(count)*w)
	}
	rows, w := s.Rows(id)
	return rows[int(first)*w : (int(first)+int(count))*w]
}
func (s *Shard) parent(section int, ordinal uint32) uint32 {
	if s.disk != nil {
		return u32(s.disk.pages.span(s.disk.base+int64(s.disk.parents[section].offset)+int64(ordinal)*4, 4), 0)
	}
	return s.lookup.prefixes[section].parents[ordinal]
}
