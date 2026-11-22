package via3

import (
	"bytes"
	"sort"
)

const prefixBlockRows = rowPageSize / 32
const asnBlockRows = rowPageSize / 8

// These optional directories hold just the first key of each aligned page.
// When the complete set would use the remaining cache allowance, the same
// binary search reads the first key directly from the authenticated page.
func (index *nativeIndex) reserveFence(bytes int) bool {
	if bytes > index.fenceBudget-index.fenceBytes {
		return false
	}
	index.fenceBytes += bytes
	return true
}
func pageCount(first, end, n uint32) int {
	if first == end {
		return 0
	}
	return int((end-1)/n - first/n + 1)
}
func blockFirst(first uint32, block int, n uint32) uint32 {
	return max(first, (first/n+uint32(block))*n)
}
func (d *indexedShard) buildFences(s *Shard, index *nativeIndex) {
	for k, id := range []uint16{1, 8} {
		rows := s.lookup.rows[id]
		if s.Kind == 9 {
			n := pageCount(0, uint32(len(rows)/32), prefixBlockRows)
			if n > 1 && index.reserveFence(n*20) {
				keys := make([][20]byte, n)
				for i := range keys {
					copy(keys[i][:], rows[i*rowPageSize:i*rowPageSize+20])
				}
				d.rpkiFences[k] = keys
			}
			continue
		}
		bounds := s.lookup.prefixes[k].families
		for family := 0; family < 2; family++ {
			first, end := bounds[family], bounds[family+1]
			n := pageCount(first, end, prefixBlockRows)
			if n <= 1 || !index.reserveFence(n*16) {
				continue
			}
			keys := make([][16]byte, n)
			for i := range keys {
				at := int(blockFirst(first, i, prefixBlockRows)) * 32
				copy(keys[i][:], rows[at+4:at+20])
			}
			d.prefixFences[k][family] = keys
		}
	}
	rows := s.lookup.rows[2]
	n := pageCount(0, uint32(len(rows)/8), asnBlockRows)
	if n > 1 && index.reserveFence(n*4) {
		d.asnFences = make([]uint32, n)
		for i := range d.asnFences {
			d.asnFences[i] = u32(rows, i*rowPageSize)
		}
	}
}

func (s *Shard) prefixBlock(section, family int, id uint16, addr [16]byte, first, end uint32) ([]byte, uint32) {
	if s.disk == nil {
		rows := s.lookup.rows[id]
		return rows[int(first)*32 : int(end)*32], first
	}
	n := pageCount(first, end, prefixBlockRows)
	if n > 1 {
		keys := s.disk.prefixFences[section][family]
		block := sort.Search(n, func(i int) bool {
			if len(keys) != 0 {
				return bytes.Compare(keys[i][:], addr[:]) > 0
			}
			return bytes.Compare(s.row(id, blockFirst(first, i, prefixBlockRows))[4:20], addr[:]) > 0
		}) - 1
		if block < 0 {
			return nil, first
		}
		first = blockFirst(first, block, prefixBlockRows)
		end = min(end, (first/prefixBlockRows+1)*prefixBlockRows)
	}
	return s.rowSpan(id, first, end-first), first
}

func (s *Shard) asnBlock(asn uint32) ([]byte, uint32) {
	if s.disk == nil {
		rows, _ := s.Rows(2)
		return rows, 0
	}
	count := uint32(s.rowCount(2))
	n := pageCount(0, count, asnBlockRows)
	var start uint32
	if n > 1 {
		keys := s.disk.asnFences
		block := sort.Search(n, func(i int) bool {
			if len(keys) > 0 {
				return keys[i] > asn
			}
			return u32(s.row(2, uint32(i)*asnBlockRows), 0) > asn
		}) - 1
		if block < 0 {
			return nil, 0
		}
		start = uint32(block) * asnBlockRows
	}
	return s.rowSpan(2, start, min(uint32(asnBlockRows), count-start)), start
}

func (s *Shard) rpkiBound(section int, id uint16, key []byte, upper bool) int {
	count := s.rowCount(id)
	start, end := 0, count
	if s.disk != nil {
		n := pageCount(0, uint32(count), prefixBlockRows)
		if n > 1 {
			keys := s.disk.rpkiFences[section]
			block := sort.Search(n, func(i int) bool {
				var row []byte
				if len(keys) > 0 {
					row = keys[i][:]
				} else {
					row = s.row(id, uint32(i)*prefixBlockRows)
				}
				c := keyCompare(row, key)
				return c > 0 || c == 0 && !upper
			}) - 1
			start = max(0, block) * prefixBlockRows
			end = min(count, start+prefixBlockRows)
		}
	}
	rows := s.rowSpan(id, uint32(start), uint32(end-start))
	return start + sort.Search(end-start, func(i int) bool { v := keyCompare(rows[i*32:(i+1)*32], key); return v > 0 || v == 0 && !upper })
}

// Drop the directory before a required live row page would otherwise fail.
// Its original sorted vectors provide identical page selection on fallback.
func (r *Release) releaseNativeFences() {
	if r.native == nil || r.native.fenceBytes == 0 {
		return
	}
	for _, ref := range r.references {
		if d := ref.onsite; d != nil {
			d.prefixFences = [2][2][][16]byte{}
			d.rpkiFences = [2][][20]byte{}
			d.asnFences = nil
		}
	}
	r.native.pages.setMetadata(-r.native.fenceBytes)
	r.native.fenceBytes = 0
}
