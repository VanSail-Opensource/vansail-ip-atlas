package via3

import (
	"net/netip"
	"strings"
)

// An immutable spelling per validated announced prefix keeps a caller's first
// or continuation page from reformatting the same address on every lookup.
func appendPrefixText(dst []byte, key []byte) []byte {
	address, _ := keyAddr(key)
	return netip.PrefixFrom(address, int(key[1])).AppendTo(dst)
}

func prefixTextSize(rows []byte) int {
	var buffer [43]byte
	size := 0
	for i := 0; i < len(rows); i += 24 {
		size += len(appendPrefixText(buffer[:0], rows[i:i+24]))
	}
	return size
}
func writePrefixText(w *nativeIndexWriter, rows []byte) error {
	var label [43]byte
	var offset [4]byte
	sum := uint32(0)
	for i := 0; i < len(rows); i += 24 {
		p32(offset[:], 0, sum)
		if err := w.write(offset[:]); err != nil {
			return err
		}
		sum += uint32(len(appendPrefixText(label[:0], rows[i:i+24])))
	}
	p32(offset[:], 0, sum)
	if err := w.write(offset[:]); err != nil {
		return err
	}
	for i := 0; i < len(rows); i += 24 {
		if err := w.write(appendPrefixText(label[:0], rows[i:i+24])); err != nil {
			return err
		}
	}
	return nil
}
func (d *indexedShard) prefixStrings(first, count uint32, out []string) {
	offsets := d.pages.span(d.base+int64(d.prefixOffsets.offset)+int64(first)*4, (int(count)+1)*4)
	start, end := u32(offsets, 0), u32(offsets, int(count)*4)
	// Only the requested characters escape the private page cache. Every
	// returned string header belongs to this caller's mutable result slice.
	text := d.pages.text(d.base+int64(d.prefixText.offset)+int64(start), int(end-start))
	for i := range out {
		out[i] = text[u32(offsets, i*4)-start : u32(offsets, (i+1)*4)-start]
	}
}

// Copy just the requested text into an immutable caller-owned string. A
// cross-page request streams straight into its final string allocation.
func (p *nativePages) text(offset int64, n int) string {
	if n == 0 {
		return ""
	}
	number, within := int(offset/rowPageSize), int(offset%rowPageSize)
	first := p.page(number)
	if n <= rowPageSize-within {
		return string(first[within : within+n])
	}
	var out strings.Builder
	out.Grow(n)
	out.Write(first[within:])
	for out.Len() < n {
		number++
		part := p.page(number)
		out.Write(part[:min(len(part), n-out.Len())])
	}
	return out.String()
}
