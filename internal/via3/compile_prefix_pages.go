package via3

import "sort"

const (
	prefixPageSize      = 256
	prefixPackingWindow = 32
	prefixObjectRows    = 2048
)

type prefixPageSpan struct {
	object       *BuiltObject
	first, count uint32
}

type ownedPrefix struct {
	asn uint32
	key []byte
}

type prefixSpanPlacement struct {
	asn                                         uint32
	rows                                        [][]byte
	logicalFirst, physicalObject, physicalFirst int
}

type prefixLogicalPage struct {
	rows  [][]byte
	spans []prefixSpanPlacement
}

type prefixPagePacker struct {
	pending []ownedPrefix
	window  []prefixLogicalPage
	byASN   map[uint32][]prefixPageSpan
	write   func([][]byte) (BuiltObject, error)
}

func (p *prefixPagePacker) append(asn uint32, key []byte) error {
	p.pending = append(p.pending, ownedPrefix{asn, key})
	if len(p.pending) < prefixPageSize {
		return nil
	}
	p.endPage()
	if len(p.window) == prefixPackingWindow {
		return p.writeWindow()
	}
	return nil
}

func (p *prefixPagePacker) finish() error {
	if len(p.pending) != 0 {
		p.endPage()
	}
	return p.writeWindow()
}

// Preserve each ASN's logical cursor boundaries, including gaps where another
// owner's prefix falls between two of its prefixes in the canonical order.
func (p *prefixPagePacker) endPage() {
	sort.Slice(p.pending, func(i, j int) bool {
		a, b := p.pending[i], p.pending[j]
		if order := keyCompare(a.key, b.key); order != 0 {
			return order < 0
		}
		return a.asn < b.asn
	})
	page := prefixLogicalPage{rows: make([][]byte, 0, len(p.pending))}
	lastSpan := make(map[uint32]int)
	for _, value := range p.pending {
		if len(page.rows) == 0 || keyCompare(page.rows[len(page.rows)-1], value.key) != 0 {
			// PrefixKey was created with record ordinal zero. Its first 24 bytes
			// are the canonical section-11 row.
			page.rows = append(page.rows, value.key[:24:24])
		}
		index := len(page.rows) - 1
		if n, ok := lastSpan[value.asn]; ok {
			span := &page.spans[n]
			end := span.logicalFirst + len(span.rows)
			if index == end-1 {
				continue
			}
			if index == end {
				span.rows = page.rows[span.logicalFirst : index+1]
				continue
			}
		}
		lastSpan[value.asn] = len(page.spans)
		page.spans = append(page.spans, prefixSpanPlacement{asn: value.asn, logicalFirst: index, rows: page.rows[index : index+1]})
	}
	p.window = append(p.window, page)
	p.pending = p.pending[:0]
}

// Put complete spans into globally sorted physical objects. A shared boundary
// prefix occupies one row and is referenced by both owners. If overlapping
// ranges would use as many objects as the original layout, keep that layout.
func packedPrefixObjects(window []prefixLogicalPage) [][][]byte {
	var spans []*prefixSpanPlacement
	for i := range window {
		for j := range window[i].spans {
			spans = append(spans, &window[i].spans[j])
		}
	}
	sort.SliceStable(spans, func(i, j int) bool {
		a, b := spans[i].rows, spans[j].rows
		if order := keyCompare(a[0], b[0]); order != 0 {
			return order < 0
		}
		return keyCompare(a[len(a)-1], b[len(b)-1]) < 0
	})
	var objects [][][]byte
nextSpan:
	for _, span := range spans {
		for i, rows := range objects {
			order := keyCompare(rows[len(rows)-1], span.rows[0])
			if order > 0 {
				continue
			}
			first, skip := len(rows), 0
			if order == 0 {
				first--
				skip++
			}
			if first+len(span.rows) > prefixObjectRows {
				continue
			}
			span.physicalObject, span.physicalFirst = i, first
			objects[i] = append(rows, span.rows[skip:]...)
			continue nextSpan
		}
		if len(objects)+1 >= len(window) {
			return nil
		}
		span.physicalObject, span.physicalFirst = len(objects), 0
		objects = append(objects, append([][]byte(nil), span.rows...))
	}
	return objects
}

func (p *prefixPagePacker) writeWindow() error {
	if len(p.window) == 0 {
		return nil
	}
	var rows [][][]byte
	if len(p.window) > 1 {
		rows = packedPrefixObjects(p.window)
	}
	if len(rows) == 0 {
		for i, page := range p.window {
			rows = append(rows, page.rows)
			for j := range page.spans {
				span := &page.spans[j]
				span.physicalObject = i
				span.physicalFirst = span.logicalFirst
			}
		}
	}
	objects := make([]BuiltObject, len(rows))
	for i, r := range rows {
		obj, err := p.write(r)
		if err != nil {
			return err
		}
		objects[i] = obj
	}
	for _, page := range p.window {
		for _, span := range page.spans {
			p.byASN[span.asn] = append(p.byASN[span.asn], prefixPageSpan{&objects[span.physicalObject], uint32(span.physicalFirst), uint32(len(span.rows))})
		}
	}
	clear(p.window)
	p.window = p.window[:0]
	return nil
}
