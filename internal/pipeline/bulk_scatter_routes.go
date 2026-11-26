package pipeline

import (
	"errors"
	"math/bits"
	"net/netip"
)

// Every terminal is the same number of address bits below the parent, in
// network order. A normalized prefix belongs to one contiguous interval of
// those terminals. Narrow prefixes can go straight to their single writer.
type bulkScatterRoutes struct {
	parent netip.Prefix
	width  int
	start  int // Bit position in Addr.As16.
	slots  int
}

func newBulkScatterRoutes(parent netip.Prefix, terminals []*bulkBucket) (bulkScatterRoutes, error) {
	n := len(terminals)
	if !parent.IsValid() || parent != parent.Masked() || parent.Addr().Is4In6() || n < 2 || n > 16 || n&(n-1) != 0 {
		return bulkScatterRoutes{}, errors.New("invalid spatial scatter routing geometry")
	}
	width := bits.Len(uint(n - 1))
	if parent.Bits()+width > parent.Addr().BitLen() {
		return bulkScatterRoutes{}, errors.New("spatial scatter exceeds address width")
	}
	r := bulkScatterRoutes{parent: parent, width: width, start: parent.Bits(), slots: n}
	if parent.Addr().Is4() {
		r.start += 96
	}
	for i, terminal := range terminals {
		if terminal == nil || terminal.prefix != terminal.prefix.Masked() || terminal.prefix.Bits() != parent.Bits()+width {
			return bulkScatterRoutes{}, errors.New("invalid spatial scatter terminal")
		}
		first, end := r.overlapping(terminal.prefix)
		if first != i || end != i+1 {
			return bulkScatterRoutes{}, errors.New("spatial scatter terminal order differs")
		}
	}
	return r, nil
}

func (r bulkScatterRoutes) overlapping(prefix netip.Prefix) (int, int) {
	parentBits := r.parent.Bits()
	if prefix.Bits() <= parentBits {
		if prefix.Contains(r.parent.Addr()) {
			return 0, r.slots
		}
		return 0, 0
	}
	if !r.parent.Contains(prefix.Addr()) {
		return 0, 0
	}
	data := prefix.Addr().As16()
	index, offset := r.start/8, r.start%8
	var slot int
	if offset+r.width <= 8 {
		slot = int(data[index]) >> (8 - offset - r.width)
	} else {
		word := uint16(data[index])<<8 | uint16(data[index+1])
		slot = int(word) >> (16 - offset - r.width)
	}
	slot &= r.slots - 1
	width := 1 << max(0, parentBits+r.width-prefix.Bits())
	first := slot &^ (width - 1)
	return first, first + width
}
