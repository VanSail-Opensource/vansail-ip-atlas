package pipeline

import (
	"errors"
	"net/netip"

	"vansail-ip-atlas/internal/via3"
)

// A /24 containing an exact observation is covered in full by the original
// leave-one-out computation. Its disjoint ordinary regions frequently repeat
// the same answer around individual observations. Keep all exact facts and
// select a default only after every address is accounted for.
type qualityBlockWriter struct {
	scope  netip.Prefix
	emit   func(via3.PublicRecord) error
	block  netip.Prefix
	rows   []qualityBlockRow
	counts map[qualityValue]int
}

type qualityBlockRow struct {
	prefix netip.Prefix
	data   *via3.QualityData
	value  qualityValue
	exact  bool
}

// Compare the original unquantized values, including every nullable field.
type qualityValue struct {
	score      uint16
	confidence uint8
	reasons    uint32
	assessed   [4]bool
	complete   bool
	present    uint8
	layers     [4]float64
}

func qualityValueOf(data *via3.QualityData) qualityValue {
	v := qualityValue{confidence: data.Confidence, reasons: data.Reasons, assessed: data.Assessed, complete: data.CoverageComplete}
	if data.Score != nil {
		v.score = 1 + uint16(*data.Score)
	}
	for i, p := range [4]*float64{data.Exact, data.Prefix, data.ASN, data.Neighbors} {
		if p != nil {
			v.present |= 1 << i
			v.layers[i] = *p
		}
	}
	return v
}

func (w *qualityBlockWriter) write(prefix netip.Prefix, exact bool, data *via3.QualityData) error {
	if !prefix.Addr().Is4() || prefix.Bits() < 24 || (w.scope.IsValid() && (w.scope.Bits() > 24 || !w.scope.Contains(prefix.Addr()))) {
		if err := w.flush(); err != nil {
			return err
		}
		return w.emit(via3.PublicRecord{Version: 3, Kind: 6, Prefix: prefix, Exact: exact, Quality: data})
	}
	block := netip.PrefixFrom(prefix.Addr(), 24).Masked()
	if block != w.block {
		if err := w.flush(); err != nil {
			return err
		}
		w.block = block
	}
	if len(w.rows) >= 256 {
		return errors.New("disjoint quality regions exceed IPv4 block")
	}
	w.rows = append(w.rows, qualityBlockRow{prefix: prefix, data: data, value: qualityValueOf(data), exact: exact})
	return nil
}

func (w *qualityBlockWriter) defaultIndex() int {
	if len(w.rows) < 3 {
		return -1
	}
	covered := 0
	hasExact := false
	for _, r := range w.rows {
		if int(r.prefix.Addr().As4()[3]) != covered {
			return -1
		}
		covered += 1 << (32 - r.prefix.Bits())
		hasExact = hasExact || r.exact
	}
	if covered != 256 || !hasExact {
		return -1
	}
	if w.counts == nil {
		w.counts = make(map[qualityValue]int)
	} else {
		clear(w.counts)
	}
	best, maximum := -1, 1
	for i, r := range w.rows {
		if r.exact {
			continue
		}
		count := w.counts[r.value] + 1
		w.counts[r.value] = count
		if count > maximum {
			best, maximum = i, count
		}
	}
	return best
}

func (w *qualityBlockWriter) flush() error {
	best := w.defaultIndex()
	if best >= 0 {
		if err := w.emit(via3.PublicRecord{Version: 3, Kind: 6, Prefix: w.block, Quality: w.rows[best].data}); err != nil {
			return err
		}
	}
	for _, r := range w.rows {
		if best >= 0 && !r.exact && r.value == w.rows[best].value {
			continue
		}
		if err := w.emit(via3.PublicRecord{Version: 3, Kind: 6, Prefix: r.prefix, Exact: r.exact, Quality: r.data}); err != nil {
			return err
		}
	}
	clear(w.rows)
	w.rows = w.rows[:0]
	return nil
}
