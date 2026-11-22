package via3

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
)

// Equal raw ordinal vectors denote the same ordered kind-to-object mapping,
// including when independently encoded router records have different offsets.
func (r *browserRoutes) destination(row []byte) int {
	ints, _ := r.router.Rows(4)
	start := int(u32(row, 0)) * 4
	raw := ints[start : start+int(u16(row, 4))*4]
	if id, ok := r.setIDs[string(raw)]; ok {
		return id
	}
	set := make([]int, 0, len(raw)/4)
	for i := 0; i < len(raw); i += 4 {
		set = append(set, int(u32(raw, i)))
	}
	id := len(r.sets)
	r.sets = append(r.sets, set)
	r.setIDs[string(raw)] = id
	return id
}

func browserAddrKey(addr netip.Addr) string {
	if addr.Is4() {
		v := addr.As4()
		return hex.EncodeToString(v[:])
	}
	v := addr.As16()
	return hex.EncodeToString(v[:])
}

func browserASNKey(asn uint32) string {
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], asn)
	return hex.EncodeToString(v[:])
}

func lastInBrowserPrefix(p netip.Prefix) netip.Addr {
	v := p.Addr().As16()
	depth := p.Bits()
	if p.Addr().Is4() {
		depth += 96
	}
	for i := depth; i < 128; i++ {
		v[i/8] |= 1 << (7 - i%8)
	}
	if p.Addr().Is4() {
		return netip.AddrFrom4([4]byte(v[12:]))
	}
	return netip.AddrFrom16(v)
}

// A longest-prefix result changes only at a prefix start or immediately after
// its end. Evaluate each interval through the same native lookup as an IP
// query. This preserves nested fallbacks, host/exact ties and empty gaps.
func (r *browserRoutes) ipIntervals(ctx context.Context, boundaries []netip.Addr, width int) ([]browserSpan, error) {
	slices.SortFunc(boundaries, netip.Addr.Compare)
	boundaries = slices.Compact(boundaries)
	var spans []browserSpan
	previousSet := -1
	for i, addr := range boundaries {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if addr.Is4In6() {
			previousSet = -1
			continue
		}
		row, _, ok := r.router.findPrefix(addr)
		if !ok {
			previousSet = -1
			continue
		}
		last := strings.Repeat("f", width)
		if i+1 < len(boundaries) {
			last = browserAddrKey(boundaries[i+1].Prev())
		}
		set := r.destination(row)
		if set != previousSet {
			spans = append(spans, browserSpan{first: browserAddrKey(addr), last: last, set: set})
		} else {
			spans[len(spans)-1].last = last
		}
		previousSet = set
	}
	return spans, nil
}

func (r *browserRoutes) intervals(ctx context.Context) (v4, v6, asns []browserSpan, err error) {
	var boundaries [2][]netip.Addr
	for _, section := range []uint16{1, 8} {
		keys, _ := r.router.Rows(section)
		for i := 0; i < len(keys); i += 32 {
			if i%32768 == 0 {
				if err = ctx.Err(); err != nil {
					return
				}
			}
			addr, _ := keyAddr(keys[i : i+32])
			group := 0
			if addr.Is6() {
				group = 1
			}
			boundaries[group] = append(boundaries[group], addr)
			after := lastInBrowserPrefix(netip.PrefixFrom(addr, int(keys[i+1]))).Next()
			if after.IsValid() {
				boundaries[group] = append(boundaries[group], after)
			}
		}
	}
	// Browser inputs canonicalize mapped IPv6 literals to IPv4. Keep that
	// noncanonical part of the IPv6 plane from influencing later IPv6 keys.
	if len(boundaries[1]) > 0 {
		boundaries[1] = append(boundaries[1], netip.MustParseAddr("::ffff:0:0"), netip.MustParseAddr("::1:0:0:0"))
	}
	if v4, err = r.ipIntervals(ctx, boundaries[0], 8); err != nil {
		return
	}
	if v6, err = r.ipIntervals(ctx, boundaries[1], 32); err != nil {
		return
	}
	keys, _ := r.router.Rows(2)
	var previous uint32
	for i := 0; i < len(keys); i += 8 {
		if i%8192 == 0 {
			if err = ctx.Err(); err != nil {
				return
			}
		}
		asn := u32(keys, i)
		set := r.destination(r.router.Record(u32(keys, i+4)))
		end := len(asns) - 1
		if end >= 0 && asn-previous == 1 && asns[end].set == set {
			asns[end].last = browserASNKey(asn)
		} else {
			key := browserASNKey(asn)
			asns = append(asns, browserSpan{key, key, set})
		}
		previous = asn
	}
	return
}
