package via3

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"sort"
)

type IPv4NetworkCoverage struct {
	CoveredAddresses uint64 `json:"covered_addresses"`
	RouterIntervals  int    `json:"router_intervals"`
	NetworkObjects   int    `json:"network_objects"`
}

// IPv4NetworkCoverage verifies the selected network shard over every IPv4
// routing interval. A kind-4 match always contributes a Network answer. Its
// more-specific matches can change the values but still contribute a Network.
// A gap returns its first address and cannot certify absence of unknowns.
func (r *Release) IPv4NetworkCoverage(ctx context.Context) (coverage IPv4NetworkCoverage, gap netip.Addr, resultErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverNativeRead(&resultErr)
	r.beginQuery()
	defer r.endQuery()
	var report IPv4NetworkCoverage
	if err := r.current(); err != nil {
		return report, netip.Addr{}, err
	}
	const domain = uint64(1) << 32
	cuts := []uint64{0, domain}
	index, _ := r.router.Rows(1)
	for len(index) > 0 {
		row := index[:32]
		index = index[32:]
		if row[0] != 4 {
			continue
		}
		start := uint64(binary.BigEndian.Uint32(row[16:20]))
		cuts = append(cuts, start, start+(uint64(1)<<(32-int(row[1]))))
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i] < cuts[j] })
	cuts = slices.Compact(cuts)
	seen := map[uint32]bool{}
	var raw [4]byte
	for i, lo := range cuts[:len(cuts)-1] {
		if err := ctx.Err(); err != nil {
			return report, netip.Addr{}, err
		}
		r.beginQuery()
		hi := cuts[i+1]
		binary.BigEndian.PutUint32(raw[:], uint32(lo))
		addr := netip.AddrFrom4(raw)
		row, _, ok := r.router.findPrefix(addr)
		if !ok {
			return report, addr, nil
		}
		id, ok := r.router.destinationID(row, 4)
		if !ok {
			return report, addr, nil
		}
		shard, err := r.reference(ctx, r.router, id)
		if err != nil {
			return report, netip.Addr{}, err
		}
		if shard.Kind != 4 {
			return report, netip.Addr{}, fail("record")
		}
		if !seen[id] {
			seen[id] = true
			report.NetworkObjects++
		}
		report.RouterIntervals++
		if _, _, coversAll := shard.findPrefixWithin(addr, 0); coversAll {
			report.CoveredAddresses += hi - lo
			continue
		}
		for lo < hi {
			if err = ctx.Err(); err != nil {
				return report, netip.Addr{}, err
			}
			binary.BigEndian.PutUint32(raw[:], uint32(lo))
			addr = netip.AddrFrom4(raw)
			_, prefix, matched := shard.findPrefix(addr)
			if !matched {
				return report, addr, nil
			}
			first := prefix.Addr().As4()
			end := min(hi, uint64(binary.BigEndian.Uint32(first[:]))+(uint64(1)<<(32-prefix.Bits())))
			report.CoveredAddresses += end - lo
			lo = end
		}
	}
	if err := r.current(); err != nil {
		return report, netip.Addr{}, err
	}
	return report, netip.Addr{}, nil
}
