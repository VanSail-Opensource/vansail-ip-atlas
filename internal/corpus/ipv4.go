// Package corpus describes evidence used by the private production query workload.
package corpus

import (
	"context"
	"errors"
	"net/netip"
	"reflect"

	"vansail-ip-atlas/internal/via3"
)

const IPv4Addresses = uint64(1) << 32

type IPv4Coverage struct {
	via3.IPv4NetworkCoverage
	Lookup via3.LookupAnswer  `json:"lookup"`
	ClassC *via3.ClassCAnswer `json:"class_c"`
}

// InspectIPv4 obtains its counts from the authenticated lookup indexes and its
// witness from the ordinary native lookup and Class C entry points.
func InspectIPv4(ctx context.Context, r *via3.Release) (*IPv4Coverage, netip.Addr, error) {
	coverage, gap, err := r.IPv4NetworkCoverage(ctx)
	if err != nil || gap.IsValid() {
		return nil, gap, err
	}
	if coverage.CoveredAddresses != IPv4Addresses {
		return nil, netip.Addr{}, errors.New("incomplete IPv4 network coverage")
	}
	const q = "0.0.0.0"
	answer, err := r.Lookup(ctx, q)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	grid, err := r.ClassC(ctx, q)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	result := &IPv4Coverage{coverage, answer, grid}
	if !result.Valid(r.Manifest.ReleaseID) {
		return nil, netip.Addr{}, errors.New("invalid IPv4 coverage witness")
	}
	return result, netip.Addr{}, nil
}

func (p *IPv4Coverage) Valid(releaseID string) bool {
	if p == nil || p.CoveredAddresses != IPv4Addresses || p.RouterIntervals < 1 || uint64(p.RouterIntervals) > IPv4Addresses || p.NetworkObjects < 1 || p.NetworkObjects >= 18500 || p.NetworkObjects > p.RouterIntervals || p.Lookup.Kind != "ip" || p.Lookup.Q != "0.0.0.0" || p.Lookup.Synthetic || p.Lookup.ReleaseID != releaseID || p.Lookup.Network == nil {
		return false
	}
	prefix, err := netip.ParsePrefix(p.Lookup.Network.Prefix)
	return err == nil && prefix == prefix.Masked() && prefix.Contains(netip.IPv4Unspecified()) && (p.ClassC == nil || p.ClassC.Prefix == "0.0.0.0/24" && len(p.ClassC.Cells) == 256)
}

func (p *IPv4Coverage) Verify(ctx context.Context, r *via3.Release) error {
	actual, gap, err := InspectIPv4(ctx, r)
	if err != nil {
		return err
	}
	if gap.IsValid() || !reflect.DeepEqual(p, actual) {
		return errors.New("IPv4 corpus coverage differs from the selected release")
	}
	return nil
}
