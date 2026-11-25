package pipeline

import (
	"context"
	"net/netip"

	"vansail-ip-atlas/internal/via3"
)

type locationRow[T any] struct {
	prefix netip.Prefix
	value  T
}

// Each explicit value stays in its original address-ordered slot. A promoted
// parent uses its left child's slot (the same first address), before any more
// specific overrides. An invalid prefix marks an absorbed row.
func foldLocationSiblings[T any](rows []locationRow[T], scope netip.Prefix, equal func(T, T) bool) []locationRow[T] {
	if len(rows) < 2 {
		return rows
	}
	type branch struct {
		prefix           netip.Prefix
		own, left, right int // one-based slots; zero is absent
	}
	stack := make([]branch, 0, 129)
	closeBranch := func() {
		i := len(stack) - 1
		node := stack[i]
		stack = stack[:i]
		inside := !scope.IsValid() || node.prefix.Bits() >= scope.Bits() && scope.Contains(node.prefix.Addr())
		if inside && node.left != 0 && node.right != 0 && equal(rows[node.left-1].value, rows[node.right-1].value) &&
			(node.own == 0 || equal(rows[node.own-1].value, rows[node.left-1].value)) {
			rows[node.right-1].prefix = netip.Prefix{}
			if node.own == 0 {
				node.own = node.left
				rows[node.own-1].prefix = node.prefix
			} else {
				rows[node.left-1].prefix = netip.Prefix{}
			}
		}
		if len(stack) > 0 {
			parent := &stack[len(stack)-1]
			if node.prefix.Addr() == parent.prefix.Addr() {
				parent.left = node.own
			} else {
				parent.right = node.own
			}
		}
	}
	for i := range rows {
		p := rows[i].prefix
		for len(stack) > 0 && !stack[len(stack)-1].prefix.Contains(p.Addr()) {
			closeBranch()
		}
		start := 0
		if len(stack) > 0 {
			start = stack[len(stack)-1].prefix.Bits() + 1
		}
		for depth := start; depth <= p.Bits(); depth++ {
			stack = append(stack, branch{prefix: netip.PrefixFrom(p.Addr(), depth).Masked()})
		}
		stack[len(stack)-1].own = i + 1
	}
	for len(stack) > 0 {
		closeBranch()
	}
	kept := rows[:0]
	for _, row := range rows {
		if row.prefix.IsValid() {
			kept = append(kept, row)
		}
	}
	return kept
}

// The closed mapping pass has at most one row per kind at each of its
// bounded input boundaries. Folding edits those vectors in place.
type locationRows struct {
	geo         []locationRow[via3.GeoData]
	coordinates []locationRow[via3.CoordinateData]
	usage       []locationRow[via3.UsageData]
}

func (p *locationRows) collect(r via3.PublicRecord) error {
	switch r.Kind {
	case 2:
		p.geo = append(p.geo, locationRow[via3.GeoData]{r.Prefix, *r.Geo})
	case 3:
		p.coordinates = append(p.coordinates, locationRow[via3.CoordinateData]{r.Prefix, *r.Coordinates})
	case 5:
		p.usage = append(p.usage, locationRow[via3.UsageData]{r.Prefix, *r.Usage})
	default:
		return errFactGroup
	}
	return nil
}

func firstLocationPrefix[T any](rows []locationRow[T], first netip.Prefix) netip.Prefix {
	if len(rows) == 0 {
		return first
	}
	p := rows[0].prefix
	if !first.IsValid() || p.Addr().Less(first.Addr()) || p.Addr() == first.Addr() && p.Bits() < first.Bits() {
		return p
	}
	return first
}

func equalLocationValue[T comparable](a, b T) bool { return a == b }

func (p *locationRows) emit(ctx context.Context, scope netip.Prefix, emit func(via3.PublicRecord) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.geo = foldLocationSiblings(p.geo, scope, equalLocationValue[via3.GeoData])
	p.coordinates = foldLocationSiblings(p.coordinates, scope, equalLocationValue[via3.CoordinateData])
	p.usage = foldLocationSiblings(p.usage, scope, func(a, b via3.UsageData) bool {
		return a.Type == b.Type && a.Assignment == b.Assignment && optionalBoolCode(a.Anycast) == optionalBoolCode(b.Anycast) && optionalBoolCode(a.DirectedBroadcast) == optionalBoolCode(b.DirectedBroadcast)
	})
	// Merging the three sorted vectors restores the materializer's original
	// address, prefix length, then kind order after independent promotions.
	for len(p.geo)+len(p.coordinates)+len(p.usage) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		first := firstLocationPrefix(p.geo, netip.Prefix{})
		first = firstLocationPrefix(p.coordinates, first)
		first = firstLocationPrefix(p.usage, first)
		if len(p.geo) > 0 && p.geo[0].prefix == first {
			if err := emit(via3.PublicRecord{Version: 3, Kind: 2, Prefix: first, Geo: &p.geo[0].value}); err != nil {
				return err
			}
			p.geo = p.geo[1:]
		}
		if len(p.coordinates) > 0 && p.coordinates[0].prefix == first {
			if err := emit(via3.PublicRecord{Version: 3, Kind: 3, Prefix: first, Coordinates: &p.coordinates[0].value}); err != nil {
				return err
			}
			p.coordinates = p.coordinates[1:]
		}
		if len(p.usage) > 0 && p.usage[0].prefix == first {
			if err := emit(via3.PublicRecord{Version: 3, Kind: 5, Prefix: first, Usage: &p.usage[0].value}); err != nil {
				return err
			}
			p.usage = p.usage[1:]
		}
	}
	return nil
}
