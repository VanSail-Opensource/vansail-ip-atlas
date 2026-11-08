package pipeline

import (
	"errors"
	"net/netip"
	"sort"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/via3"
)

// Normalize before encoding: malformed unions and huge vectors must not reach
// JSON allocation, and equivalent unordered input must dedupe to identical bytes.
func normalizePayload(record via3.PublicRecord) (via3.PublicRecord, error) {
	members := []bool{record.Geo != nil, record.Coordinates != nil, record.Network != nil, record.Usage != nil, record.Quality != nil, record.Profile != nil, record.ASNAggregate != nil, record.RPKI != nil, record.Origins != nil, record.Path != nil, record.Relationship != nil, record.Tier1 != nil}
	count := 0
	for i, present := range members {
		if present {
			count++
			if uint16(i+2) != record.Kind {
				return record, errors.New("public record union does not match kind")
			}
		}
	}
	if count != 1 || record.Kind != 11 && record.Rank != 0 {
		return record, errors.New("invalid public record union or rank")
	}
	if record.Kind != 8 && record.Kind < 11 && record.Kind != 9 && record.ASN != 0 {
		return record, errors.New("ASN key only belongs to RPKI prefix records")
	}
	if record.Geo != nil {
		g := *record.Geo
		if len(g.Region) > 1024 || len(g.City) > 1024 || len(g.Country) > 2 || len(g.RegistrationCountry) > 2 {
			return record, errors.New("oversized public geo label")
		}
		g.Region = via3.SanitizeLabel(g.Region)
		g.City = via3.SanitizeLabel(g.City)
		record.Geo = &g
	}
	asns := func(values []uint32) ([]uint32, error) {
		if len(values) > via3.PublicOrigins {
			return nil, errors.New("origin count exceeds answer ceiling")
		}
		copy := append([]uint32(nil), values...)
		if values != nil && copy == nil {
			copy = []uint32{}
		}
		for _, asn := range copy {
			if !facts.PublicASN(asn) {
				return nil, errors.New("invalid origin ASN")
			}
		}
		sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
		return compact(copy), nil
	}
	if record.Network != nil {
		n := *record.Network
		if len(n.Name) > 1024 || len(n.Organization) > 1024 || len(n.ISP) > 1024 {
			return record, errors.New("oversized public network label")
		}
		n.Name = via3.SanitizeLabel(n.Name)
		n.Organization = via3.SanitizeLabel(n.Organization)
		n.ISP = via3.SanitizeLabel(n.ISP)
		var err error
		n.Origins, err = asns(n.Origins)
		if err != nil {
			return record, err
		}
		record.Network = &n
	}
	if record.Origins != nil {
		o := *record.Origins
		var err error
		o.ASNs, err = asns(o.ASNs)
		if err != nil {
			return record, err
		}
		record.Origins = &o
	}
	if record.Profile != nil {
		p := *record.Profile
		if len(p.Cells) > 256 {
			return record, errors.New("profile exceeds 256 cells")
		}
		p.Cells = append([]via3.CellData(nil), p.Cells...)
		for i := range p.Cells {
			if !p.Cells[i].Address.IsValid() || p.Cells[i].Address.Zone() != "" {
				return record, errors.New("invalid profile cell address")
			}
			p.Cells[i].Address = p.Cells[i].Address.Unmap()
		}
		sort.Slice(p.Cells, func(i, j int) bool { return p.Cells[i].Address.Less(p.Cells[j].Address) })
		record.Profile = &p
	}
	if record.ASNAggregate != nil {
		a := *record.ASNAggregate
		if len(a.Name) > 1024 || len(a.Organization) > 1024 || len(a.Country) > 2 {
			return record, errors.New("oversized public ASN label")
		}
		if len(a.Prefixes) > 131072 {
			return record, errors.New("single ASN prefix list exceeds bounded record ceiling")
		}
		a.Name = via3.SanitizeLabel(a.Name)
		a.Organization = via3.SanitizeLabel(a.Organization)
		if a.Prefixes != nil {
			a.Prefixes = append([]netip.Prefix{}, a.Prefixes...)
		}
		for i, p := range a.Prefixes {
			if !p.IsValid() || p.Addr().Zone() != "" {
				return record, errors.New("invalid ASN prefix")
			}
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return record, errors.New("mapped ASN prefix crosses families")
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			a.Prefixes[i] = p.Masked()
		}
		sort.Slice(a.Prefixes, func(i, j int) bool {
			a, b := a.Prefixes[i], a.Prefixes[j]
			if a.Addr() != b.Addr() {
				return a.Addr().Less(b.Addr())
			}
			return a.Bits() < b.Bits()
		})
		if len(a.Prefixes) > 0 {
			out := a.Prefixes[:1]
			for _, p := range a.Prefixes[1:] {
				if p != out[len(out)-1] {
					out = append(out, p)
				}
			}
			a.Prefixes = out
		}
		record.ASNAggregate = &a
	}
	if record.Path != nil {
		p := *record.Path
		if len(p.Segments) > 255 {
			return record, errors.New("path segment ceiling exceeded")
		}
		p.Segments = append([]via3.SegmentData(nil), p.Segments...)
		total := 0
		for i, s := range p.Segments {
			total += len(s.ASNs)
			if total > via3.PublicPathASNs {
				return record, errors.New("path ASN ceiling exceeded")
			}
			s.ASNs = append([]uint32(nil), s.ASNs...)
			if s.Type == 2 || s.Type == 4 {
				sort.Slice(s.ASNs, func(i, j int) bool { return s.ASNs[i] < s.ASNs[j] })
				s.ASNs = compact(s.ASNs)
			}
			p.Segments[i] = s
		}
		record.Path = &p
	}
	return record, nil
}
