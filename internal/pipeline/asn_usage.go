package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"sort"

	"vansail-ip-atlas/internal/intelligence"
)

// ASN usage is a bounded fallback joined only to current observed origin
// prefixes. It is not evidence about every address assigned to an organization.
type asnUsageIndex map[uint32][]intelligence.UsageEvidence

func (index asnUsageIndex) add(v *intelligence.ScopedUsage) error {
	if v == nil || v.ASN == 0 || !intelligence.IsPublicASN(v.ASN) || v.Prefix.IsValid() || !v.Evidence.Current || v.Evidence.Family == "" || len(v.Evidence.Family) > 256 || len(v.Evidence.Type) > 32 {
		return errors.New("invalid ASN usage context")
	}
	values := index[v.ASN]
	for _, old := range values {
		if old.Family == v.Evidence.Family && old.Type == v.Evidence.Type {
			return nil
		}
	}
	if len(values) >= 16 || len(index) >= 200000 && len(values) == 0 {
		return errors.New("ASN usage context budget exceeded")
	}
	index[v.ASN] = append(values, v.Evidence)
	return nil
}

func (index asnUsageIndex) joined(prefix netip.Prefix, origins []uint32) intelligence.NormalizedRecord {
	kind := ""
	known := len(origins) > 0
	for _, asn := range origins {
		value := intelligence.FuseUsage(index[asn]).Type
		if value == "unknown" || kind != "" && kind != value {
			known = false
		}
		if kind == "" {
			kind = value
		}
	}
	if !known || kind == "" {
		kind = "unknown"
	}
	return intelligence.NormalizedRecord{Version: 3, Kind: intelligence.RecordUsage, Usage: &intelligence.ScopedUsage{Prefix: prefix, Evidence: intelligence.UsageEvidence{Family: "asn-usage-context", Type: kind, Current: true, Contextual: true, ContextPrefixBits: uint8(prefix.Bits())}}}
}

// joinASNUsage is used only on already bounded materialization states. The full
// production input instead preloads the bounded ASN index and joins each spatial
// partition after its origin union is complete. Source receipts remain untouched.
func joinASNUsage(ctx context.Context, state intelligence.BuildState) (intelligence.BuildState, error) {
	index := asnUsageIndex{}
	for _, s := range state.Sources {
		for _, r := range s.Records {
			if r.Usage != nil && r.Usage.ASN != 0 {
				if err := index.add(r.Usage); err != nil {
					return state, err
				}
			}
		}
	}
	if len(index) == 0 {
		return state, nil
	}
	result := state
	result.Sources = append([]intelligence.StoredSource(nil), state.Sources...)
	origins := map[netip.Prefix][]uint32{}
	for i, s := range state.Sources {
		result.Sources[i].Records = nil
		for _, r := range s.Records {
			if err := ctx.Err(); err != nil {
				return state, err
			}
			if r.Usage != nil && r.Usage.ASN != 0 {
				continue
			}
			result.Sources[i].Records = append(result.Sources[i].Records, r)
			if r.Origins != nil {
				p, err := canonicalMappingPrefix(r.Origins.Prefix)
				if err != nil {
					return state, err
				}
				if len(origins) >= 200000 && origins[p] == nil {
					return state, errors.New("bounded usage join prefix count exceeded")
				}
				origins[p] = append(origins[p], r.Origins.Origins...)
			}
		}
	}
	keys := make([]netip.Prefix, 0, len(origins))
	for p := range origins {
		keys = append(keys, p)
	}
	sortPrefixes(keys)
	for _, p := range keys {
		v := origins[p]
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		result.Sources[0].Records = append(result.Sources[0].Records, index.joined(p, compact(v)))
	}
	return result, nil
}
