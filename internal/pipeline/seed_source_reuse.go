package pipeline

import (
	"context"
	"sort"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/intelligence"
)

const seedSourceDomain = "seed-source"

type seedGroup struct {
	entry spatialCacheEntry
	hit   bool
	risk  [2]bool
}

// Only these source effects may be replayed. If a source contains any other
// global mutation, it follows the complete normalized record walk.
type seedSourceSummary struct {
	ASNs             []uint32 `json:",omitempty"`
	Risk             []byte   // Per input partition, bit 0 is IPv4 and bit 1 is IPv6.
	Exact, DirectASN bool     `json:",omitzero"`
}

func (v *seedSourceSummary) valid() bool {
	if len(v.Risk) == 0 || len(v.Risk) > spatialCacheInputPartitions || len(v.ASNs) > 200000 || v.DirectASN && len(v.ASNs) == 0 {
		return false
	}
	for _, flags := range v.Risk {
		if flags > 3 {
			return false
		}
	}
	for i, asn := range v.ASNs {
		if !facts.PublicASN(asn) || i > 0 && asn <= v.ASNs[i-1] {
			return false
		}
	}
	return true
}

type seedSourceCapture struct {
	eligible         bool
	known            map[uint32]bool
	exact, directASN bool
}

func (c *seedSourceCapture) add(asn uint32) {
	if c.known == nil {
		c.known = make(map[uint32]bool)
	}
	c.known[asn] = true
}

func (c *seedSourceCapture) observe(r intelligence.NormalizedRecord) {
	if c == nil || !c.eligible {
		return
	}
	// seedRecord has already accepted this record and enforced its bounds.
	// Keep role and relationship contributions on the strict path, including
	// mixed sources with one such row anywhere in their partition sequence.
	switch r.Kind {
	case intelligence.RecordGeo, intelligence.RecordVRP, intelligence.RecordNetworkOrganization:
	case intelligence.RecordUsage:
		if r.Usage.ASN != 0 {
			c.eligible = false
		}
	case intelligence.RecordPath:
		c.add(r.Path.Observation.Origin)
	case intelligence.RecordOrigins:
		for _, asn := range r.Origins.Origins {
			c.add(asn)
		}
	case intelligence.RecordEvidence:
		if r.Evidence.Scope == intelligence.ASN {
			c.directASN = true
			c.add(r.Evidence.ASN)
		} else if r.Evidence.Scope == intelligence.Exact {
			c.exact = true
		}
	case intelligence.RecordCoverage:
		if r.Coverage.Layer == intelligence.ASN {
			c.add(r.Coverage.ASN)
		}
	case intelligence.RecordASNIdentity:
		c.add(r.ASNIdentity.ASN)
	default:
		c.eligible = false
	}
	if !c.eligible {
		c.known = nil
	}
}

func (c *seedSourceCapture) summary(groups []seedGroup) seedSourceSummary {
	v := seedSourceSummary{Risk: make([]byte, len(groups)), Exact: c.exact, DirectASN: c.directASN}
	for asn := range c.known {
		v.ASNs = append(v.ASNs, asn)
	}
	sort.Slice(v.ASNs, func(i, j int) bool { return v.ASNs[i] < v.ASNs[j] })
	for i, group := range groups {
		for family, relevant := range group.risk {
			if relevant {
				v.Risk[i] |= 1 << family
			}
		}
	}
	return v
}

// A source summary comes from an earlier complete strict walk of the exact
// ordered descriptors under this executable and contract. Verify the original
// file bytes again, then authenticate and import every derived category. Missing
// summaries or individual category entries take the ordinary semantic path.
func (s *bulkSpool) replaySeedSource(ctx context.Context, workspace string, source intelligence.StoredSource, key [32]byte, categories *[6][]intelligence.RecordPartition) (bool, error) {
	replay, hit, err := s.reuse.Lookup(ctx, seedSourceDomain, key)
	if err != nil || !hit {
		return false, err
	}
	if len(replay.SeedSource.Risk) != len(source.RecordPartitions) {
		return false, errSpatialCache
	}
	if err := intelligence.VerifyStoredSourceObjects(ctx, workspace, source); err != nil {
		return false, err
	}
	groups := make([]seedGroup, 0, len(source.RecordPartitions))
	for i, part := range source.RecordPartitions {
		groupKey, err := spatialReuseKey("seed", part)
		if err != nil {
			return false, err
		}
		entry, hit, err := s.reuse.Lookup(ctx, "seed", groupKey)
		if err != nil || !hit {
			return false, err
		}
		flags := replay.SeedSource.Risk[i]
		groups = append(groups, seedGroup{entry, true, [2]bool{flags&1 != 0, flags&2 != 0}})
	}
	if err := s.adoptSeedGroups(ctx, groups, categories); err != nil {
		return false, err
	}
	s.hasExact = s.hasExact || replay.SeedSource.Exact
	s.hasASNDirect = s.hasASNDirect || replay.SeedSource.DirectASN
	for _, asn := range replay.SeedSource.ASNs {
		if err := s.addASN(asn); err != nil {
			return false, err
		}
	}
	_, err = s.reuse.Retain(ctx, replay, nil)
	return err == nil, err
}

func (s *bulkSpool) adoptSeedGroups(ctx context.Context, groups []seedGroup, categories *[6][]intelligence.RecordPartition) error {
	var imports [][]intelligence.RecordPartition
	for _, group := range groups {
		if group.hit {
			imports = append(imports, group.entry.Seed.Parts[:]...)
		}
	}
	if len(imports) != 0 {
		if err := s.importCachedGroups(ctx, imports); err != nil {
			return err
		}
	}
	for _, group := range groups {
		for i, parts := range group.entry.Seed.Parts {
			categories[i] = append(categories[i], parts...)
			if i < 2 && group.risk[i] {
				for _, part := range parts {
					s.riskParts[part.SHA256] = true
				}
			}
		}
		if s.reuse != nil && group.entry.Key != ([32]byte{}) {
			if _, err := s.reuse.Retain(ctx, group.entry, s.cachePartFiles(group.entry.Seed.Parts[:]...)); err != nil {
				return err
			}
		}
	}
	return nil
}
