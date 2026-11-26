package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"maps"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/intelligence"
)

const maxMaterializationASNs = 200000

var errBulkPartition = errors.New("normalized working partition requires subdivision")
var errRawBulkPartition = fmt.Errorf("raw spatial input exceeds collection limit: %w: %w", errBulkPartition, intelligence.ErrVerifyRecordPrefix)

type bulkBucket struct {
	prefix       netip.Prefix
	first, last  uint32
	asn          bool
	parts        []intelligence.RecordPartition
	sourceEnds   []int // Original source boundaries for the ordered family root.
	riskDigest   [32]byte
	mappingInput [2][32]byte
	riskExact    bool
	timedScoring bool
	riskOnly     bool
	active       bool
	cover        netip.Prefix
	scattered    [2]*bulkBucket
	// Retained only for the synchronous visit of an owned collected state.
	recordBytes []int
	originASNs  []uint32
	geoCapture  bool
	geoRawCount int
	geoReplay   *geoLayoutReplay
}
type bulkSpool struct {
	root           string
	store          *intelligence.RecordStore
	canonical      map[[32]byte]intelligence.CanonicalPartition
	riskParts      map[[32]byte]bool
	clock          time.Time
	binding        [32]byte
	maximum        uint64
	external       func() uint64
	all            []*bulkBucket
	coverage       []intelligence.RecordPartition
	pathParts      []intelligence.RecordPartition
	prefixParts    []intelligence.RecordPartition
	prefixFile     *os.File
	prefixIndex    map[uint32]bulkPrefixRange
	pathBytes      uint64
	known          map[uint32]bool
	edges          map[intelligence.ASNEdge]bool
	batchBytes     int
	batchRecords   int
	relations      *intelligence.RelationshipIndex
	hasExact       bool
	hasASNDirect   bool
	usage          asnUsageIndex
	observe        func(context.Context, Stage) func(bool)
	reuse          *spatialCache
	publicStream   *spatialStreamWriter
	mappingStreams [2]*spatialStreamWriter
	replaySink     *spatialReplaySink
	publicRows     uint64
	started        bool

	logicalSplits int
}

func (s *bulkSpool) stage(ctx context.Context, stage Stage) func(bool) {
	return observeStage(ctx, Options{ObserveStage: s.observe}, stage)
}

func (s *bulkSpool) refresh() error {
	limits := intelligence.DefaultRecordStoreLimits()
	used := s.external() + s.pathBytes
	if used >= s.maximum || s.maximum-used < uint64(limits.PartitionBytes) {
		return errors.New("bulk scratch budget exceeded")
	}
	limits.DiskBytes = int64(s.maximum - used)
	store, err := intelligence.NewRecordStore(s.root, limits)
	if err != nil {
		return err
	}
	s.store = store
	return nil
}
func (s *bulkSpool) walk(ctx context.Context, parts []intelligence.RecordPartition, emit func(intelligence.NormalizedRecord) error) error {
	return intelligence.WalkStoredSource(ctx, s.root, intelligence.StoredSource{RecordPartitions: parts}, emit)
}

// Writer-produced and independently re-encoded chunks can reuse frame sizes
// and digests during later strictly verified reads in this process.
func (s *bulkSpool) walkOwned(ctx context.Context, parts []intelligence.RecordPartition, emit func(intelligence.NormalizedRecord, intelligence.CanonicalRecordFrame) error) error {
	consume := func(frame intelligence.CanonicalRecordFrame) error {
		record, err := frame.Record()
		if err != nil {
			return err
		}
		return emit(record, frame)
	}
	return s.walkCanonicalParts(parts, func(part intelligence.CanonicalPartition) error {
		return part.Walk(ctx, consume)
	}, func(part intelligence.RecordPartition) (intelligence.CanonicalPartition, error) {
		return intelligence.CompareCanonicalFrames(ctx, s.root, part, consume)
	})
}

func (s *bulkSpool) walkMeasured(ctx context.Context, parts []intelligence.RecordPartition, emit func(intelligence.NormalizedRecord, intelligence.CanonicalRecordMeasure) error) error {
	return s.walkCanonicalParts(parts, func(part intelligence.CanonicalPartition) error {
		return part.WalkMeasures(ctx, emit)
	}, func(part intelligence.RecordPartition) (intelligence.CanonicalPartition, error) {
		return intelligence.CompareCanonicalMeasures(ctx, s.root, part, emit)
	})
}

func (s *bulkSpool) walkCanonicalParts(parts []intelligence.RecordPartition, walk func(intelligence.CanonicalPartition) error, compare func(intelligence.RecordPartition) (intelligence.CanonicalPartition, error)) error {
	for _, part := range parts {
		if capability, ok := s.canonical[part.SHA256]; ok {
			if capability.Descriptor() != part {
				return errors.New("canonical spool partition identity differs")
			}
			if err := walk(capability); err != nil {
				return err
			}
			continue
		}
		verified, err := compare(part)
		if err != nil {
			return err
		}
		if verified.Descriptor() == part {
			if s.canonical == nil {
				s.canonical = make(map[[32]byte]intelligence.CanonicalPartition)
			}
			s.canonical[part.SHA256] = verified
		}
	}
	return nil
}

func (s *bulkSpool) finish(writer *intelligence.RecordWriter) ([]intelligence.RecordPartition, error) {
	capabilities, err := writer.FinishCanonical()
	if err != nil {
		return nil, err
	}
	if s.canonical == nil {
		s.canonical = make(map[[32]byte]intelligence.CanonicalPartition)
	}
	parts := make([]intelligence.RecordPartition, 0, len(capabilities))
	for _, capability := range capabilities {
		part := capability.Descriptor()
		if prior, ok := s.canonical[part.SHA256]; ok && prior.Descriptor() != part {
			return nil, errors.New("canonical spool partition descriptor conflicts")
		}
		s.canonical[part.SHA256] = capability
		parts = append(parts, part)
	}
	return parts, nil
}
func (s *bulkSpool) collect(ctx context.Context, b *bulkBucket, withCoverage bool) (intelligence.BuildState, error) {
	return s.collectRaw(ctx, b, withCoverage, errBulkPartition)
}

func (s *bulkSpool) collectRaw(ctx context.Context, b *bulkBucket, withCoverage bool, overflow error) (intelligence.BuildState, error) {
	b.recordBytes = nil
	b.geoRawCount = 0
	source := intelligence.StoredSource{ID: "bounded-materialization", Fingerprint: s.binding, ExpiresAt: s.clock.Add(720 * time.Hour)}
	var recordBytes []int
	var seen map[[32]byte]bool
	bytes, projected := 0, 0
	if replay := b.geoReplay; replay != nil {
		layout := replay.entry.Leaf.GeoLayout
		if !withCoverage || b.asn || b.riskOnly || len(replay.records) != layout.OtherRecords ||
			len(replay.lengths) != layout.OtherRecords || len(replay.seen) != layout.OtherRecords || replay.seen == nil {
			return intelligence.BuildState{}, errSpatialCache
		}
		source.Records, recordBytes, seen = replay.records, replay.lengths, replay.seen
		replay.records, replay.lengths, replay.seen = nil, nil, nil
		bytes, projected = layout.GeoCharge+layout.OtherCharge, layout.GeoRecords
	} else {
		// Bound the allocation by the existing minimum cost per accepted row,
		// even if a broad ancestor's descriptors count the same record twice.
		maxRecords := min(s.batchRecords, s.batchBytes/1024)
		reserve := 0
		for _, part := range b.parts {
			reserve += int(min(uint64(maxRecords-reserve), part.Records))
			if reserve == maxRecords {
				break
			}
		}
		source.Records = make([]intelligence.NormalizedRecord, 0, reserve)
		recordBytes = make([]int, 0, reserve)
		seen = make(map[[32]byte]bool, reserve)
	}
	riskDigest := sha256.New()
	collectRisk := s.reuse != nil && !withCoverage && !b.asn
	b.riskDigest = [32]byte{}
	b.riskExact = false
	b.timedScoring = false
	b.mappingInput = [2][32]byte{}
	// A geographic replay omits original Geo rows, so it cannot establish this
	// narrower identity. The ordinary exact physical mapping path still works.
	var mapping [2]hash.Hash
	var mappingRow [37]byte
	if s.reuse != nil && withCoverage && !b.asn && !b.riskOnly && b.geoReplay == nil {
		mapping[0], mapping[1] = sha256.New(), sha256.New()
	}
	paths := 0
	asns := map[uint32]bool{}
	observeRecord := func(record intelligence.NormalizedRecord) error {
		if record.Kind == intelligence.RecordPath {
			paths++
			if paths > 100000 {
				return overflow
			}
		}
		if withCoverage && record.Origins != nil {
			for _, asn := range record.Origins.Origins {
				asns[asn] = true
			}
		}
		return nil
	}
	appendDecoded := func(record intelligence.NormalizedRecord, size int, digest [32]byte) error {
		if seen[digest] {
			return nil
		}
		seen[digest] = true
		bytes += 2*size + 1024
		if projected+len(source.Records) >= s.batchRecords || bytes > s.batchBytes {
			return overflow
		}
		b.timedScoring = b.timedScoring || record.Kind == intelligence.RecordEvidence || record.Kind == intelligence.RecordCoverage
		if collectRisk && exactRiskInput(record) {
			_, _ = riskDigest.Write(digest[:])
			b.riskExact = b.riskExact || record.Kind == intelligence.RecordEvidence
		}
		if index := mappingInputStream(record.Kind); index >= 0 && mapping[index] != nil {
			// Use the already accepted canonical row, after normal deduplication.
			// This also sees the actual generated usage rows below.
			mappingRow[0] = byte(record.Kind)
			binary.LittleEndian.PutUint32(mappingRow[1:5], uint32(size))
			copy(mappingRow[5:], digest[:])
			_, _ = mapping[index].Write(mappingRow[:])
		}
		if err := observeRecord(record); err != nil {
			return err
		}
		source.Records = append(source.Records, record)
		recordBytes = append(recordBytes, size)
		return nil
	}
	add := func(record intelligence.NormalizedRecord, frame intelligence.CanonicalRecordMeasure) error {
		if err := boundedNormalizedRecord(record); err != nil {
			return err
		}
		size, digest := frame.EncodedBytes(), frame.Digest()
		if size == 0 {
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			size, digest = len(data), sha256.Sum256(data)
		}
		return appendDecoded(record, size, digest)
	}
	if b.geoReplay != nil {
		for _, record := range source.Records {
			if err := ctx.Err(); err != nil {
				return intelligence.BuildState{}, err
			}
			if err := observeRecord(record); err != nil {
				return intelligence.BuildState{}, err
			}
		}
	} else if err := s.walkMeasured(ctx, b.parts, add); err != nil {
		return intelligence.BuildState{}, err
	}
	b.geoRawCount = len(source.Records)
	overflow = errBulkPartition
	if !b.asn && !b.riskOnly && len(s.usage) > 0 {
		origins := map[netip.Prefix][]uint32{}
		for _, r := range source.Records {
			if r.Origins != nil {
				origins[r.Origins.Prefix] = append(origins[r.Origins.Prefix], r.Origins.Origins...)
			}
		}
		keys := make([]netip.Prefix, 0, len(origins))
		for p := range origins {
			keys = append(keys, p)
		}
		sortPrefixes(keys)
		for _, p := range keys {
			v := origins[p]
			slices.Sort(v)
			if err := add(s.usage.joined(p, compact(v)), intelligence.CanonicalRecordMeasure{}); err != nil {
				return intelligence.BuildState{}, err
			}
		}
	}
	if withCoverage {
		if err := s.walkMeasured(ctx, s.coverage, func(record intelligence.NormalizedRecord, frame intelligence.CanonicalRecordMeasure) error {
			if record.Coverage == nil || record.Coverage.Layer != intelligence.ASN {
				return errors.New("invalid ASN coverage spool")
			}
			if asns[record.Coverage.ASN] {
				return add(record, frame)
			}
			return nil
		}); err != nil {
			return intelligence.BuildState{}, err
		}
		if s.reuse != nil {
			b.originASNs = slices.Sorted(maps.Keys(asns))
		}
	}
	if collectRisk {
		copy(b.riskDigest[:], riskDigest.Sum(nil))
	}
	for i, digest := range mapping {
		if digest != nil {
			copy(b.mappingInput[i][:], digest.Sum(nil))
		}
	}
	b.recordBytes = recordBytes
	return intelligence.BuildState{Version: 1, PolicyHash: s.binding, EvaluatedAt: s.clock, Sources: []intelligence.StoredSource{source}}, nil
}
func spatialPrefix(record intelligence.NormalizedRecord) (netip.Prefix, error) {
	var p netip.Prefix
	switch record.Kind {
	case intelligence.RecordEvidence:
		if record.Evidence.Scope == intelligence.Exact {
			addr := record.Evidence.Address.Unmap()
			p = netip.PrefixFrom(addr, addr.BitLen())
		} else if record.Evidence.Scope == intelligence.ExplicitPrefix {
			p = record.Evidence.Prefix
		}
	case intelligence.RecordCoverage:
		if record.Coverage.Layer != intelligence.ASN {
			p = record.Coverage.Prefix
		}
	case intelligence.RecordNetworkName:
		p = record.NetworkName.Prefix
	case intelligence.RecordNetworkOrganization:
		p = record.NetworkOrganization.Prefix
	case intelligence.RecordOrigins:
		p = record.Origins.Prefix
	case intelligence.RecordGeo:
		p = record.Geo.Prefix
	case intelligence.RecordUsage:
		p = record.Usage.Prefix
	case intelligence.RecordVRP:
		p = record.VRP.Prefix
	}
	if !p.IsValid() {
		return p, errors.New("normalized record has no spatial key")
	}
	return canonicalMappingPrefix(p)
}
func bulkChildren(b *bulkBucket) (*bulkBucket, *bulkBucket, error) {
	left, right := *b, *b
	left.parts = nil
	right.parts = nil
	left.sourceEnds = nil
	right.sourceEnds = nil
	left.recordBytes = nil
	right.recordBytes = nil
	left.scattered = [2]*bulkBucket{}
	right.scattered = [2]*bulkBucket{}
	left.cover = netip.Prefix{}
	right.cover = netip.Prefix{}
	left.active = true
	right.active = true
	if b.asn {
		if b.first == b.last {
			return nil, nil, errors.New("one ASN exceeds bounded materialization")
		}
		middle := b.first + (b.last-b.first)/2
		left.last = middle
		right.first = middle + 1
		return &left, &right, nil
	}
	p := b.prefix
	limit := p.Addr().BitLen()
	if p.Addr().Is4() {
		limit = 24
	}
	if p.Bits() >= limit {
		return nil, nil, errors.New("indivisible spatial scope exceeds bounded materialization")
	}
	raw := p.Addr().As16()
	offset := 0
	if p.Addr().Is4() {
		offset = 96
	}
	position := offset + p.Bits()
	raw[position/8] |= 1 << uint(7-position%8)
	addr := netip.AddrFrom16(raw)
	if p.Addr().Is4() {
		addr = addr.Unmap()
	}
	left.prefix = netip.PrefixFrom(p.Addr(), p.Bits()+1)
	right.prefix = netip.PrefixFrom(addr, p.Bits()+1)
	return &left, &right, nil
}
func asnRecord(record intelligence.NormalizedRecord, b *bulkBucket) (intelligence.NormalizedRecord, bool) {
	contains := func(asn uint32) bool { return asn >= b.first && asn <= b.last }
	switch record.Kind {
	case intelligence.RecordASNIdentity:
		return record, contains(record.ASNIdentity.ASN)
	case intelligence.RecordEvidence:
		return record, record.Evidence.Scope == intelligence.ASN && contains(record.Evidence.ASN)
	case intelligence.RecordOrigins:
		origins := make([]uint32, 0, len(record.Origins.Origins))
		for _, asn := range record.Origins.Origins {
			if contains(asn) {
				origins = append(origins, asn)
			}
		}
		if len(origins) == 0 {
			return record, false
		}
		value := *record.Origins
		value.Origins = origins
		record.Origins = &value
		return record, true
	case intelligence.RecordPath:
		return record, contains(record.Path.Observation.Origin)
	}
	return record, false
}

// bulkPrefixCover includes every address represented by either input prefix,
// including an inherited broad row. Its constant-size work never walks the
// address population or allows a descendant to narrow an ancestor's scope.
func bulkPrefixCover(a, b netip.Prefix) netip.Prefix {
	if !a.IsValid() {
		return b
	}
	common := 0
	if a.Addr().Is4() {
		x, y := a.Addr().As4(), b.Addr().As4()
		common = bits.LeadingZeros32(binary.BigEndian.Uint32(x[:]) ^ binary.BigEndian.Uint32(y[:]))
	} else {
		x, y := a.Addr().As16(), b.Addr().As16()
		common = bits.LeadingZeros64(binary.BigEndian.Uint64(x[:8]) ^ binary.BigEndian.Uint64(y[:8]))
		if common == 64 {
			common += bits.LeadingZeros64(binary.BigEndian.Uint64(x[8:]) ^ binary.BigEndian.Uint64(y[8:]))
		}
	}
	return netip.PrefixFrom(a.Addr(), min(common, a.Bits(), b.Bits())).Masked()
}

func narrowBulkChild(child *bulkBucket, cover netip.Prefix) {
	if !cover.IsValid() || cover.Bits() <= child.prefix.Bits() {
		return
	}
	depth := cover.Bits()
	if cover.Addr().Is4() {
		// Exact observations need their entire /24 for leave-one-out context.
		depth = min(depth, 24)
	}
	if depth > child.prefix.Bits() {
		target := netip.PrefixFrom(cover.Addr(), depth).Masked()
		// Retain the matching cached subtree while skipping empty scopes. Its
		// terminal parts contain each inherited row only once per terminal;
		// rescattering the wider group's union would multiply those copies.
		node := child
		for node.prefix.Bits() < depth && node.scattered[0] != nil {
			next, sibling := node.scattered[0], node.scattered[1]
			if !next.prefix.Contains(target.Addr()) {
				next, sibling = sibling, next
			}
			if len(sibling.parts) != 0 {
				return // a populated sibling cannot be skipped
			}
			node = next
		}
		child.parts, child.scattered, child.cover = node.parts, node.scattered, node.cover
		child.prefix = target
	}
}

// splitSpatial amortizes up to four binary redistribution passes into one
// bounded scatter. The logical binary groups still go through collect, so the
// first fitting scope and public quality boundaries do not become finer merely
// because streams were prepared ahead of time. Only the active frontier owns
// parts for GC; each group's inventory includes all of its hidden descendants.
func (s *bulkSpool) splitSpatial(ctx context.Context, b *bulkBucket) (left, right *bulkBucket, failure error) {
	if b.asn {
		return nil, nil, errors.New("spatial scatter cannot partition ASN scope")
	}
	wroteParts := b.scattered[0] == nil
	if wroteParts {
		root := *b
		root.parts = nil
		var terminal []*bulkBucket
		var expand func(*bulkBucket, int) error
		expand = func(node *bulkBucket, depth int) error {
			limit := node.prefix.Addr().BitLen()
			if node.prefix.Addr().Is4() {
				limit = 24
			}
			if depth == 4 || node.prefix.Bits() >= limit && depth > 0 {
				terminal = append(terminal, node)
				return nil
			}
			l, r, err := bulkChildren(node)
			if err != nil {
				return err
			}
			l.active, r.active = false, false
			node.scattered = [2]*bulkBucket{l, r}
			if err = expand(l, depth+1); err != nil {
				return err
			}
			return expand(r, depth+1)
		}
		if err := expand(&root, 0); err != nil {
			return nil, nil, err
		}
		if len(terminal) < 2 || len(terminal) > 16 {
			return nil, nil, errors.New("spatial scatter fanout exceeded")
		}
		if err := s.refresh(); err != nil {
			return nil, nil, err
		}
		if err := s.scatterTerminals(ctx, b, terminal); err != nil {
			return nil, nil, err
		}
		var group func(*bulkBucket) error
		group = func(node *bulkBucket) error {
			if node.scattered[0] == nil {
				return nil
			}
			seen := map[[32]byte]intelligence.RecordPartition{}
			for _, child := range node.scattered {
				if err := group(child); err != nil {
					return err
				}
				if child.cover.IsValid() {
					node.cover = bulkPrefixCover(node.cover, child.cover)
				}
				for _, part := range child.parts {
					if prior, exists := seen[part.SHA256]; exists {
						if prior != part {
							return errors.New("shared spatial partition identity differs")
						}
						continue
					}
					seen[part.SHA256] = part
					node.parts = append(node.parts, part)
				}
			}
			return nil
		}
		if err := group(&root); err != nil {
			return nil, nil, err
		}
		b.scattered = root.scattered
	}
	left, right = b.scattered[0], b.scattered[1]
	if len(left.parts) == 0 {
		narrowBulkChild(right, right.cover)
	} else if len(right.parts) == 0 {
		narrowBulkChild(left, left.cover)
	}
	b.active = false
	left.active, right.active = true, true
	s.all = append(s.all, left, right)
	// Precomputed children collectively own exactly the parent's objects, even
	// after narrowing through empty siblings. No file was written or retired.
	// Audit periodically during read-only splits and at the end of each pass.
	if !wroteParts {
		s.logicalSplits++
		if s.logicalSplits < 16 {
			return left, right, ctx.Err()
		}
	}
	if err := s.gc(ctx); err != nil {
		return nil, nil, err
	}
	return left, right, nil
}

func (s *bulkSpool) split(ctx context.Context, b *bulkBucket) (*bulkBucket, *bulkBucket, error) {
	left, right, err := bulkChildren(b)
	if err != nil {
		return nil, nil, err
	}
	if err = s.refresh(); err != nil {
		return nil, nil, err
	}
	writers := [2]*intelligence.RecordWriter{s.store.Writer(ctx), s.store.Writer(ctx)}
	defer writers[0].Abort()
	defer writers[1].Abort()
	var covers [2]netip.Prefix
	err = s.walk(ctx, b.parts, func(record intelligence.NormalizedRecord) error {
		for i, child := range []*bulkBucket{left, right} {
			candidate := record
			var keep bool
			if b.asn {
				candidate, keep = asnRecord(record, child)
			} else {
				p, err := spatialPrefix(record)
				if err != nil {
					return err
				}
				keep = p.Contains(child.prefix.Addr()) || child.prefix.Contains(p.Addr())
				if keep {
					covers[i] = bulkPrefixCover(covers[i], p)
				}
			}
			if keep {
				if err := writers[i].Append(candidate); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	left.parts, err = s.finish(writers[0])
	if err != nil {
		return nil, nil, err
	}
	right.parts, err = s.finish(writers[1])
	if err != nil {
		return nil, nil, err
	}
	if !b.asn {
		// If both children contain rows, broad inherited observations may be
		// required in each scope. Only a truly empty sibling proves that the
		// surviving rows can skip the intervening empty address-space levels.
		if len(left.parts) == 0 {
			narrowBulkChild(right, covers[1])
		} else if len(right.parts) == 0 {
			narrowBulkChild(left, covers[0])
		}
	}
	b.active = false
	s.all = append(s.all, left, right)
	if err = s.gc(ctx); err != nil {
		return nil, nil, err
	}
	return left, right, nil
}
func (s *bulkSpool) auditLogicalSplits(ctx context.Context) error {
	if s.logicalSplits == 0 {
		return ctx.Err()
	}
	return s.gc(ctx)
}

func (s *bulkSpool) gc(ctx context.Context) error {
	source := intelligence.StoredSource{ExpiresAt: s.clock.Add(720 * time.Hour), RecordPartitions: append([]intelligence.RecordPartition(nil), s.coverage...)}
	source.RecordPartitions = append(source.RecordPartitions, s.pathParts...)
	source.RecordPartitions = append(source.RecordPartitions, s.prefixParts...)
	for _, bucket := range s.all {
		if bucket.active {
			source.RecordPartitions = append(source.RecordPartitions, bucket.parts...)
		}
	}
	state := intelligence.BuildState{Version: 2, PolicyHash: s.binding, Sources: []intelligence.StoredSource{source}}
	if err := intelligence.PruneRecordStore(ctx, s.root, state, intelligence.BuildState{}, s.clock); err != nil {
		return err
	}
	retained := make(map[[32]byte]bool, len(source.RecordPartitions))
	for _, part := range source.RecordPartitions {
		retained[part.SHA256] = true
	}
	for digest := range s.canonical {
		if !retained[digest] {
			delete(s.canonical, digest)
		}
	}
	if err := s.refresh(); err != nil {
		return err
	}
	s.logicalSplits = 0
	return nil
}
func (s *bulkSpool) leaves(ctx context.Context, roots []*bulkBucket, coverage bool, visit func(*bulkBucket, intelligence.BuildState) error) ([]*bulkBucket, error) {
	var leaves []*bulkBucket
	var walk func(*bulkBucket) error
	walk = func(b *bulkBucket) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(b.parts) == 0 {
			return nil
		}
		state, err := s.collectWithSplitProof(ctx, b, coverage)
		if errors.Is(err, errBulkPartition) {
			var left, right *bulkBucket
			if b.asn {
				left, right, err = s.split(ctx, b)
			} else {
				left, right, err = s.splitSpatial(ctx, b)
			}
			if err != nil {
				return err
			}
			if err = walk(left); err != nil {
				return err
			}
			return walk(right)
		}
		if err != nil {
			return err
		}
		err = visit(b, state)
		b.recordBytes = nil
		if err != nil {
			return err
		}
		leaves = append(leaves, b)
		return nil
	}
	for _, root := range roots {
		if err := walk(root); err != nil {
			return nil, err
		}
	}
	return leaves, s.auditLogicalSplits(ctx)
}
func (s *bulkSpool) addASN(asn uint32) error {
	if !facts.PublicASN(asn) {
		return errors.New("invalid global materialization ASN")
	}
	s.known[asn] = true
	if len(s.known) > maxMaterializationASNs {
		return errors.New("global ASN population exceeded")
	}
	return nil
}
func (s *bulkSpool) addEdge(edge intelligence.ASNEdge, observed bool) error {
	if err := s.addASN(edge.From); err != nil {
		return err
	}
	if err := s.addASN(edge.To); err != nil {
		return err
	}
	s.edges[edge] = s.edges[edge] || observed
	if len(s.edges) > 4_000_000 {
		return errors.New("global relationship population exceeded")
	}
	return nil
}

// Seed category streams end at every original input partition boundary. A
// changed normalized object therefore cannot shift the packing identity of
// unrelated objects. Capture source effects only after a complete strict walk.
// A replay rechecks the original physical objects and all derived groups.
func (s *bulkSpool) seedStable(ctx context.Context, workspace string, state intelligence.BuildState) ([]*bulkBucket, *bulkBucket, error) {
	if err := s.refresh(); err != nil {
		return nil, nil, err
	}
	s.usage = asnUsageIndex{}
	s.riskParts = map[[32]byte]bool{}
	var categories [6][]intelligence.RecordPartition
	var sourceEnds [2][]int
	markSource := func() {
		if s.reuse != nil {
			for i := range sourceEnds {
				sourceEnds[i] = appendSourceEnd(sourceEnds[i], len(categories[i]))
			}
		}
	}
	for _, source := range state.Sources {
		var replayKey [32]byte
		var capture *seedSourceCapture
		if s.reuse != nil && len(source.RecordPartitions) > 0 && len(source.Records) == 0 {
			key, err := spatialReuseKey(seedSourceDomain, source.RecordPartitions)
			if err != nil {
				return nil, nil, err
			}
			replayKey = key
			hit, err := s.replaySeedSource(ctx, workspace, source, key, &categories)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				markSource()
				continue
			}
			capture = &seedSourceCapture{eligible: true}
		}
		var groups []seedGroup
		var current *seedGroup
		var writers [6]*intelligence.RecordWriter
		abort := func() {
			for _, writer := range writers {
				if writer != nil {
					_ = writer.Abort()
				}
			}
		}
		partIndex := 0
		remaining := uint64(len(source.Records))
		if len(source.RecordPartitions) > 0 {
			remaining = source.RecordPartitions[0].Records
		}
		appendRecord := func(category int, record intelligence.NormalizedRecord) error {
			if category < 2 && exactRiskInput(record) {
				current.risk[category] = true
			}
			if current.hit {
				return nil
			}
			if writers[category] == nil {
				writers[category] = s.store.Writer(ctx)
			}
			return writers[category].Append(record)
		}
		adjacent := seedOriginAppender{emit: appendRecord}
		err := intelligence.WalkStoredSource(ctx, workspace, source, func(record intelligence.NormalizedRecord) error {
			if remaining == 0 {
				return errors.New("seed input partition count differs")
			}
			if current == nil {
				adjacent.reset()
				current = &seedGroup{entry: spatialCacheEntry{Domain: "seed", Seed: &spatialCacheSeed{}}}
				if s.reuse != nil && len(source.RecordPartitions) > 0 {
					key, err := spatialReuseKey("seed", source.RecordPartitions[partIndex])
					if err != nil {
						return err
					}
					current.entry.Key = key
					entry, hit, err := s.reuse.Lookup(ctx, "seed", key)
					if err != nil {
						return err
					}
					if hit {
						current.entry, current.hit = entry, true
					}
				}
			}
			emit := appendRecord
			if !current.hit {
				emit = adjacent.append
			}
			if err := s.seedRecord(record, emit); err != nil {
				return err
			}
			capture.observe(record)
			remaining--
			if remaining != 0 {
				return nil
			}
			for i, writer := range writers {
				if writer == nil {
					continue
				}
				parts, err := s.finish(writer)
				if err != nil {
					return err
				}
				current.entry.Seed.Parts[i] = parts
				writers[i] = nil
			}
			groups = append(groups, *current)
			current = nil
			partIndex++
			if partIndex < len(source.RecordPartitions) {
				remaining = source.RecordPartitions[partIndex].Records
			}
			return nil
		})
		abort()
		if err != nil {
			return nil, nil, err
		}
		if remaining != 0 {
			return nil, nil, errors.New("seed source record count differs")
		}
		if err := s.adoptSeedGroups(ctx, groups, &categories); err != nil {
			return nil, nil, err
		}
		if capture != nil && capture.eligible {
			summary := capture.summary(groups)
			if _, err := s.reuse.Retain(ctx, spatialCacheEntry{Domain: seedSourceDomain, Key: replayKey, SeedSource: &summary}, nil); err != nil {
				return nil, nil, err
			}
		}
		markSource()
	}
	spatial := []*bulkBucket{{prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0), active: true}, {prefix: netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0), active: true}}
	asn := &bulkBucket{asn: true, first: 0, last: ^uint32(0), active: true}
	for i, b := range []*bulkBucket{spatial[0], spatial[1], asn} {
		b.parts = categories[i]
		s.all = append(s.all, b)
	}
	for i, b := range spatial {
		b.sourceEnds = sourceEnds[i]
	}
	s.coverage, s.pathParts, s.prefixParts = categories[3], categories[4], categories[5]
	return spatial, asn, nil
}

func (s *bulkSpool) seedRecord(record intelligence.NormalizedRecord, appendRecord func(int, intelligence.NormalizedRecord) error) error {
	if err := boundedNormalizedRecord(record); err != nil {
		return err
	}
	switch record.Kind {
	case intelligence.RecordUsage:
		if record.Usage.ASN != 0 {
			return s.usage.add(record.Usage)
		}
	case intelligence.RecordASNIdentity:
		if err := s.addASN(record.ASNIdentity.ASN); err != nil {
			return err
		}
		return appendRecord(2, record)
	case intelligence.RecordRelationship:
		v := record.Relationship
		if v.From == v.To || v.Relation < intelligence.TransitUpstream || v.Relation > intelligence.Sibling {
			return errors.New("invalid normalized relationship")
		}
		if s.relations != nil {
			if err := s.relations.Add(v.From, v.To, v.Relation); err != nil {
				return err
			}
		}
		if err := s.addEdge(intelligence.ASNEdge{From: v.From, To: v.To}, false); err != nil {
			return err
		}
		return s.addEdge(intelligence.ASNEdge{From: v.To, To: v.From}, false)
	case intelligence.RecordPath:
		if err := s.addASN(record.Path.Observation.Origin); err != nil {
			return err
		}
		value := *record.Path
		value.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0)
		record.Path = &value
		record.MRTOriginatedAt = nil
		record.MRT = nil
		return appendRecord(4, record)
	case intelligence.RecordEvidence:
		if record.Evidence.Scope == intelligence.Exact {
			s.hasExact = true
		}
		if record.Evidence.Scope == intelligence.ASN {
			s.hasASNDirect = true
			if err := s.addASN(record.Evidence.ASN); err != nil {
				return err
			}
			return appendRecord(2, record)
		}
	case intelligence.RecordCoverage:
		if record.Coverage.Layer == intelligence.ASN {
			if err := s.addASN(record.Coverage.ASN); err != nil {
				return err
			}
			return appendRecord(3, record)
		}
	case intelligence.RecordOrigins:
		// Peer/capture identity stays in authenticated source storage. The
		// derived prefix/ASN union must not count duplicate peer rows.
		record.MRTOriginatedAt = nil
		record.MRT = nil
		for _, asn := range record.Origins.Origins {
			if err := s.addASN(asn); err != nil {
				return err
			}
		}
		if err := appendRecord(5, record); err != nil {
			return err
		}
	}
	prefix, err := spatialPrefix(record)
	if err != nil {
		return err
	}
	index := 0
	if prefix.Addr().Is6() {
		index = 1
	}
	return appendRecord(index, record)
}

func (s *bulkSpool) seed(ctx context.Context, workspace string, state intelligence.BuildState) ([]*bulkBucket, *bulkBucket, error) {
	if s.reuse != nil && canReuseSpatialState(state) {
		return s.seedStable(ctx, workspace, state)
	}
	return s.seedCold(ctx, workspace, state)
}

func (s *bulkSpool) seedCold(ctx context.Context, workspace string, state intelligence.BuildState) ([]*bulkBucket, *bulkBucket, error) {
	if err := s.refresh(); err != nil {
		return nil, nil, err
	}
	writers := [6]*intelligence.RecordWriter{s.store.Writer(ctx), s.store.Writer(ctx), s.store.Writer(ctx), s.store.Writer(ctx), s.store.Writer(ctx), s.store.Writer(ctx)}
	for _, writer := range writers {
		defer writer.Abort()
	}
	s.usage = asnUsageIndex{}
	for _, source := range state.Sources {
		adjacent := seedOriginAppender{emit: func(category int, value intelligence.NormalizedRecord) error {
			return writers[category].Append(value)
		}}
		partIndex := 0
		var remaining uint64
		if len(source.RecordPartitions) != 0 {
			remaining = source.RecordPartitions[0].Records
		}
		if err := intelligence.WalkStoredSource(ctx, workspace, source, func(record intelligence.NormalizedRecord) error {
			if len(source.RecordPartitions) != 0 && remaining == 0 {
				return errors.New("seed input partition count differs")
			}
			if err := s.seedRecord(record, adjacent.append); err != nil {
				return err
			}
			if len(source.RecordPartitions) != 0 {
				remaining--
				if remaining == 0 {
					adjacent.reset()
					partIndex++
					if partIndex < len(source.RecordPartitions) {
						remaining = source.RecordPartitions[partIndex].Records
					}
				}
			}
			return nil
		}); err != nil {
			return nil, nil, err
		}
	}
	spatial := []*bulkBucket{{prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0), active: true}, {prefix: netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0), active: true}}
	asn := &bulkBucket{asn: true, first: 0, last: ^uint32(0), active: true}
	var err error
	for i, b := range []*bulkBucket{spatial[0], spatial[1], asn} {
		b.parts, err = s.finish(writers[i])
		if err != nil {
			return nil, nil, err
		}
		s.all = append(s.all, b)
	}
	s.coverage, err = s.finish(writers[3])
	if err == nil {
		s.pathParts, err = s.finish(writers[4])
	}
	if err == nil {
		s.prefixParts, err = s.finish(writers[5])
	}
	return spatial, asn, err
}
func stateDiskBytes(workspace string) (uint64, error) {
	store, err := intelligence.NewRecordStore(workspace, intelligence.DefaultRecordStoreLimits())
	if err != nil {
		return 0, err
	}
	return store.DiskBytes(), nil
}

func sortedASNs(values map[uint32]bool) []uint32 {
	keys := make([]uint32, 0, len(values))
	for asn := range values {
		keys = append(keys, asn)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// newBulkSpool owns its exact generated directory. Cleanup never targets any
// caller-provided source path, immutable input object or unrelated private file.
func newBulkSpool(workspace string, clock time.Time, binding [32]byte, maximum uint64, external func() uint64) (*bulkSpool, error) {
	parent, err := recordSpoolParent(workspace)
	if err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(parent, "materialize-")
	if err != nil {
		return nil, err
	}
	return &bulkSpool{root: root, clock: clock, binding: binding, maximum: maximum, external: external, known: map[uint32]bool{}, edges: map[intelligence.ASNEdge]bool{}, batchBytes: 96 << 20, batchRecords: 200000, relations: intelligence.NewRelationships(true)}, nil
}
func recordSpoolParent(workspace string) (string, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	parent := filepath.Join(root, ".atlas-private")
	if err = os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("materialization scratch parent invalid")
	}
	return parent, nil
}
