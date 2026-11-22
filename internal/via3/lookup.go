package via3

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	mathbits "math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	querycontract "vansail-ip-atlas/tools/query_contract"
)

type GeoAnswer struct {
	Country             *string  `json:"country"`
	RegistrationCountry *string  `json:"registrationCountry"`
	Region              *string  `json:"region"`
	City                *string  `json:"city"`
	Latitude            *float64 `json:"latitude"`
	Longitude           *float64 `json:"longitude"`
	Precision           *string  `json:"precision"`
}
type NetworkAnswer struct {
	Prefix       string   `json:"prefix"`
	Name         *string  `json:"name"`
	Organization *string  `json:"organization"`
	ISP          *string  `json:"isp"`
	Origins      []uint32 `json:"origins"`
}
type UsageAnswer struct {
	Type              string `json:"type"`
	Assignment        string `json:"assignment"`
	Anycast           *bool  `json:"anycast"`
	DirectedBroadcast *bool  `json:"directedBroadcast"`
}
type LayerAnswer struct {
	Exact     *float64 `json:"exact"`
	Prefix    *float64 `json:"prefix"`
	ASN       *float64 `json:"asn"`
	Neighbors *float64 `json:"neighbors"`
}
type QualityAnswer struct {
	Score      *uint8         `json:"score"`
	Confidence string         `json:"confidence"`
	Reasons    []string       `json:"reasons"`
	Layers     LayerAnswer    `json:"layers"`
	Coverage   CoverageAnswer `json:"coverage"`
}
type CoverageLayers struct {
	Exact     string `json:"exact"`
	Prefix    string `json:"prefix"`
	ASN       string `json:"asn"`
	Neighbors string `json:"neighbors"`
}
type CoverageAnswer struct {
	Status string         `json:"status"`
	Layers CoverageLayers `json:"layers"`
}

func coverageAnswer(flags byte, ipv6 bool) CoverageAnswer {
	value := CoverageAnswer{Status: "incomplete", Layers: CoverageLayers{"unassessed", "unassessed", "unassessed", "unassessed"}}
	for i, target := range []*string{&value.Layers.Exact, &value.Layers.Prefix, &value.Layers.ASN, &value.Layers.Neighbors} {
		if flags&(1<<i) != 0 {
			*target = "assessed"
		}
	}
	if flags&16 != 0 {
		value.Status = "complete"
	}
	if ipv6 {
		value.Layers.Neighbors = "not_applicable"
	}
	return value
}

type ASNAnswer struct {
	ASN           uint32   `json:"asn"`
	Name          *string  `json:"name"`
	Organization  *string  `json:"organization"`
	Country       *string  `json:"country"`
	Risk          *float64 `json:"risk"`
	RiskBand      string   `json:"riskBand"`
	Confidence    string   `json:"confidence"`
	Prefixes      []string `json:"prefixes"`
	PrefixCursor  *uint32  `json:"prefixCursor"`
	CustomerCone  *uint32  `json:"customerCone"`
	TransitDegree *uint32  `json:"transitDegree"`
	NetworkClass  string   `json:"networkClass"`
	Stability     string   `json:"stability"`
}
type PathAnswer struct {
	Origin        uint32          `json:"origin"`
	ASNs          []uint32        `json:"asns"`
	Visibility    string          `json:"visibility"`
	GraphEligible bool            `json:"graphEligible"`
	Segments      []SegmentAnswer `json:"segments"`
}
type SegmentAnswer struct {
	Type string   `json:"type"`
	ASNs []uint32 `json:"asns"`
}
type RelationshipAnswer struct {
	From     uint32 `json:"from"`
	To       uint32 `json:"to"`
	Relation string `json:"relation"`
	Observed bool   `json:"observed"`
	Inferred bool   `json:"inferred"`
}
type TierAnswer struct {
	ASN          uint32 `json:"asn"`
	NetworkClass string `json:"networkClass"`
	Stability    string `json:"stability"`
}
type RPKIAnswer struct {
	Origin     uint32 `json:"origin"`
	Status     string `json:"status"`
	ObservedAt *int64 `json:"observedAt"`
	ValidUntil *int64 `json:"validUntil"`
}
type BGPAnswer struct {
	Origins       []uint32             `json:"origins"`
	Paths         []PathAnswer         `json:"paths"`
	Relationships []RelationshipAnswer `json:"relationships"`
	Tier1         []TierAnswer         `json:"tier1"`
	RPKI          []RPKIAnswer         `json:"rpki"`
}
type LookupAnswer struct {
	Q          string         `json:"q"`
	Kind       string         `json:"kind"`
	ReleaseID  string         `json:"releaseId"`
	Synthetic  bool           `json:"synthetic"`
	ValidUntil int64          `json:"validUntil"`
	Geo        *GeoAnswer     `json:"geo"`
	Network    *NetworkAnswer `json:"network"`
	Usage      *UsageAnswer   `json:"usage"`
	Quality    *QualityAnswer `json:"observedRisk"`
	ASNs       []ASNAnswer    `json:"asns"`
	BGP        BGPAnswer      `json:"bgp"`
}
type CellAnswer struct {
	IP         string   `json:"ip"`
	Observed   bool     `json:"observed"`
	Score      *uint8   `json:"observedRiskScore"`
	Confidence string   `json:"confidence"`
	Coverage   string   `json:"coverage"`
	Reasons    []string `json:"reasons"`
	Usage      string   `json:"usage"`
	Origins    []uint32 `json:"origins"`
}
type ClassCAnswer struct {
	Prefix         string       `json:"prefix"`
	Cells          []CellAnswer `json:"cells"`
	ObservedCount  int          `json:"observedCount"`
	AssessedCount  int          `json:"assessedCount"`
	PositiveCount  int          `json:"positiveCount"`
	ScoredCount    int          `json:"scoredCount"`
	AggregateScore *uint8       `json:"meanObservedRisk"`
}
type ASNPrefixPage struct {
	ASN        uint32   `json:"asn"`
	Prefixes   []string `json:"prefixes"`
	NextCursor *uint32  `json:"nextCursor"`
}

func (r *Release) prefixPage(ctx context.Context, s *Shard, row []byte, asn, cursor uint32) (ASNPrefixPage, error) {
	answer := ASNPrefixPage{ASN: asn, Prefixes: []string{}}
	count := u32(row, 40)
	if count == 0 && cursor == 0 {
		return answer, nil
	}
	if cursor >= count {
		return answer, fail("invalid_cursor")
	}
	p := s.row(12, u32(row, 36)+cursor)
	target, err := r.reference(ctx, s, u32(p, 0))
	if err != nil {
		return answer, err
	}
	if target.Kind != 8 || target.rowCount(2) != 0 || target.rowCount(3) != 0 || target.rowCount(7) != 0 || target.rowCount(12) != 0 {
		return answer, fail("record")
	}
	physicalRows := target.rowCount(11)
	first, total := u32(p, 4), u32(p, 8)
	if !rangeOK(first, total, physicalRows) {
		return answer, fail("record")
	}
	answer.Prefixes = make([]string, total)
	if target.lookup != nil && len(target.lookup.prefixLabels) == physicalRows {
		// Strings are immutable metadata; callers always own their slice and
		// its mutable headers. No decoded shard bytes back these strings.
		copy(answer.Prefixes, target.lookup.prefixLabels[first:first+total])
	} else if labels := target.cachedPrefixSpan(first, total); labels != nil {
		copy(answer.Prefixes, labels)
	} else {
		for k := first; k < first+total; k++ {
			key := target.row(11, k)
			ip, _ := keyAddr(key)
			answer.Prefixes[k-first] = netip.PrefixFrom(ip, int(key[1])).String()
		}
		if physicalRows > prefixPageSize && physicalRows <= prefixObjectRows && s.lookup != nil {
			r.retainPrefixSpan(s.lookup.references[u32(p, 0)], first, answer.Prefixes)
		}
	}
	if cursor+1 < count {
		next := cursor + 1
		answer.NextCursor = &next
	}
	return answer, nil
}
func (s *Shard) RowsMust(id uint16) []byte { b, _ := s.Rows(id); return b }
func (r *Release) Prefixes(ctx context.Context, q string, cursor uint32) (result ASNPrefixPage, resultErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverNativeRead(&resultErr)
	input, err := querycontract.ParseInput(q)
	if err != nil || input.Kind != "asn" {
		return ASNPrefixPage{}, fail("invalid_input")
	}
	r.beginQuery()
	defer r.endQuery()
	if err = ctx.Err(); err != nil {
		return ASNPrefixPage{}, err
	}
	if err = r.current(); err != nil {
		return ASNPrefixPage{}, err
	}
	answer, err := r.prefixes(ctx, q, cursor)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = r.current()
	}
	return answer, err
}
func (r *Release) prefixes(ctx context.Context, q string, cursor uint32) (ASNPrefixPage, error) {
	input, err := querycontract.ParseInput(q)
	if err != nil || input.Kind != "asn" {
		return ASNPrefixPage{}, fail("invalid_input")
	}
	asn64, _ := strconv.ParseUint(input.Canonical[2:], 10, 32)
	asn := uint32(asn64)
	s, err := r.asnDestination(ctx, asn, 8)
	if err != nil {
		return ASNPrefixPage{}, err
	}
	if s != nil {
		if row, ok := s.ASNRecord(asn); ok {
			return r.prefixPage(ctx, s, row, asn, cursor)
		}
	}
	if cursor != 0 {
		return ASNPrefixPage{}, fail("invalid_cursor")
	}
	return ASNPrefixPage{ASN: asn, Prefixes: []string{}}, nil
}

type Release struct {
	mu             sync.Mutex
	Manifest       Manifest
	load           func(string) ([]byte, error)
	cacheBytes     int
	activeBytes    int
	routerBytes    int
	residentBytes  int
	native         *nativeIndex
	closed         bool
	preparing      bool
	router         *Shard
	references     map[string]*objectReference
	cacheHead      *objectReference
	cacheTail      *objectReference
	usedReferences []*objectReference
	Clock          func() int64
	Reads          int
}

// These are immutable views of a fully validated shard, not query/answer caches.
// The metadata is owned by its shard and is released with it on cache eviction.
// Directory strings reuse canonical manifest hash strings; no mutable answer
// or caller-owned scalar is retained here.
// Prefix search adds one u32 ordinal per 32-byte
// prefix row (at most 4 MiB for a 32 MiB decoded object), plus fixed family bounds.
// These are native index metadata, not extra decoded bytes in the shared Go/TS
// payload profile. They are owned and evicted with the shard; measured process
// RSS includes their allocation. Reference pointers cost one word per directory
// row; all metadata/slot populations remain bounded by the validated inventory.
// Optional canonical prefix strings come from validated logical spans and are
// charged to the same cache/live budgets as their owning decoded shard.
type shardLookup struct {
	rows         [13][]byte
	widths       [13]int
	depths       [2][3]uint64
	references   []*objectReference
	prefixes     [2]prefixLookup
	prefixLabels []string
	prefixSpans  []cachedPrefixSpan
	owner        *objectReference
	graphIndex   *pathGraphIndex
	routerASNs   *routerASNDirectory
}

type prefixLookup struct {
	parents  []uint32  // immediate containing prefix, or None; never answer data
	families [3]uint32 // contiguous ranges in the original address-ordered rows
}

type objectReference struct {
	info                 ObjectInfo
	shard                *Shard
	size                 int
	onsite               *indexedShard
	prefixLabelBytes     int
	query, cache, router bool
	previous, next       *objectReference // bounded intrusive FIFO cache links
}

func shardLookupMetadata(s *Shard, references []*objectReference) *shardLookup {
	index := &shardLookup{references: references}
	for _, section := range s.Sections {
		index.rows[section.ID] = section.Data[8:]
		index.widths[section.ID] = int(u32(section.Data, 4))
	}
	for section, id := range []uint16{1, 8} {
		rows := index.rows[id]
		prefixes := &index.prefixes[section]
		// RPKI has repeated prefix keys for distinct origins and retains its
		// specialized origin-run search. Other validated prefix keys are unique.
		if s.Kind != 9 {
			prefixes.parents = make([]uint32, len(rows)/32)
		}
		var stack [2][130]uint32 // /0 through /128, plus explicit/exact tie
		var heights [2]int
		for p := 0; p < len(rows); p += 32 {
			family := 0
			if rows[p] == 6 {
				family = 1
			}
			depth := int(rows[p+1])
			index.depths[family][depth/64] |= 1 << (depth % 64)
			prefixes.families[family+1]++
			if s.Kind == 9 {
				continue
			}
			addr, _ := keyAddr(rows[p : p+32])
			height := heights[family]
			for height > 0 {
				previous := int(stack[family][height-1]) * 32
				start, _ := keyAddr(rows[previous : previous+32])
				if netip.PrefixFrom(start, int(rows[previous+1])).Contains(addr) {
					break
				}
				height--
			}
			ordinal := uint32(p / 32)
			prefixes.parents[ordinal] = None
			if height > 0 {
				prefixes.parents[ordinal] = stack[family][height-1]
			}
			stack[family][height] = ordinal
			heights[family] = height + 1
		}
		prefixes.families[2] += prefixes.families[1]
	}
	return index
}

func strictJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return fail("manifest")
	}
	if !bytes.Equal(canonical(target), data) {
		return fail("manifest")
	}
	return nil
}
func validHash(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && value == strings.ToLower(value)
}
func validPartition(value string) bool {
	if value == "all" {
		return true
	}
	if strings.HasPrefix(value, "asn:") {
		p := strings.Split(value, ":")
		if len(p) != 3 {
			return false
		}
		a, e1 := strconv.ParseUint(p[1], 10, 32)
		b, e2 := strconv.ParseUint(p[2], 10, 32)
		if e1 != nil || e2 != nil || a > b || strconv.FormatUint(a, 10) != p[1] || strconv.FormatUint(b, 10) != p[2] {
			return false
		}
		_, e1 = querycontract.ParseInput("AS" + p[1])
		_, e2 = querycontract.ParseInput("AS" + p[2])
		return e1 == nil && e2 == nil && !(a <= 23456 && b >= 23456) && !(a <= 131071 && b >= 64496)
	}
	if len(value) < 4 || (value[:2] != "4:" && value[:2] != "6:") {
		return false
	}
	p := strings.Split(value[2:], "/")
	if len(p) != 2 || len(p[0]) != 32 || p[0] != strings.ToLower(p[0]) {
		return false
	}
	a, e1 := hex.DecodeString(p[0])
	n, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || n < 0 || n > 128 || strconv.Itoa(n) != p[1] {
		return false
	}
	row := make([]byte, 32)
	if value[0] == '4' {
		row[0] = 4
	} else {
		row[0] = 6
	}
	row[1] = byte(n)
	copy(row[4:], a)
	return validKey(row)
}
func NewRelease(pointerBytes, manifestBytes []byte, load func(string) ([]byte, error), clock func() int64) (*Release, error) {
	var pointer Pointer
	var manifest Manifest
	if strictJSON(pointerBytes, &pointer) != nil || strictJSON(manifestBytes, &manifest) != nil {
		return nil, fail("manifest")
	}
	if len(pointerBytes) > 4096 || len(manifestBytes) > 4<<20 || !validHash(pointer.ReleaseID) || !validHash(pointer.ManifestSHA256) || pointer.FormatVersion != 3 || manifest.FormatVersion != 3 || manifest.SchemaVersion != 5 || manifest.Codec != "zstd-1" || (manifest.Mode != "synthetic" && manifest.Mode != "production") || len(manifest.Objects) == 0 || len(manifest.Objects) >= 18500 || pointer.ManifestPath != "/_atlas/releases/"+manifest.ReleaseID+"/manifest.json" || pointer.ReleaseID != manifest.ReleaseID || Hash(manifestBytes) != pointer.ManifestSHA256 || manifest.ValidFrom < 0 || manifest.ValidUntil <= manifest.ValidFrom || manifest.ValidUntil-manifest.ValidFrom > 720*3600 || manifest.ValidUntil > 9007199254740991 {
		return nil, fail("manifest")
	}
	desc := Descriptor{Codec: manifest.Codec, FormatVersion: 3, Mode: manifest.Mode, Objects: manifest.Objects, SchemaVersion: 5, ValidFrom: manifest.ValidFrom, ValidUntil: manifest.ValidUntil}
	if Hash(canonical(desc)) != manifest.ReleaseID {
		return nil, fail("manifest")
	}
	slots := make([]objectReference, len(manifest.Objects))
	r := &Release{Manifest: manifest, references: make(map[string]*objectReference, len(manifest.Objects)),
		usedReferences: make([]*objectReference, 0, len(manifest.Objects)), load: load, Clock: clock}
	previous := ""
	routerHash := ""
	for index, o := range manifest.Objects {
		h, err := hex.DecodeString(o.SHA256)
		if err != nil || len(h) != 32 || o.SHA256 != strings.ToLower(o.SHA256) || o.SHA256 <= previous || o.Kind < 1 || o.Kind > 14 || o.Bytes < 64 || o.Bytes >= MaxFile || !validPartition(o.Partition) {
			return nil, fail("manifest")
		}
		previous = o.SHA256
		slots[index].info = o
		r.references[o.SHA256] = &slots[index]
		if o.Kind == 1 {
			if routerHash != "" || o.Partition != "all" {
				return nil, fail("manifest")
			}
			routerHash = o.SHA256
		}
	}
	if routerHash == "" {
		return nil, fail("manifest")
	}
	if err := r.current(); err != nil {
		return nil, err
	}
	router, err := r.object(context.Background(), routerHash)
	if err != nil {
		return nil, err
	}
	r.router = router
	r.routerBytes = r.references[routerHash].size
	r.references[routerHash].router = true
	r.endQuery()
	return r, nil
}
func OpenRelease(root string, clock func() int64) (*Release, error) {
	p, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err != nil {
		return nil, err
	}
	var pointer Pointer
	if strictJSON(p, &pointer) != nil || !validHash(pointer.ReleaseID) {
		return nil, fail("manifest")
	}
	m, err := os.ReadFile(filepath.Join(root, "releases", pointer.ReleaseID, "manifest.json"))
	if err != nil {
		return nil, err
	}
	r, err := NewRelease(p, m, func(hash string) ([]byte, error) {
		if len(hash) != 64 {
			return nil, fail("manifest")
		}
		file, err := os.Open(filepath.Join(root, "objects", hash+".via3"))
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if info.Size() < 64 || info.Size() >= MaxFile {
			return nil, fail("length")
		}
		return io.ReadAll(io.LimitReader(file, MaxFile))
	}, clock)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Release) current() error {
	if r.closed {
		return fail("closed")
	}
	now := r.Clock()
	if now < r.Manifest.ValidFrom || now >= r.Manifest.ValidUntil {
		return fail("expired")
	}
	return nil
}
func (r *Release) object(ctx context.Context, hash string) (*Shard, error) {
	if err := r.current(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reference := r.references[hash]
	if reference == nil {
		return nil, fail("missing_object")
	}
	return r.objectReference(ctx, reference)
}

func (r *Release) objectReference(ctx context.Context, reference *objectReference) (*Shard, error) {
	if err := r.current(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if reference.shard != nil {
		if !reference.query {
			if err := r.admitReference(reference, reference.size); err != nil {
				return nil, err
			}
		}
		return reference.shard, nil
	}
	if reference.onsite != nil {
		if err := r.admitReference(reference, reference.onsite.decoded); err != nil {
			return nil, err
		}
		reference.shard = &reference.onsite.shard
		r.cacheReference(reference)
		return reference.shard, nil
	}
	info := reference.info
	hash := info.SHA256
	b, err := r.load(hash)
	if err != nil {
		return nil, fail("missing_object")
	}
	r.Reads++
	if len(b) != info.Bytes || Hash(b) != hash {
		return nil, fail("integrity")
	}
	if len(b) < 64 {
		return nil, fail("length")
	}
	declared := u64(b, 36)
	if declared > PublicObjectDecoded {
		return nil, fail("resource_limit")
	}
	if err := r.admitReference(reference, int(declared)); err != nil {
		return nil, err
	}
	s, err := Read(ctx, b)
	if err != nil {
		return nil, err
	}
	if s.Kind != info.Kind {
		return nil, fail("schema")
	}
	if err := ValidatePublicProfile(s); err != nil {
		return nil, err
	}
	dir, _ := s.Rows(7)
	references := make([]*objectReference, len(dir)/40)
	for p := 0; p < len(dir); p += 40 {
		var encoded [64]byte
		hex.Encode(encoded[:], dir[p+8:p+40])
		target := r.references[string(encoded[:])]
		if target == nil || target.info.Kind != u16(dir, p) || target.info.Bytes != int(u32(dir, p+4)) || target == reference {
			return nil, fail("record")
		}
		references[p/40] = target
	}
	if strings.HasPrefix(info.Partition, "4:") || strings.HasPrefix(info.Partition, "6:") {
		parts := strings.Split(info.Partition[2:], "/")
		if len(parts) != 2 {
			return nil, fail("manifest")
		}
		address, err := hex.DecodeString(parts[0])
		n, err2 := strconv.Atoi(parts[1])
		if err != nil || err2 != nil || len(address) != 16 {
			return nil, fail("manifest")
		}
		key := make([]byte, 32)
		if info.Partition[0] == '4' {
			key[0] = 4
		} else {
			key[0] = 6
		}
		key[1] = byte(n)
		copy(key[4:], address)
		if !validKey(key) {
			return nil, fail("manifest")
		}
		partitionAddr, _ := keyAddr(key)
		overlay, _ := s.Rows(8)
		for p := 0; p < len(overlay); p += 32 {
			a, _ := keyAddr(overlay[p : p+32])
			prefix := netip.PrefixFrom(a, int(overlay[p+1]))
			if !prefix.Contains(partitionAddr) || int(overlay[p+1]) > n {
				return nil, fail("record")
			}
		}
		local, _ := s.Rows(1)
		partitionPrefix := netip.PrefixFrom(partitionAddr, n)
		for p := 0; p < len(local); p += 32 {
			a, _ := keyAddr(local[p : p+32])
			if local[p] != key[0] || int(local[p+1]) < n || !partitionPrefix.Contains(a) {
				return nil, fail("record")
			}
		}
	}
	if strings.HasPrefix(info.Partition, "asn:") {
		parts := strings.Split(info.Partition, ":")
		first, _ := strconv.ParseUint(parts[1], 10, 32)
		last, _ := strconv.ParseUint(parts[2], 10, 32)
		index, _ := s.Rows(2)
		for p := 0; p < len(index); p += 8 {
			asn := uint64(u32(index, p))
			if asn < first || asn > last {
				return nil, fail("record")
			}
		}
	}
	s.lookup = shardLookupMetadata(&s, references)
	if s.Kind == 1 {
		r.prepareRouterASNs(reference, &s)
	}
	if s.Kind == 11 || s.Kind == 12 {
		s.lookup.owner = reference
	}
	if !r.preparing {
		r.preparePrefixLabels(reference, &s)
	}
	reference.shard = &s
	r.cacheReference(reference)
	return &s, nil
}

// Prefix pages normally contain at most 256 rows. Preformat only this bounded
// case, after complete payload validation, and charge the allocation before it
// is made. Packed files retain only spans that are subsequently requested.
// Individual strings avoid keeping an entire page alive for a one-prefix answer.
func (r *Release) preparePrefixLabels(reference *objectReference, shard *Shard) {
	if shard.Kind != 8 || shard.lookup == nil {
		return
	}
	rows, _ := shard.Rows(11)
	count := len(rows) / 24
	if count == 0 || count > prefixPageSize {
		return
	}
	// A string header occupies at most 16 bytes on supported Go architectures;
	// canonical IPv6 prefix text is at most 43 bytes, including /128.
	reserved := count * (16 + 43)
	if !r.reservePrefixMetadata(reference, reserved) {
		return
	}
	labels := make([]string, count)
	used := count * 16
	for i := range labels {
		row := rows[i*24 : (i+1)*24]
		address, _ := keyAddr(row)
		labels[i] = netip.PrefixFrom(address, int(row[1])).String()
		used += len(labels[i])
	}
	reference.size -= reserved - used
	r.residentBytes -= reserved - used
	r.activeBytes -= reserved - used
	reference.prefixLabelBytes = used
	shard.lookup.prefixLabels = labels
}

func (r *Release) reference(ctx context.Context, from *Shard, index uint32) (*Shard, error) {
	if from.lookup != nil {
		if uint64(index) >= uint64(len(from.lookup.references)) {
			return nil, fail("record")
		}
		return r.objectReference(ctx, from.lookup.references[index])
	}
	dir, _ := from.Rows(7)
	if uint64(index) >= uint64(len(dir)/40) {
		return nil, fail("record")
	}
	// Resolve the binary reference to the already validated canonical manifest
	// string. The temporary string is used only for a map lookup, so repeated
	// dictionary/path references do not allocate two hexadecimal copies each.
	var encoded [64]byte
	hex.Encode(encoded[:], dir[int(index)*40+8:int(index)*40+40])
	reference := r.references[string(encoded[:])]
	if reference == nil {
		return nil, fail("missing_object")
	}
	return r.objectReference(ctx, reference)
}
func (r *Release) label(ctx context.Context, from *Shard, row []byte, p int, target *string, labels *lookupLabels) (*string, error) {
	object, id := u32(row, p), u32(row, p+4)
	if object == None && id == None {
		return nil, nil
	}
	dictionary, err := r.reference(ctx, from, object)
	if err != nil {
		return nil, err
	}
	if dictionary.Kind != 14 {
		return nil, fail("record")
	}
	if uint64(id)+1 >= uint64(dictionary.rowCount(5)) {
		return nil, fail("record")
	}
	offsets := dictionary.rowSpan(5, id, 2)
	first, end := u32(offsets, 0), u32(offsets, 4)
	return labels.add(dictionary.rowSpan(6, first, end-first), target)
}
func (s *Shard) ASNRecord(asn uint32) ([]byte, bool) {
	if s.lookup != nil && s.lookup.routerASNs != nil {
		ordinal, ok := s.lookup.routerASNs.ordinal(asn)
		if !ok {
			return nil, false
		}
		index := u32(s.lookup.rows[2], int(ordinal)*8+4)
		return s.Record(index), true
	}
	first, _, ok := s.asnBounds(asn)
	if !ok {
		return nil, false
	}
	return s.Record(first), true
}

type destinationSet [15]*Shard

func (d destinationSet) ipRecord(kind uint16, addr netip.Addr) ([]byte, netip.Prefix) {
	if s := d[kind]; s != nil {
		row, p, _ := s.findPrefix(addr)
		return row, p
	}
	return nil, netip.Prefix{}
}

func (r *Release) asnDestinations(ctx context.Context, asn uint32) (destinationSet, error) {
	row, ok := r.router.ASNRecord(asn)
	return r.rowDestinations(ctx, row, ok)
}

// Relationship lookup needs only its own routed shard. Loading every ASN fact
// object for every observed adjacency would decode and pin unrelated data.
func (r *Release) asnDestination(ctx context.Context, asn uint32, kind uint16) (*Shard, error) {
	row, ok := r.router.ASNRecord(asn)
	return r.rowDestination(ctx, row, ok, kind)
}

func (r *Release) rowDestination(ctx context.Context, row []byte, ok bool, kind uint16) (*Shard, error) {
	if !ok {
		return nil, nil
	}
	id, found := r.router.destinationID(row, kind)
	if !found {
		return nil, nil
	}
	return r.reference(ctx, r.router, id)
}

func (s *Shard) destinationID(row []byte, kind uint16) (uint32, bool) {
	ints, _ := s.Rows(4)
	directory, _ := s.Rows(7)
	for j := uint32(0); j < uint32(u16(row, 4)); j++ {
		object := u32(ints, int(u32(row, 0)+j)*4)
		if u16(directory, int(object)*40) == kind {
			return object, true
		}
	}
	return 0, false
}
func (r *Release) rowDestinations(ctx context.Context, row []byte, ok bool) (destinationSet, error) {
	var out destinationSet
	if !ok {
		return out, nil
	}
	ints, _ := r.router.Rows(4)
	for j := uint32(0); j < uint32(u16(row, 4)); j++ {
		object := u32(ints, int(u32(row, 0)+j)*4)
		s, err := r.reference(ctx, r.router, object)
		if err != nil {
			return out, err
		}
		out[s.Kind] = s
	}
	return out, nil
}
func country(v uint16) *string {
	if v == 0 {
		return nil
	}
	n := int(v) - 1
	s := string([]byte{byte(n/26) + 'A', byte(n%26) + 'A'})
	return &s
}

// Optional pointers and their owning result are allocated together. Each block
// is fresh for this answer, never retained on Release or shared across queries.
// Keep separate fact blocks so a sparse answer does not allocate absent views.
type geoLookupValues struct {
	answer                                         GeoAnswer
	country, registration, region, city, precision string
	latitude, longitude                            float64
}
type networkLookupValues struct {
	answer                  NetworkAnswer
	name, organization, isp string
}
type usageLookupValues struct {
	answer                     UsageAnswer
	anycast, directedBroadcast bool
}
type qualityLookupValues struct {
	answer                        QualityAnswer
	exact, prefix, asn, neighbors float64
	score                         uint8
}

// Dense IP answers use one caller-owned allocation for the four present
// families. Sparse coverage still creates only the individual values it has.
type ipLookupValues struct {
	geo     geoLookupValues
	network networkLookupValues
	usage   usageLookupValues
	quality qualityLookupValues
}

type singleOriginValues struct {
	values    [1]asnLookupValues
	aggregate [1]ASNAnswer
	tier      [1]TierAnswer
	rpki      [1]RPKIAnswer
}

type asnLookupValues struct {
	country, name, organization string
	risk                        float64
	customerCone, transitDegree uint32
}

// Wire country values are a fixed two-letter enum. Their immutable spelling
// needs no per-answer byte allocation; each mutable string header is still
// stored in its own caller-owned answer block.
const countrySpellings = "AAABACADAEAFAGAHAIAJAKALAMANAOAPAQARASATAUAVAWAXAYAZ" +
	"BABBBCBDBEBFBGBHBIBJBKBLBMBNBOBPBQBRBSBTBUBVBWBXBYBZ" +
	"CACBCCCDCECFCGCHCICJCKCLCMCNCOCPCQCRCSCTCUCVCWCXCYCZ" +
	"DADBDCDDDEDFDGDHDIDJDKDLDMDNDODPDQDRDSDTDUDVDWDXDYDZ" +
	"EAEBECEDEEEFEGEHEIEJEKELEMENEOEPEQERESETEUEVEWEXEYEZ" +
	"FAFBFCFDFEFFFGFHFIFJFKFLFMFNFOFPFQFRFSFTFUFVFWFXFYFZ" +
	"GAGBGCGDGEGFGGGHGIGJGKGLGMGNGOGPGQGRGSGTGUGVGWGXGYGZ" +
	"HAHBHCHDHEHFHGHHHIHJHKHLHMHNHOHPHQHRHSHTHUHVHWHXHYHZ" +
	"IAIBICIDIEIFIGIHIIIJIKILIMINIOIPIQIRISITIUIVIWIXIYIZ" +
	"JAJBJCJDJEJFJGJHJIJJJKJLJMJNJOJPJQJRJSJTJUJVJWJXJYJZ" +
	"KAKBKCKDKEKFKGKHKIKJKKKLKMKNKOKPKQKRKSKTKUKVKWKXKYKZ" +
	"LALBLCLDLELFLGLHLILJLKLLLMLNLOLPLQLRLSLTLULVLWLXLYLZ" +
	"MAMBMCMDMEMFMGMHMIMJMKMLMMMNMOMPMQMRMSMTMUMVMWMXMYMZ" +
	"NANBNCNDNENFNGNHNINJNKNLNMNNNONPNQNRNSNTNUNVNWNXNYNZ" +
	"OAOBOCODOEOFOGOHOIOJOKOLOMONOOOPOQOROSOTOUOVOWOXOYOZ" +
	"PAPBPCPDPEPFPGPHPIPJPKPLPMPNPOPPPQPRPSPTPUPVPWPXPYPZ" +
	"QAQBQCQDQEQFQGQHQIQJQKQLQMQNQOQPQQQRQSQTQUQVQWQXQYQZ" +
	"RARBRCRDRERFRGRHRIRJRKRLRMRNRORPRQRRRSRTRURVRWRXRYRZ" +
	"SASBSCSDSESFSGSHSISJSKSLSMSNSOSPSQSRSSSTSUSVSWSXSYSZ" +
	"TATBTCTDTETFTGTHTITJTKTLTMTNTOTPTQTRTSTTTUTVTWTXTYTZ" +
	"UAUBUCUDUEUFUGUHUIUJUKULUMUNUOUPUQURUSUTUUUVUWUXUYUZ" +
	"VAVBVCVDVEVFVGVHVIVJVKVLVMVNVOVPVQVRVSVTVUVVVWVXVYVZ" +
	"WAWBWCWDWEWFWGWHWIWJWKWLWMWNWOWPWQWRWSWTWUWVWWWXWYWZ" +
	"XAXBXCXDXEXFXGXHXIXJXKXLXMXNXOXPXQXRXSXTXUXVXWXXXYXZ" +
	"YAYBYCYDYEYFYGYHYIYJYKYLYMYNYOYPYQYRYSYTYUYVYWYXYYYZ" +
	"ZAZBZCZDZEZFZGZHZIZJZKZLZMZNZOZPZQZRZSZTZUZVZWZXZYZZ"

func countryInto(v uint16, target *string) *string {
	if v == 0 {
		return nil
	}
	n := (int(v) - 1) * 2
	*target = countrySpellings[n : n+2]
	return target
}
func confidence(v byte) string { return []string{"unrated", "low", "medium", "high"}[v] }
func usageName(v byte) string {
	return []string{"unknown", "residential", "business", "mobile", "datacenter", "hosting", "education", "government"}[v]
}
func className(v byte) string {
	return []string{"unknown", "tier1_candidate", "global_transit", "regional_transit", "access_network"}[v]
}
func stability(v byte) string { return []string{"unavailable", "pending", "stable"}[v] }
func reasons(v uint32) []string {
	names := []string{"malware", "botnet", "command_control", "abuse", "fraud", "scanning", "spam", "tor", "vpn", "proxy", "datacenter", "hosting", "asn_context", "subnet_context"}
	out := make([]string, 0, mathbits.OnesCount32(v&((1<<len(names))-1)))
	for bit, name := range names {
		if v&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	return out
}
func riskValue(row []byte, p int, bit uint, target *float64) *float64 {
	if !present(row, bit) {
		return nil
	}
	*target = float64(u32(row, p)) / 1000000
	return target
}
func origins(s *Shard, row []byte) []uint32 {
	ints := s.rowSpan(4, u32(row, 4), u32(row, 8))
	out := make([]uint32, u32(row, 8))
	for i := range out {
		out[i] = u32(ints, i*4)
	}
	return out
}

func (r *Release) Lookup(ctx context.Context, q string) (result LookupAnswer, resultErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverNativeRead(&resultErr)
	input, err := querycontract.ParseInput(q)
	if err != nil {
		return LookupAnswer{}, err
	}
	r.beginQuery()
	defer r.endQuery()
	var labels lookupLabels
	defer labels.finish() // Preserve partial error answers before releasing pins.
	budget := newAnswerBudget()
	if err = r.current(); err != nil {
		return LookupAnswer{}, err
	}
	answer := LookupAnswer{Q: input.Canonical, Kind: input.Kind, ReleaseID: r.Manifest.ReleaseID, Synthetic: r.Manifest.Mode == "synthetic", ValidUntil: r.Manifest.ValidUntil, ASNs: []ASNAnswer{}, BGP: BGPAnswer{Origins: []uint32{}, Paths: []PathAnswer{}, Relationships: []RelationshipAnswer{}, Tier1: []TierAnswer{}, RPKI: []RPKIAnswer{}}}
	var addr netip.Addr
	var dest destinationSet
	if input.Kind == "ip" {
		addr = netip.MustParseAddr(input.Canonical)
		row, _, ok := r.router.findPrefix(addr)
		dest, err = r.rowDestinations(ctx, row, ok)
		if err != nil {
			return answer, err
		}
	}
	var announcement netip.Prefix
	var geoValues *geoLookupValues
	networkOriginsKnown := false
	if input.Kind == "ip" {
		geoRow, _ := dest.ipRecord(2, addr)
		networkRow, networkPrefix := dest.ipRecord(4, addr)
		usageRow, _ := dest.ipRecord(5, addr)
		qualityRow, _ := dest.ipRecord(6, addr)
		var network *networkLookupValues
		var usage *usageLookupValues
		var quality *qualityLookupValues
		if geoRow != nil && networkRow != nil && usageRow != nil && qualityRow != nil {
			all := new(ipLookupValues)
			geoValues, network, usage, quality = &all.geo, &all.network, &all.usage, &all.quality
		}

		if s := dest[2]; s != nil {
			if row := geoRow; row != nil {
				if geoValues == nil {
					geoValues = new(geoLookupValues)
				}
				g := &geoValues.answer
				g.Country, g.RegistrationCountry = countryInto(u16(row, 4), &geoValues.country), countryInto(u16(row, 6), &geoValues.registration)
				if g.Region, err = r.label(ctx, s, row, 8, &geoValues.region, &labels); err != nil {
					return answer, err
				}
				if g.City, err = r.label(ctx, s, row, 16, &geoValues.city, &labels); err != nil {
					return answer, err
				}
				answer.Geo = g
			}
		}
		if s := dest[3]; s != nil {
			if row, _, ok := s.findPrefix(addr); ok && present(row, 4) {
				if answer.Geo == nil {
					geoValues = &geoLookupValues{}
					answer.Geo = &geoValues.answer
				}
				geoValues.latitude, geoValues.longitude = float64(int32(u32(row, 4)))/1000, float64(int32(u32(row, 8)))/1000
				geoValues.precision = []string{"unknown", "country", "region", "city_centroid", "area"}[row[12]]
				answer.Geo.Latitude = &geoValues.latitude
				answer.Geo.Longitude = &geoValues.longitude
				answer.Geo.Precision = &geoValues.precision
			}
		}
		if s := dest[4]; s != nil {
			if row, prefix := networkRow, networkPrefix; row != nil {
				if err := budget.charge(4096 + 16*int(u32(row, 8))); err != nil {
					return answer, err
				}
				values := network
				if values == nil {
					values = new(networkLookupValues)
				}
				values.answer = NetworkAnswer{Prefix: prefix.String(), Origins: origins(s, row)}
				n := &values.answer
				if n.Name, err = r.label(ctx, s, row, 16, &values.name, &labels); err != nil {
					return answer, err
				}
				if n.Organization, err = r.label(ctx, s, row, 24, &values.organization, &labels); err != nil {
					return answer, err
				}
				if n.ISP, err = r.label(ctx, s, row, 32, &values.isp, &labels); err != nil {
					return answer, err
				}
				answer.Network = n
				networkOriginsKnown = present(row, 19)
				if networkOriginsKnown {
					announcement = prefix
				}
				answer.BGP.Origins = n.Origins
			}
		}
		if s := dest[5]; s != nil {
			if row := usageRow; row != nil {
				values := usage
				if values == nil {
					values = new(usageLookupValues)
				}
				values.answer = UsageAnswer{Type: usageName(row[4]), Assignment: []string{"unknown", "native", "broadcast_or_routed"}[row[5]]}
				u := &values.answer
				if present(row, 7) {
					values.anycast = row[6]&1 != 0
					u.Anycast = &values.anycast
				}
				if present(row, 8) {
					values.directedBroadcast = row[6]&2 != 0
					u.DirectedBroadcast = &values.directedBroadcast
				}
				answer.Usage = u
				if u.Anycast != nil && *u.Anycast && answer.Geo != nil {
					answer.Geo.City = nil
					answer.Geo.Latitude = nil
					answer.Geo.Longitude = nil
					answer.Geo.Precision = nil
				}
			}
		}
		if s := dest[6]; s != nil {
			if row := qualityRow; row != nil {
				values := quality
				if values == nil {
					values = new(qualityLookupValues)
				}
				q := &values.answer
				*q = QualityAnswer{Coverage: coverageAnswer(row[11], addr.Is6()), Confidence: confidence(row[10]), Reasons: reasons(u32(row, 4)), Layers: LayerAnswer{Exact: riskValue(row, 12, 10, &values.exact), Prefix: riskValue(row, 16, 11, &values.prefix), ASN: riskValue(row, 20, 12, &values.asn), Neighbors: riskValue(row, 24, 13, &values.neighbors)}}
				if present(row, 9) {
					values.score = row[9]
					q.Score = &values.score
				}
				answer.Quality = q
			}
		}
		if s := dest[10]; s != nil {
			if row, prefix, ok := s.findPrefix(addr); ok {
				if present(row, 19) {
					if err := budget.charge(16 * int(u32(row, 8))); err != nil {
						return answer, err
					}
					values := origins(s, row)
					if networkOriginsKnown && !slices.Equal(answer.Network.Origins, values) {
						return answer, fail("record")
					}
					answer.BGP.Origins = values
					announcement = prefix
				}
			}
		}
	} else {
		n, _ := strconv.ParseUint(input.Canonical[2:], 10, 32)
		answer.BGP.Origins = []uint32{uint32(n)}
	}
	var asnValues []asnLookupValues
	var pairStorage [64]uint64
	ordered := pairStorage[:0]
	var sortedPairs bool
	var components graphComponents
	for _, asn := range answer.BGP.Origins {
		asndest, err := r.asnDestinations(ctx, asn)
		if err != nil {
			return answer, err
		}
		if s := asndest[8]; s != nil {
			if row, ok := s.ASNRecord(asn); ok {
				if err := budget.charge(4096); err != nil {
					return answer, err
				}
				if asnValues == nil {
					if len(answer.BGP.Origins) == 1 {
						single := new(singleOriginValues)
						asnValues = single.values[:]
						answer.ASNs = single.aggregate[:0]
						answer.BGP.Tier1 = single.tier[:0]
						answer.BGP.RPKI = single.rpki[:0]
					} else {
						asnValues = make([]asnLookupValues, len(answer.BGP.Origins))
					}
				}
				values := &asnValues[len(answer.ASNs)]
				a := ASNAnswer{ASN: asn, Country: countryInto(u16(row, 24), &values.country), Risk: riskValue(row, 28, 23, &values.risk), RiskBand: []string{"unknown", "low", "medium", "high"}[row[26]], Confidence: confidence(row[27]), Prefixes: []string{}, NetworkClass: className(row[52]), Stability: stability(row[53])}
				if a.Name, err = r.label(ctx, s, row, 8, &values.name, &labels); err != nil {
					return answer, err
				}
				if a.Organization, err = r.label(ctx, s, row, 16, &values.organization, &labels); err != nil {
					return answer, err
				}
				if present(row, 25) {
					values.customerCone = u32(row, 44)
					a.CustomerCone = &values.customerCone
				}
				if present(row, 26) {
					values.transitDegree = u32(row, 48)
					a.TransitDegree = &values.transitDegree
				}
				if u32(row, 40) > 0 {
					p := s.row(12, u32(row, 36))
					if err := budget.charge(64 * int(u32(p, 8))); err != nil {
						return answer, err
					}
				}
				page, err := r.prefixPage(ctx, s, row, asn, 0)
				if err != nil {
					return answer, err
				}
				a.Prefixes, a.PrefixCursor = page.Prefixes, page.NextCursor
				if cap(answer.ASNs) == 0 {
					answer.ASNs = make([]ASNAnswer, 0, len(answer.BGP.Origins))
				}
				answer.ASNs = append(answer.ASNs, a)
			}
		}
		if s := asndest[11]; s != nil {
			graph := r.pathGraph(s, asn)
			if graph != nil && graph.fits(budget) {
				answer.BGP.Paths = graph.appendPaths(answer.BGP.Paths, asn, budget)
				ordered = append(ordered, graph.pairs...)
				sortedPairs = len(answer.BGP.Origins) == 1
				if sortedPairs {
					components.prepare(s, asn, graph)
				}
			} else {
				firstPath := len(answer.BGP.Paths)
				answer.BGP.Paths, err = s.appendOriginPaths(answer.BGP.Paths, asn, budget)
				if err != nil {
					return answer, err
				}
				for _, path := range answer.BGP.Paths[firstPath:] {
					if path.GraphEligible {
						ordered = appendPathPairs(ordered, path.ASNs)
					}
				}
			}
		}
		if s := asndest[13]; s != nil {
			if row, ok := s.ASNRecord(asn); ok {
				if cap(answer.BGP.Tier1) == 0 {
					answer.BGP.Tier1 = make([]TierAnswer, 0, len(answer.BGP.Origins))
				}
				answer.BGP.Tier1 = append(answer.BGP.Tier1, TierAnswer{ASN: asn, NetworkClass: className(row[8]), Stability: stability(row[9])})
			}
		}
		if input.Kind == "ip" {
			observation := RPKIAnswer{Origin: asn, Status: "unavailable"}
			if s := dest[9]; s != nil {
				if row, ok := s.FindRPKI(addr, asn, announcement); ok {
					observation.Status = []string{"unavailable", "valid", "invalid", "not_found"}[row[8]]
					if row[8] != 0 {
						observedAt, validUntil := int64(u64(row, 16)), int64(u64(row, 24))
						observation.ObservedAt, observation.ValidUntil = &observedAt, &validUntil
					}
				}
			}
			if cap(answer.BGP.RPKI) == 0 {
				answer.BGP.RPKI = make([]RPKIAnswer, 0, len(answer.BGP.Origins))
			}
			answer.BGP.RPKI = append(answer.BGP.RPKI, observation)
		}
	}
	// Only actual consecutive retained path hops are queried. Relationship runs
	// may be large; binary lookup avoids allocating or scanning an ASN's degree.
	if !sortedPairs {
		slices.Sort(ordered)
		ordered = slices.Compact(ordered)
	}
	if err := budget.charge(256 * len(ordered)); err != nil {
		return answer, err
	}
	answer.BGP.Relationships, err = r.relationshipAnswers(ctx, ordered, &components)
	if err != nil {
		return answer, err
	}
	labels.finish()
	if err := ctx.Err(); err != nil {
		return answer, err
	}
	if err := r.current(); err != nil {
		return answer, err
	}
	if err := lookupFits(answer); err != nil {
		return answer, err
	}
	r.retainGraphComponents(&components, len(ordered))
	return answer, nil
}

func (r *Release) ClassC(ctx context.Context, q string) (result *ClassCAnswer, resultErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverNativeRead(&resultErr)
	if _, err := querycontract.ParseInput(q); err != nil {
		return nil, err
	}
	r.beginQuery()
	defer r.endQuery()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.current(); err != nil {
		return nil, err
	}
	answer, err := r.classC(ctx, q)
	if err == nil {
		err = answerFits(answer)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = r.current()
	}
	return answer, err
}
func (r *Release) classC(ctx context.Context, q string) (*ClassCAnswer, error) {
	budget := newAnswerBudget()
	if err := budget.charge(256 * 512); err != nil {
		return nil, err
	}
	input, err := querycontract.ParseInput(q)
	if err != nil {
		return nil, err
	}
	if input.Kind != "ip" {
		return nil, nil
	}
	addr := netip.MustParseAddr(input.Canonical)
	if !addr.Is4() {
		return nil, nil
	}
	routed, _, known := r.router.findPrefix(addr)
	s, err := r.rowDestination(ctx, routed, known, 7)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	row, prefix, ok := s.FindPrefix(addr)
	if !ok {
		return nil, nil
	}
	answer := &ClassCAnswer{Prefix: prefix, Cells: make([]CellAnswer, 256), ObservedCount: int(u16(row, 8)), AssessedCount: int(u16(row, 10)), PositiveCount: int(u16(row, 12)), ScoredCount: int(u16(row, 14))}
	if present(row, 22) {
		v := row[20]
		answer.AggregateScore = &v
	}
	a := addr.As4()
	a[3] = 0
	for suffix := 0; suffix < 256; suffix++ {
		a[3] = byte(suffix)
		answer.Cells[suffix] = CellAnswer{IP: netip.AddrFrom4(a).String(), Confidence: "unrated", Coverage: "incomplete", Reasons: []string{}, Usage: "unknown", Origins: []uint32{}}
	}
	for j := u32(row, 4); j < u32(row, 4)+uint32(u16(row, 8)); j++ {
		cell := s.row(10, j)
		c := &answer.Cells[cell[0]]
		c.Observed = true
		c.Confidence = confidence(cell[9])
		if cell[10] == 1 {
			c.Coverage = "complete"
		}
		c.Reasons = reasons(u32(cell, 4))
		c.Usage = usageName(cell[2])
		if cell[1]&8 != 0 {
			score := cell[8]
			c.Score = &score
		}
		if cell[1]&32 != 0 {
			network, err := r.reference(ctx, s, u32(cell, 16))
			if err != nil {
				return nil, err
			}
			n := network.Record(u32(cell, 20))
			if n == nil {
				return nil, fail("record")
			}
			if err := budget.cellOrigins(int(u32(n, 8))); err != nil {
				return nil, err
			}
			c.Origins = origins(network, n)
		}
	}
	if err := r.current(); err != nil {
		return nil, err
	}
	return answer, nil
}
