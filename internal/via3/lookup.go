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
	"sort"
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
	Score      *uint8      `json:"score"`
	Confidence string      `json:"confidence"`
	Reasons    []string    `json:"reasons"`
	Layers     LayerAnswer `json:"layers"`
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
	Origin uint32 `json:"origin"`
	Status string `json:"status"`
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
	Quality    *QualityAnswer `json:"quality"`
	ASNs       []ASNAnswer    `json:"asns"`
	BGP        BGPAnswer      `json:"bgp"`
}
type CellAnswer struct {
	IP         string   `json:"ip"`
	Observed   bool     `json:"observed"`
	Score      *uint8   `json:"score"`
	Confidence string   `json:"confidence"`
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
	AggregateScore *uint8       `json:"aggregateScore"`
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
	pages, _ := s.Rows(12)
	j := u32(row, 36) + cursor
	p := pages[j*16 : (j+1)*16]
	target, err := r.reference(ctx, s, u32(p, 0))
	if err != nil {
		return answer, err
	}
	if target.Kind != 8 || len(target.RowsMust(2)) != 0 || len(target.RowsMust(3)) != 0 || len(target.RowsMust(7)) != 0 || len(target.RowsMust(12)) != 0 {
		return answer, fail("record")
	}
	rows, _ := target.Rows(11)
	first, total := u32(p, 4), u32(p, 8)
	if !rangeOK(first, total, len(rows)/24) {
		return answer, fail("record")
	}
	for k := first; k < first+total; k++ {
		key := rows[k*24 : (k+1)*24]
		ip, _ := keyAddr(key)
		answer.Prefixes = append(answer.Prefixes, netip.PrefixFrom(ip, int(key[1])).String())
	}
	if cursor+1 < count {
		next := cursor + 1
		answer.NextCursor = &next
	}
	return answer, nil
}
func (s *Shard) RowsMust(id uint16) []byte { b, _ := s.Rows(id); return b }
func (r *Release) Prefixes(ctx context.Context, q string, cursor uint32) (ASNPrefixPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
	dest, err := r.destinations(ctx, input)
	if err != nil {
		return ASNPrefixPage{}, err
	}
	if s := dest[8]; s != nil {
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
	objects        map[string]ObjectInfo
	load           func(string) ([]byte, error)
	cache          map[string]*Shard
	cacheOrder     []string
	cacheBytes     int
	active         map[string]bool
	activeObjects  map[string]*Shard
	activeBytes    int
	routerBytes    int
	residents      map[string]*resident
	residentBytes  int
	router         *Shard
	references     map[string]*objectReference
	usedReferences []*objectReference
	Clock          func() int64
	Reads          int
}

// These are immutable views of a fully validated shard, not query/answer caches.
// The metadata is owned by its shard and is released with it on cache eviction.
// Directory strings reuse canonical manifest hash strings; no mutable answer
// or caller-owned scalar is retained here.
// No decoded payload is copied: row slices are views, reference pointers cost
// one machine word per 40-byte directory row, and the fixed row/depth tables
// occur at most once per loaded manifest object (<18500). Reference-slot and
// used-slot counts are likewise bounded by that manifest inventory. Decoded
// section admission remains unchanged; process RSS still needs full-corpus
// measurement including this bounded metadata and Go allocator overhead.
type shardLookup struct {
	rows       [13][]byte
	widths     [13]int
	depths     [2][129]bool
	references []*objectReference
}

type objectReference struct {
	hash   string
	active *Shard // same query pin as activeObjects; cleared by endQuery
}

func shardLookupMetadata(s *Shard, references []*objectReference) *shardLookup {
	index := &shardLookup{references: references}
	for _, section := range s.Sections {
		index.rows[section.ID] = section.Data[8:]
		index.widths[section.ID] = int(u32(section.Data, 4))
	}
	for _, id := range []uint16{1, 8} {
		rows := index.rows[id]
		for p := 0; p < len(rows); p += 32 {
			family := 0
			if rows[p] == 6 {
				family = 1
			}
			index.depths[family][rows[p+1]] = true
		}
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
	if len(pointerBytes) > 4096 || len(manifestBytes) > 4<<20 || !validHash(pointer.ReleaseID) || !validHash(pointer.ManifestSHA256) || pointer.FormatVersion != 3 || manifest.FormatVersion != 3 || manifest.SchemaVersion != 3 || manifest.Codec != "zstd-1" || (manifest.Mode != "synthetic" && manifest.Mode != "production") || len(manifest.Objects) == 0 || len(manifest.Objects) >= 18500 || pointer.ManifestPath != "/_atlas/releases/"+manifest.ReleaseID+"/manifest.json" || pointer.ReleaseID != manifest.ReleaseID || Hash(manifestBytes) != pointer.ManifestSHA256 || manifest.ValidFrom < 0 || manifest.ValidUntil <= manifest.ValidFrom || manifest.ValidUntil-manifest.ValidFrom > 720*3600 || manifest.ValidUntil > 9007199254740991 {
		return nil, fail("manifest")
	}
	desc := Descriptor{Codec: manifest.Codec, FormatVersion: 3, Mode: manifest.Mode, Objects: manifest.Objects, SchemaVersion: 3, ValidFrom: manifest.ValidFrom, ValidUntil: manifest.ValidUntil}
	if Hash(canonical(desc)) != manifest.ReleaseID {
		return nil, fail("manifest")
	}
	r := &Release{Manifest: manifest, objects: make(map[string]ObjectInfo, len(manifest.Objects)), load: load, cache: make(map[string]*Shard), active: make(map[string]bool), activeObjects: make(map[string]*Shard), Clock: clock}
	previous := ""
	routerHash := ""
	for _, o := range manifest.Objects {
		h, err := hex.DecodeString(o.SHA256)
		if err != nil || len(h) != 32 || o.SHA256 != strings.ToLower(o.SHA256) || o.SHA256 <= previous || o.Kind < 1 || o.Kind > 14 || o.Bytes < 64 || o.Bytes >= MaxFile || !validPartition(o.Partition) {
			return nil, fail("manifest")
		}
		previous = o.SHA256
		r.objects[o.SHA256] = o
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
	r.routerBytes = decodedSize(router)
	r.residents[routerHash].router = true
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
	return NewRelease(p, m, func(hash string) ([]byte, error) {
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
}
func (r *Release) current() error {
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
	if s := r.activeObjects[hash]; s != nil {
		return s, nil
	}
	if s := r.cache[hash]; s != nil {
		if err := r.admit(hash, decodedSize(s)); err != nil {
			return nil, err
		}
		if r.activeObjects == nil {
			r.activeObjects = make(map[string]*Shard)
		}
		r.activeObjects[hash] = s
		return s, nil
	}
	info, ok := r.objects[hash]
	if !ok {
		return nil, fail("missing_object")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	if err := r.admit(hash, int(declared)); err != nil {
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
		o, ok := r.objects[string(encoded[:])]
		if !ok || o.Kind != u16(dir, p) || o.Bytes != int(u32(dir, p+4)) || o.SHA256 == hash {
			return nil, fail("record")
		}
		if r.references == nil {
			r.references = make(map[string]*objectReference)
		}
		reference := r.references[o.SHA256]
		if reference == nil {
			reference = &objectReference{hash: o.SHA256}
			r.references[o.SHA256] = reference
		}
		references[p/40] = reference
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
	r.cacheObject(hash, &s)
	if r.activeObjects == nil {
		r.activeObjects = make(map[string]*Shard)
	}
	r.activeObjects[hash] = &s
	return &s, nil
}
func (r *Release) reference(ctx context.Context, from *Shard, index uint32) (*Shard, error) {
	if from.lookup != nil {
		if uint64(index) >= uint64(len(from.lookup.references)) {
			return nil, fail("record")
		}
		reference := from.lookup.references[index]
		if reference.active != nil {
			if err := r.current(); err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return reference.active, nil
		}
		shard, err := r.object(ctx, reference.hash)
		if err == nil {
			reference.active = shard
			r.usedReferences = append(r.usedReferences, reference)
		}
		return shard, err
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
	info, ok := r.objects[string(encoded[:])]
	if !ok {
		return nil, fail("missing_object")
	}
	return r.object(ctx, info.SHA256)
}
func (r *Release) label(ctx context.Context, from *Shard, row []byte, p int, target *string) (*string, error) {
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
	offsets, _ := dictionary.Rows(5)
	text, _ := dictionary.Rows(6)
	if uint64(id)+1 >= uint64(len(offsets)/4) {
		return nil, fail("record")
	}
	*target = string(text[u32(offsets, int(id)*4):u32(offsets, (int(id)+1)*4)])
	return target, nil
}
func (s *Shard) ASNRecord(asn uint32) ([]byte, bool) {
	index, _ := s.Rows(2)
	i := sort.Search(len(index)/8, func(i int) bool { return u32(index, i*8) >= asn })
	if i == len(index)/8 || u32(index, i*8) != asn {
		return nil, false
	}
	return s.Record(u32(index, i*8+4)), true
}

type destinationSet [15]*Shard

func (r *Release) destinations(ctx context.Context, input querycontract.Input) (destinationSet, error) {
	var row []byte
	var ok bool
	if input.Kind == "ip" {
		row, _, ok = r.router.findPrefix(netip.MustParseAddr(input.Canonical))
	} else {
		n, _ := strconv.ParseUint(input.Canonical[2:], 10, 32)
		return r.asnDestinations(ctx, uint32(n))
	}
	return r.rowDestinations(ctx, row, ok)
}
func (r *Release) asnDestinations(ctx context.Context, asn uint32) (destinationSet, error) {
	row, ok := r.router.ASNRecord(asn)
	return r.rowDestinations(ctx, row, ok)
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
type asnLookupValues struct {
	country, name, organization string
	risk                        float64
	customerCone, transitDegree uint32
}

func countryInto(v uint16, target *string) *string {
	if v == 0 {
		return nil
	}
	n := int(v) - 1
	*target = string([]byte{byte(n/26) + 'A', byte(n%26) + 'A'})
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
	ints, _ := s.Rows(4)
	out := make([]uint32, u32(row, 8))
	for i := range out {
		out[i] = u32(ints, (int(u32(row, 4))+i)*4)
	}
	return out
}

func (r *Release) Lookup(ctx context.Context, q string) (LookupAnswer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	input, err := querycontract.ParseInput(q)
	if err != nil {
		return LookupAnswer{}, err
	}
	r.beginQuery()
	defer r.endQuery()
	budget := newAnswerBudget()
	if err = r.current(); err != nil {
		return LookupAnswer{}, err
	}
	answer := LookupAnswer{Q: input.Canonical, Kind: input.Kind, ReleaseID: r.Manifest.ReleaseID, Synthetic: r.Manifest.Mode == "synthetic", ValidUntil: r.Manifest.ValidUntil, ASNs: []ASNAnswer{}, BGP: BGPAnswer{Origins: []uint32{}, Paths: []PathAnswer{}, Relationships: []RelationshipAnswer{}, Tier1: []TierAnswer{}, RPKI: []RPKIAnswer{}}}
	dest, err := r.destinations(ctx, input)
	if err != nil {
		return answer, err
	}
	var addr netip.Addr
	var announcement netip.Prefix
	var geoValues *geoLookupValues
	networkOriginsKnown := false
	if input.Kind == "ip" {
		addr = netip.MustParseAddr(input.Canonical)
		if s := dest[2]; s != nil {
			if row, _, ok := s.findPrefix(addr); ok {
				geoValues = &geoLookupValues{}
				g := &geoValues.answer
				g.Country, g.RegistrationCountry = countryInto(u16(row, 4), &geoValues.country), countryInto(u16(row, 6), &geoValues.registration)
				if g.Region, err = r.label(ctx, s, row, 8, &geoValues.region); err != nil {
					return answer, err
				}
				if g.City, err = r.label(ctx, s, row, 16, &geoValues.city); err != nil {
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
			if row, prefix, ok := s.findPrefix(addr); ok {
				if err := budget.charge(4096 + 16*int(u32(row, 8))); err != nil {
					return answer, err
				}
				values := &networkLookupValues{answer: NetworkAnswer{Prefix: prefix.String(), Origins: origins(s, row)}}
				n := &values.answer
				if n.Name, err = r.label(ctx, s, row, 16, &values.name); err != nil {
					return answer, err
				}
				if n.Organization, err = r.label(ctx, s, row, 24, &values.organization); err != nil {
					return answer, err
				}
				if n.ISP, err = r.label(ctx, s, row, 32, &values.isp); err != nil {
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
			if row, _, ok := s.findPrefix(addr); ok {
				values := &usageLookupValues{answer: UsageAnswer{Type: usageName(row[4]), Assignment: []string{"unknown", "native", "broadcast_or_routed"}[row[5]]}}
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
			if row, _, ok := s.findPrefix(addr); ok {
				values := &qualityLookupValues{}
				q := &values.answer
				*q = QualityAnswer{Confidence: confidence(row[10]), Reasons: reasons(u32(row, 4)), Layers: LayerAnswer{Exact: riskValue(row, 12, 10, &values.exact), Prefix: riskValue(row, 16, 11, &values.prefix), ASN: riskValue(row, 20, 12, &values.asn), Neighbors: riskValue(row, 24, 13, &values.neighbors)}}
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
				values := &asnLookupValues{}
				a := ASNAnswer{ASN: asn, Country: countryInto(u16(row, 24), &values.country), Risk: riskValue(row, 28, 23, &values.risk), RiskBand: []string{"unknown", "low", "medium", "high"}[row[26]], Confidence: confidence(row[27]), Prefixes: []string{}, NetworkClass: className(row[52]), Stability: stability(row[53])}
				if a.Name, err = r.label(ctx, s, row, 8, &values.name); err != nil {
					return answer, err
				}
				if a.Organization, err = r.label(ctx, s, row, 16, &values.organization); err != nil {
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
					pages, _ := s.Rows(12)
					p := pages[u32(row, 36)*16 : (u32(row, 36)+1)*16]
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
			if first, end, ok := s.asnBounds(asn); ok {
				if end-first > 12 {
					return answer, fail("record")
				}
				segments, _ := s.Rows(9)
				ints, _ := s.Rows(4)
				for ordinal := first; ordinal < end; ordinal++ {
					row := s.Record(ordinal)
					count := int(u16(row, 12))
					total := 0
					for j := u32(row, 8); j < u32(row, 8)+uint32(u16(row, 12)); j++ {
						seg := segments[j*12 : (j+1)*12]
						if err := budget.path(int(u32(seg, 8))); err != nil {
							return answer, err
						}
						total += int(u32(seg, 8))
					}
					// Flat and per-segment values have disjoint caller-owned ranges.
					// Full slice bounds also prevent an append from overwriting the
					// next range. The complete allocation is reserved above first.
					values := make([]uint32, 2*total)
					p := PathAnswer{Origin: asn, ASNs: values[:total:total], Visibility: []string{"unknown", "low", "medium", "high"}[row[15]], GraphEligible: row[14]&1 != 0, Segments: make([]SegmentAnswer, count)}
					start := 0
					for offset := 0; offset < count; offset++ {
						j := u32(row, 8) + uint32(offset)
						seg := segments[j*12 : (j+1)*12]
						end := start + int(u32(seg, 8))
						a := values[total+start : total+end : total+end]
						for k := range a {
							a[k] = u32(ints, (int(u32(seg, 4))+k)*4)
						}
						p.Segments[offset] = SegmentAnswer{Type: []string{"", "sequence", "set", "confederation_sequence", "confederation_set"}[seg[0]], ASNs: a}
						copy(p.ASNs[start:end], a)
						start = end
					}
					answer.BGP.Paths = append(answer.BGP.Paths, p)
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
			status := "unavailable"
			if s := dest[9]; s != nil {
				if row, ok := s.FindRPKI(addr, asn, announcement); ok {
					status = []string{"unavailable", "valid", "invalid", "not_found"}[row[8]]
				}
			}
			if cap(answer.BGP.RPKI) == 0 {
				answer.BGP.RPKI = make([]RPKIAnswer, 0, len(answer.BGP.Origins))
			}
			answer.BGP.RPKI = append(answer.BGP.RPKI, RPKIAnswer{Origin: asn, Status: status})
		}
	}
	// Only actual consecutive retained path hops are queried. Relationship runs
	// may be large; binary lookup avoids allocating or scanning an ASN's degree.
	pairs := make(map[uint64]bool)
	for _, path := range answer.BGP.Paths {
		if !path.GraphEligible {
			continue
		}
		for i := 1; i < len(path.ASNs); i++ {
			from, to := path.ASNs[i-1], path.ASNs[i]
			if from != to {
				pairs[uint64(from)<<32|uint64(to)] = true
			}
		}
	}
	ordered := make([]uint64, 0, len(pairs))
	for pair := range pairs {
		ordered = append(ordered, pair)
	}
	slices.Sort(ordered)
	for _, pair := range ordered {
		if err := budget.charge(256); err != nil {
			return answer, err
		}
		if err := ctx.Err(); err != nil {
			return answer, err
		}
		from, to := uint32(pair>>32), uint32(pair)
		related, err := r.asnDestinations(ctx, from)
		if err != nil {
			return answer, err
		}
		edge := RelationshipAnswer{From: from, To: to, Relation: "unknown", Observed: true}
		if s := related[12]; s != nil {
			if row, ok := s.FindRelationship(from, to); ok {
				edge.Relation = []string{"unknown", "transit_upstream", "peer", "customer", "sibling"}[row[12]]
				edge.Inferred = row[13]&2 != 0
			}
		}
		answer.BGP.Relationships = append(answer.BGP.Relationships, edge)
	}
	if err := ctx.Err(); err != nil {
		return answer, err
	}
	if err := r.current(); err != nil {
		return answer, err
	}
	if err := lookupFits(answer); err != nil {
		return answer, err
	}
	return answer, nil
}

func (r *Release) ClassC(ctx context.Context, q string) (*ClassCAnswer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
	dest, err := r.destinations(ctx, input)
	if err != nil {
		return nil, err
	}
	s := dest[7]
	if s == nil {
		return nil, nil
	}
	row, prefix, ok := s.FindPrefix(addr)
	if !ok {
		return nil, nil
	}
	answer := &ClassCAnswer{Prefix: prefix, Cells: make([]CellAnswer, 256), ObservedCount: int(u16(row, 8)), AssessedCount: int(u16(row, 10)), PositiveCount: int(u16(row, 12))}
	if present(row, 22) {
		v := row[20]
		answer.AggregateScore = &v
	}
	a := addr.As4()
	a[3] = 0
	for suffix := 0; suffix < 256; suffix++ {
		a[3] = byte(suffix)
		answer.Cells[suffix] = CellAnswer{IP: netip.AddrFrom4(a).String(), Confidence: "unrated", Reasons: []string{}, Usage: "unknown", Origins: []uint32{}}
	}
	cells, _ := s.Rows(10)
	for j := u32(row, 4); j < u32(row, 4)+uint32(u16(row, 8)); j++ {
		cell := cells[j*32 : (j+1)*32]
		c := &answer.Cells[cell[0]]
		c.Observed = true
		c.Confidence = confidence(cell[9])
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
