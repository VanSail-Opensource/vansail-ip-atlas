package via3

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

type ObjectInfo struct {
	Bytes     int    `json:"bytes"`
	Kind      uint16 `json:"kind"`
	Partition string `json:"partition"`
	SHA256    string `json:"sha256"`
}
type Descriptor struct {
	Codec         string       `json:"codec"`
	FormatVersion int          `json:"format_version"`
	Mode          string       `json:"mode"`
	Objects       []ObjectInfo `json:"objects"`
	SchemaVersion int          `json:"schema_version"`
	ValidFrom     int64        `json:"valid_from"`
	ValidUntil    int64        `json:"valid_until"`
}
type Manifest struct {
	Codec         string       `json:"codec"`
	FormatVersion int          `json:"format_version"`
	Mode          string       `json:"mode"`
	Objects       []ObjectInfo `json:"objects"`
	ReleaseID     string       `json:"release_id"`
	SchemaVersion int          `json:"schema_version"`
	ValidFrom     int64        `json:"valid_from"`
	ValidUntil    int64        `json:"valid_until"`
}
type Pointer struct {
	FormatVersion  int    `json:"format_version"`
	ManifestPath   string `json:"manifest_path"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ReleaseID      string `json:"release_id"`
}
type BuiltObject struct {
	Info  ObjectInfo
	Bytes []byte
	Shard Shard
}
type BuiltRelease struct {
	Descriptor Descriptor
	Manifest   Manifest
	Pointer    Pointer
	Objects    []BuiltObject
}

// Struct field order follows canonical ASCII-key ordering. Every public key/string
// in these three manifest structs is fixed ASCII; no arbitrary map is serialized.
func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func newShard(kind uint16, records ...[]byte) Shard {
	width, ids := schema(kind)
	s := Shard{Kind: kind}
	for _, id := range ids {
		s.Sections = append(s.Sections, Section{ID: id, Data: Vector(sectionWidth(id, width))})
	}
	if width > 0 {
		s.set(3, Vector(width, records...))
	}
	return s
}
func (s *Shard) set(id uint16, data []byte) {
	for i := range s.Sections {
		if s.Sections[i].ID == id {
			s.Sections[i].Data = data
			return
		}
	}
	panic("unavailable section")
}
func intVector(values ...uint32) []byte {
	rows := make([][]byte, len(values))
	for i, v := range values {
		rows[i] = make([]byte, 4)
		p32(rows[i], 0, v)
	}
	return Vector(4, rows...)
}
func asnKeys(values ...uint32) []byte {
	rows := make([][]byte, len(values))
	for i, v := range values {
		rows[i] = make([]byte, 8)
		p32(rows[i], 0, v)
		p32(rows[i], 4, uint32(i))
	}
	return Vector(8, rows...)
}
func key(prefix string, exact bool, record uint32) []byte {
	return PrefixKey(netip.MustParsePrefix(prefix), exact, record)
}
func prefixRows(rows ...[]byte) []byte {
	sort.Slice(rows, func(i, j int) bool { return keyCompare(rows[i], rows[j]) < 0 })
	return Vector(32, rows...)
}
func makeObjectDir(objects ...BuiltObject) ([]byte, func(BuiltObject) uint32) {
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].Info.Kind != objects[j].Info.Kind {
			return objects[i].Info.Kind < objects[j].Info.Kind
		}
		return objects[i].Info.SHA256 < objects[j].Info.SHA256
	})
	rows := make([][]byte, len(objects))
	for i, o := range objects {
		r := make([]byte, 40)
		p16(r, 0, o.Info.Kind)
		p32(r, 4, uint32(o.Info.Bytes))
		h, _ := hex.DecodeString(o.Info.SHA256)
		copy(r[8:], h)
		rows[i] = r
	}
	return Vector(40, rows...), func(o BuiltObject) uint32 {
		for i, x := range objects {
			if x.Info.SHA256 == o.Info.SHA256 {
				return uint32(i)
			}
		}
		panic("missing object")
	}
}
func stringRef(r []byte, p int, object, id uint32) { p32(r, p, object); p32(r, p+4, id) }
func nullRef(r []byte, p int)                      { stringRef(r, p, None, None) }

// Synthetic uses only documentation IP ranges and clearly artificial names.
// It never reads source configuration, source samples, production caches or APIs.
func Synthetic(ctx context.Context, clock int64) (BuiltRelease, error) {
	var objects []BuiltObject
	add := func(s Shard, partition string) (BuiltObject, error) {
		if err := ValidatePublicProfile(s); err != nil {
			return BuiltObject{}, err
		}
		b, err := Write(ctx, s)
		if err != nil {
			return BuiltObject{}, err
		}
		o := BuiltObject{Info: ObjectInfo{Bytes: len(b), Kind: s.Kind, Partition: partition, SHA256: Hash(b)}, Bytes: b, Shard: s}
		objects = append(objects, o)
		return o, nil
	}
	labels := []string{"Atlas Access", "Atlas City", "Atlas Harbor", "Atlas Region", "Atlas Transit", "Example Organization"}
	offsets := []uint32{0}
	var text []byte
	for _, label := range labels {
		text = append(text, []byte(label)...)
		offsets = append(offsets, uint32(len(text)))
	}
	dictionary := newShard(14)
	dictionary.set(5, intVector(offsets...))
	dictionary.set(6, BytesVector(text))
	dict, err := add(dictionary, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	geoBase := func(city uint32) []byte {
		r := make([]byte, 24)
		p32(r, 0, bits(0, 1, 2, 3))
		p16(r, 4, 539)
		p16(r, 6, 158)
		stringRef(r, 8, 0, 3)
		stringRef(r, 16, 0, city)
		return r
	}
	geo := newShard(2, geoBase(1), geoBase(2))
	dir, _ := makeObjectDir(dict)
	geo.set(7, dir)
	geo.set(1, prefixRows(key("203.0.113.1/32", true, 1)))
	geo.set(8, prefixRows(key("203.0.0.0/16", false, 0)))
	geoA, err := add(geo, "4:000000000000000000000000cb007100/24")
	if err != nil {
		return BuiltRelease{}, err
	}
	geoBShard := newShard(2, geoBase(1))
	geoBShard.set(7, dir)
	geoBShard.set(8, prefixRows(key("203.0.0.0/16", false, 0)))
	geoB, err := add(geoBShard, "4:000000000000000000000000cb007200/24")
	if err != nil {
		return BuiltRelease{}, err
	}
	geo6Shard := newShard(2, geoBase(1))
	geo6Shard.set(7, dir)
	geo6Shard.set(1, prefixRows(key("2001:db8::/32", false, 0)))
	geo6, err := add(geo6Shard, "6:20010db8000000000000000000000000/32")
	if err != nil {
		return BuiltRelease{}, err
	}
	coordRow := func(lat, lon int32) []byte {
		r := make([]byte, 16)
		p32(r, 0, bits(4))
		p32(r, 4, uint32(lat))
		p32(r, 8, uint32(lon))
		r[12] = 3
		return r
	}
	coordinates := newShard(3, coordRow(47600, -122300), coordRow(0, 0))
	coordinates.set(1, prefixRows(key("203.0.0.0/16", false, 0), key("2001:db8::/32", false, 1)))
	coord, err := add(coordinates, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	networkRow := make([]byte, 40)
	p32(networkRow, 0, bits(15, 16, 17, 18, 19))
	p32(networkRow, 8, 2)
	stringRef(networkRow, 16, 0, 4)
	stringRef(networkRow, 24, 0, 5)
	stringRef(networkRow, 32, 0, 0)
	network := newShard(4, networkRow)
	network.set(7, dir)
	network.set(1, prefixRows(key("203.0.113.0/24", false, 0), key("203.0.114.0/24", false, 0), key("2001:db8::/32", false, 0)))
	network.set(4, intVector(13335, 15169))
	netObj, err := add(network, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	usageRow := make([]byte, 8)
	p32(usageRow, 0, bits(5, 6, 7, 8))
	usageRow[4] = 1
	usageRow[5] = 1
	usage6Row := append([]byte(nil), usageRow...)
	p32(usage6Row, 0, bits(5, 6, 7))
	usage := newShard(5, usageRow, usage6Row)
	usage.set(1, prefixRows(key("203.0.0.0/16", false, 0), key("2001:db8::/32", false, 1)))
	useObj, err := add(usage, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	qualityRow := func(score byte, reasons uint32, contributions [4]uint32, assessed bool) []byte {
		r := make([]byte, 32)
		mask := bits(10, 11, 12, 13, 14)
		if assessed {
			mask |= bits(9)
			r[8] = 1
			r[9] = score
			r[10] = 2
		}
		p32(r, 0, mask)
		p32(r, 4, reasons)
		for i, v := range contributions {
			p32(r, 12+i*4, v)
		}
		return r
	}
	quality6 := qualityRow(0, bits(9), [4]uint32{100000, 0, 0, 0}, false)
	p32(quality6, 0, bits(10, 14)) // IPv6 has positive exact evidence; unassessed layers remain unknown.
	quality := newShard(6, qualityRow(86, bits(9, 12, 13), [4]uint32{110000, 18000, 9000, 3000}, true), qualityRow(0, bits(0, 1, 2, 3), [4]uint32{550000, 180000, 150000, 120000}, true), quality6)
	quality.set(1, prefixRows(key("203.0.113.1/32", true, 0), key("203.0.113.200/32", true, 1), key("2001:db8::1/128", true, 2)))
	qualObj, err := add(quality, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	cell := func(suffix byte, score byte, assessed bool, reasons uint32, risk uint32) []byte {
		r := make([]byte, 32)
		r[0] = suffix
		r[1] = 0xf7
		r[2] = 1
		r[3] = 1
		if assessed {
			r[1] |= 8
			r[8] = score
			r[9] = 2
		}
		p32(r, 4, reasons)
		p32(r, 12, risk)
		p32(r, 16, 0)
		p32(r, 20, 0)
		return r
	}
	profileRow := make([]byte, 24)
	p32(profileRow, 0, bits(21))
	p16(profileRow, 8, 3)
	p16(profileRow, 10, 2)
	p16(profileRow, 12, 3)
	profile := newShard(7, profileRow)
	netDir, _ := makeObjectDir(netObj)
	profile.set(7, netDir)
	profile.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	profile.set(10, Vector(32, cell(1, 86, true, bits(9, 12, 13), 200000), cell(2, 0, false, bits(9), 200000), cell(200, 0, true, bits(0, 1, 2, 3), 1000000)))
	profileObj, err := add(profile, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	pageShard := newShard(8)
	prefix := key("203.0.113.0/24", false, 0)
	prefixRow := make([]byte, 24)
	copy(prefixRow[:20], prefix[:20])
	pageShard.set(11, Vector(24, prefixRow))
	pageObj, err := add(pageShard, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	asnDir, indexOf := makeObjectDir(pageObj, dict)
	asnRow := func(asn uint32, label uint32, risk bool) []byte {
		r := make([]byte, 64)
		mask := bits(16, 17, 24, 25, 26, 27, 28, 31)
		if risk {
			mask |= bits(14, 23)
			r[26] = 2
			r[27] = 2
			p32(r, 28, 500000)
			p32(r, 32, bits(12))
		}
		p32(r, 0, mask)
		p32(r, 4, asn)
		stringRef(r, 8, indexOf(dict), label)
		stringRef(r, 16, indexOf(dict), 5)
		p16(r, 24, 539)
		p32(r, 40, 1)
		p32(r, 44, 10)
		p32(r, 48, 3)
		r[52] = 2
		r[53] = 1
		return r
	}
	asnShard := newShard(8, asnRow(13335, 4, true), asnRow(15169, 0, false))
	asnShard.set(2, asnKeys(13335, 15169))
	asnShard.set(7, asnDir)
	pageRow := make([]byte, 16)
	p32(pageRow, 0, indexOf(pageObj))
	p32(pageRow, 8, 1)
	asnShard.set(12, Vector(16, pageRow))
	asnObj, err := add(asnShard, "asn:13335:15169")
	if err != nil {
		return BuiltRelease{}, err
	}
	rpkiRow := func(asn uint32, status byte) []byte {
		r := make([]byte, 16)
		p32(r, 0, bits(20))
		p32(r, 4, asn)
		r[8] = status
		r[9] = 24
		return r
	}
	rpki := newShard(9, rpkiRow(13335, 1), rpkiRow(15169, 2))
	rpki.set(1, Vector(32, key("203.0.113.0/24", false, 0), key("203.0.113.0/24", false, 1)))
	rpkiObj, err := add(rpki, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	originRow := make([]byte, 16)
	p32(originRow, 0, bits(19))
	p32(originRow, 8, 2)
	origins := newShard(10, originRow)
	origins.set(1, prefixRows(key("203.0.113.0/24", false, 0), key("203.0.114.0/24", false, 0), key("2001:db8::/32", false, 0)))
	origins.set(4, intVector(13335, 15169))
	originObj, err := add(origins, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	pathRow := func(asn, first uint32) []byte {
		r := make([]byte, 24)
		p32(r, 0, bits(29))
		p32(r, 4, asn)
		p32(r, 8, first)
		p16(r, 12, 1)
		r[14] = 1
		r[15] = 2
		return r
	}
	paths := newShard(11, pathRow(13335, 0), pathRow(15169, 1))
	paths.set(2, asnKeys(13335, 15169))
	paths.set(4, intVector(13335, 15169, 3356, 15169, 3356))
	segA, segB := make([]byte, 12), make([]byte, 12)
	segA[0] = 1
	p32(segA, 8, 3)
	segB[0] = 1
	p32(segB, 4, 3)
	p32(segB, 8, 2)
	paths.set(9, Vector(12, segA, segB))
	pathObj, err := add(paths, "asn:13335:15169")
	if err != nil {
		return BuiltRelease{}, err
	}
	relationRow := func(from, to uint32, relation byte) []byte {
		r := make([]byte, 16)
		p32(r, 0, bits(30))
		p32(r, 4, from)
		p32(r, 8, to)
		r[12] = relation
		r[13] = 3
		return r
	}
	relationships := newShard(12, relationRow(13335, 15169, 1), relationRow(15169, 3356, 1))
	relationships.set(2, asnKeys(13335, 15169))
	relObj, err := add(relationships, "asn:13335:15169")
	if err != nil {
		return BuiltRelease{}, err
	}
	tierRow := func(asn uint32, class byte) []byte {
		r := make([]byte, 16)
		p32(r, 0, bits(27, 28))
		p32(r, 4, asn)
		r[8] = class
		r[9] = 2
		return r
	}
	tier := newShard(13, tierRow(13335, 2), tierRow(15169, 1))
	tier.set(2, asnKeys(13335, 15169))
	tierObj, err := add(tier, "asn:13335:15169")
	if err != nil {
		return BuiltRelease{}, err
	}
	routerDir, routerID := makeObjectDir(geoA, geoB, geo6, coord, netObj, useObj, qualObj, profileObj, asnObj, rpkiObj, originObj, pathObj, relObj, tierObj)
	router := newShard(1)
	router.set(7, routerDir)
	var destinationRows [][]byte
	var routeRecords [][]byte
	addRoute := func(dest ...BuiltObject) uint32 {
		sort.Slice(dest, func(i, j int) bool { return dest[i].Info.Kind < dest[j].Info.Kind })
		r := make([]byte, 16)
		p32(r, 0, uint32(len(destinationRows)))
		p16(r, 4, uint16(len(dest)))
		for _, o := range dest {
			v := make([]byte, 4)
			p32(v, 0, routerID(o))
			destinationRows = append(destinationRows, v)
		}
		ordinal := uint32(len(routeRecords))
		routeRecords = append(routeRecords, r)
		return ordinal
	}
	a := addRoute(geoA, coord, netObj, useObj, qualObj, profileObj, rpkiObj, originObj)
	b := addRoute(geoB, coord, netObj, useObj, qualObj, rpkiObj, originObj)
	c := addRoute(geo6, coord, netObj, useObj, qualObj, rpkiObj, originObj)
	d := addRoute(asnObj, pathObj, relObj, tierObj)
	router.set(1, prefixRows(key("203.0.113.0/24", false, a), key("203.0.114.0/24", false, b), key("2001:db8::/32", false, c)))
	routerASNs := make([][]byte, 2)
	for i, asn := range []uint32{13335, 15169} {
		r := make([]byte, 8)
		p32(r, 0, asn)
		p32(r, 4, d)
		routerASNs[i] = r
	}
	router.set(2, Vector(8, routerASNs...))
	router.set(3, Vector(16, routeRecords...))
	router.set(4, Vector(4, destinationRows...))
	_, err = add(router, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Info.SHA256 < objects[j].Info.SHA256 })
	infos := make([]ObjectInfo, len(objects))
	for i, o := range objects {
		infos[i] = o.Info
	}
	descriptor := Descriptor{Codec: "zstd-1", FormatVersion: 3, Mode: "synthetic", Objects: infos, SchemaVersion: 3, ValidFrom: clock, ValidUntil: clock + 720*3600}
	id := Hash(canonical(descriptor))
	manifest := Manifest{Codec: descriptor.Codec, FormatVersion: 3, Mode: descriptor.Mode, Objects: infos, ReleaseID: id, SchemaVersion: 3, ValidFrom: clock, ValidUntil: descriptor.ValidUntil}
	pointer := Pointer{FormatVersion: 3, ManifestPath: "/_atlas/releases/" + id + "/manifest.json", ManifestSHA256: Hash(canonical(manifest)), ReleaseID: id}
	return BuiltRelease{Descriptor: descriptor, Manifest: manifest, Pointer: pointer, Objects: objects}, nil
}

// SyntheticGraph24 extends the unchanged golden example with an artificial
// AS424240 graph: twelve sequence routes form exactly 24 unique nodes and 23
// observed edges. It certifies no real ASN facts or source coverage.
func SyntheticGraph24(ctx context.Context, clock int64) (BuiltRelease, error) {
	release, err := Synthetic(ctx, clock)
	if err != nil {
		return BuiltRelease{}, err
	}
	const origin = uint32(424240)
	var records, segments [][]byte
	var values []uint32
	next := origin + 6
	for group := uint32(0); group < 3; group++ {
		for branch := 0; branch < 4; branch++ {
			path := []uint32{origin, origin + 1, origin + 2, origin + 3 + group, next}
			next++
			if branch < 2 {
				path = append(path, next)
				next++
			}
			row := make([]byte, 24)
			p32(row, 0, bits(29))
			p32(row, 4, origin)
			p32(row, 8, uint32(len(segments)))
			p16(row, 12, 1)
			row[14] = 1
			row[15] = 3
			segment := make([]byte, 12)
			segment[0] = 1
			p32(segment, 4, uint32(len(values)))
			p32(segment, 8, uint32(len(path)))
			records = append(records, row)
			segments = append(segments, segment)
			values = append(values, path...)
		}
	}
	paths := newShard(11, records...)
	paths.set(2, asnKeys(origin))
	paths.set(4, intVector(values...))
	paths.set(9, Vector(12, segments...))
	makeObject := func(shard Shard, partition string) (BuiltObject, error) {
		if err := ValidatePublicProfile(shard); err != nil {
			return BuiltObject{}, err
		}
		encoded, err := Write(ctx, shard)
		if err != nil {
			return BuiltObject{}, err
		}
		return BuiltObject{Info: ObjectInfo{Bytes: len(encoded), Kind: shard.Kind, Partition: partition, SHA256: Hash(encoded)}, Bytes: encoded, Shard: shard}, nil
	}
	pathObject, err := makeObject(paths, "asn:424240:424240")
	if err != nil {
		return BuiltRelease{}, err
	}
	var router Shard
	var objects []BuiltObject
	byHash := make(map[string]BuiltObject, len(release.Objects))
	for _, object := range release.Objects {
		byHash[object.Info.SHA256] = object
		if object.Info.Kind == 1 {
			router = object.Shard
			router.Sections = append([]Section(nil), router.Sections...)
		} else {
			objects = append(objects, object)
		}
	}
	oldDir, _ := router.Rows(7)
	var destinations []BuiltObject
	for p := 0; p < len(oldDir); p += 40 {
		destinations = append(destinations, byHash[hex.EncodeToString(oldDir[p+8:p+40])])
	}
	destinations = append(destinations, pathObject)
	newDir, newID := makeObjectDir(destinations...)
	oldValues, _ := router.Rows(4)
	newValues := make([]uint32, 0, len(oldValues)/4+1)
	for p := 0; p < len(oldValues); p += 4 {
		ordinal := int(u32(oldValues, p))
		hash := hex.EncodeToString(oldDir[ordinal*40+8 : ordinal*40+40])
		newValues = append(newValues, newID(byHash[hash]))
	}
	oldRecords, _ := router.Rows(3)
	newRecords := make([][]byte, 0, len(oldRecords)/16+1)
	for p := 0; p < len(oldRecords); p += 16 {
		newRecords = append(newRecords, oldRecords[p:p+16])
	}
	graphRoute := make([]byte, 16)
	p32(graphRoute, 0, uint32(len(newValues)))
	p16(graphRoute, 4, 1)
	graphOrdinal := uint32(len(newRecords))
	newRecords = append(newRecords, graphRoute)
	newValues = append(newValues, newID(pathObject))
	oldASNs, _ := router.Rows(2)
	var asns [][]byte
	for p := 0; p < len(oldASNs); p += 8 {
		asns = append(asns, oldASNs[p:p+8])
	}
	graphASN := make([]byte, 8)
	p32(graphASN, 0, origin)
	p32(graphASN, 4, graphOrdinal)
	asns = append(asns, graphASN)
	router.set(7, newDir)
	router.set(4, intVector(newValues...))
	router.set(3, Vector(16, newRecords...))
	router.set(2, Vector(8, asns...))
	routerObject, err := makeObject(router, "all")
	if err != nil {
		return BuiltRelease{}, err
	}
	objects = append(objects, pathObject, routerObject)
	sort.Slice(objects, func(i, j int) bool { return objects[i].Info.SHA256 < objects[j].Info.SHA256 })
	infos := make([]ObjectInfo, len(objects))
	for i, object := range objects {
		infos[i] = object.Info
	}
	descriptor := Descriptor{Codec: "zstd-1", FormatVersion: 3, Mode: "synthetic", Objects: infos, SchemaVersion: 3, ValidFrom: clock, ValidUntil: clock + 720*3600}
	id := Hash(canonical(descriptor))
	manifest := Manifest{Codec: descriptor.Codec, FormatVersion: 3, Mode: descriptor.Mode, Objects: infos, ReleaseID: id, SchemaVersion: 3, ValidFrom: clock, ValidUntil: descriptor.ValidUntil}
	pointer := Pointer{FormatVersion: 3, ManifestPath: "/_atlas/releases/" + id + "/manifest.json", ManifestSHA256: Hash(canonical(manifest)), ReleaseID: id}
	return BuiltRelease{Descriptor: descriptor, Manifest: manifest, Pointer: pointer, Objects: objects}, nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".atlas-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil {
		if string(old) == string(data) {
			return nil
		}
	}
	return os.Rename(name, path)
}
func (r BuiltRelease) Write(root string) error {
	for _, o := range r.Objects {
		if err := atomicWrite(filepath.Join(root, "objects", o.Info.SHA256+".via3"), o.Bytes); err != nil {
			return err
		}
	}
	if err := atomicWrite(filepath.Join(root, "releases", r.Pointer.ReleaseID, "manifest.json"), canonical(r.Manifest)); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(root, "current.json"), canonical(r.Pointer))
}
