package via3

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"vansail-ip-atlas/internal/intelligence"

	"github.com/klauspost/compress/zstd"
)

// Independent byte-contract regressions. These full-integrity containers are
// semantically hostile, rather than merely broken compressed streams.
type auditCase struct {
	name  string
	shard Shard
	query string
}

func auditCases() []auditCase {
	out := []auditCase{}
	origins := make([]byte, 16)
	p32(origins, 8, 1)
	s := newShard(10, origins)
	s.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	s.set(4, intVector(13335))
	out = append(out, auditCase{"origins_without_presence", s, "203.0.113.1"})
	tier := make([]byte, 16)
	p32(tier, 4, 13335)
	tier[8], tier[9] = 1, 2
	s = newShard(13, tier)
	s.set(2, asnKeys(13335))
	out = append(out, auditCase{"tier1_without_presence", s, "AS13335"})
	tier = append([]byte(nil), tier...)
	p32(tier, 0, bits(27, 28))
	p32(tier, 4, 3356)
	s = newShard(13, tier)
	s.set(2, asnKeys(13335))
	out = append(out, auditCase{"tier1_index_identity", s, "AS13335"})
	pathCase := func(name string, values []uint32, segments, records int) {
		rows := make([][]byte, records)
		segmentRows := make([][]byte, segments)
		for i := range rows {
			row := make([]byte, 24)
			p32(row, 0, bits(29))
			p32(row, 4, 13335)
			if segments > 0 {
				p32(row, 8, uint32(i))
				p16(row, 12, 1)
			}
			row[14] = 1
			rows[i] = row
		}
		for i := range segmentRows {
			row := make([]byte, 12)
			row[0] = 1
			p32(row, 4, uint32(i*len(values)))
			p32(row, 8, uint32(len(values)))
			segmentRows[i] = row
		}
		ints := []uint32{}
		for range segments {
			ints = append(ints, values...)
		}
		shard := newShard(11, rows...)
		shard.set(2, asnKeys(13335))
		shard.set(4, intVector(ints...))
		shard.set(9, Vector(12, segmentRows...))
		out = append(out, auditCase{name, shard, "AS13335"})
	}
	pathCase("path_empty_segments", nil, 0, 1)
	pathCase("path_zero_asn", []uint32{13335, 0}, 1, 1)
	pathCase("path_wrong_origin", []uint32{3356, 13335}, 1, 1)
	pathCase("path_graph_loop", []uint32{13335, 3356, 13335}, 1, 1)
	pathCase("path_over_twelve", []uint32{13335}, 13, 13)
	profile := make([]byte, 24)
	p32(profile, 0, bits(21))
	p16(profile, 8, 1)
	p16(profile, 10, 1)
	cell := make([]byte, 32)
	cell[0], cell[1], cell[8] = 1, 8, 50
	p32(cell, 16, None)
	p32(cell, 20, None)
	s = newShard(7, profile)
	s.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	s.set(10, Vector(32, cell))
	out = append(out, auditCase{"cell_score_without_confidence", s, "203.0.113.1"})
	aggregate := make([]byte, 64)
	p32(aggregate, 0, bits(23))
	p32(aggregate, 4, 13335)
	for _, offset := range []int{8, 12, 16, 20} {
		p32(aggregate, offset, None)
	}
	aggregate[26] = 1
	p32(aggregate, 28, 1000000)
	s = newShard(8, aggregate)
	s.set(2, asnKeys(13335))
	out = append(out, auditCase{"asn_risk_band_disagrees", s, "AS13335"})
	rpki := make([]byte, 16)
	p32(rpki, 0, bits(20))
	p32(rpki, 4, 13335)
	rpki[8], rpki[9] = 1, 128
	s = newShard(9, rpki)
	s.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	out = append(out, auditCase{"ipv4_vrp_length_128", s, "203.0.113.1"})
	quality := make([]byte, 32)
	p32(quality, 0, bits(9, 10, 11, 12, 13, 14))
	quality[8], quality[9], quality[10] = 1, 100, 1
	for i, value := range []uint32{550000, 180000, 150000, 120000} {
		p32(quality, 12+i*4, value)
	}
	s = newShard(6, quality)
	s.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	out = append(out, auditCase{"quality_score_impossible_for_layers", s, "203.0.113.1"})
	ipv6Quality := make([]byte, 32)
	p32(ipv6Quality, 0, bits(9, 10, 11, 12, 13, 14))
	ipv6Quality[8], ipv6Quality[9], ipv6Quality[10] = 1, 100, 1
	s = newShard(6, ipv6Quality)
	s.set(1, prefixRows(key("2001:db8::/32", false, 0)))
	out = append(out, auditCase{"ipv6_quality_numeric_score", s, "2001:db8::1"})
	ipv6Neighbors := make([]byte, 32)
	p32(ipv6Neighbors, 0, bits(13))
	s = newShard(6, ipv6Neighbors)
	s.set(1, prefixRows(key("2001:db8::/32", false, 0)))
	out = append(out, auditCase{"ipv6_neighbor_layer_present_zero", s, "2001:db8::1"})
	return out
}
func auditUncheckedContainer(t *testing.T, s Shard) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(3)), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(MaxWindow), zstd.WithEncoderCRC(true), zstd.WithSingleSegment(true))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	data := make([]byte, 64+len(s.Sections)*64)
	copy(data, "VIA3")
	p16(data, 4, 3)
	p16(data, 6, 3)
	p16(data, 8, 64)
	p16(data, 10, s.Kind)
	p32(data, 16, uint32(len(s.Sections)))
	p64(data, 20, 64)
	data[44] = 1
	total := 0
	for i, section := range s.Sections {
		encoded := encoder.EncodeAll(section.Data, nil)
		descriptor := data[64+i*64 : 128+i*64]
		p16(descriptor, 0, section.ID)
		descriptor[2] = 1
		p64(descriptor, 8, uint64(len(data)))
		p64(descriptor, 16, uint64(len(encoded)))
		p64(descriptor, 24, uint64(len(section.Data)))
		sum := sha256.Sum256(section.Data)
		copy(descriptor[32:], sum[:])
		data = append(data, encoded...)
		total += len(section.Data)
	}
	p64(data, 28, uint64(len(data)))
	p64(data, 36, uint64(total))
	return data
}

func TestAuditRecordSemantics(t *testing.T) {
	for _, item := range auditCases() {
		t.Run(item.name, func(t *testing.T) {
			if ErrorCode(Validate(item.shard)) != "record" {
				t.Error("semantically invalid record accepted")
			}
			_, err := Read(context.Background(), auditUncheckedContainer(t, item.shard))
			if ErrorCode(err) != "record" {
				t.Fatalf("full-integrity hostile container accepted: %v", err)
			}
		})
	}
}
func TestAuditPublicLabelTokensAndBidi(t *testing.T) {
	if !safeLabel("St. Louis") {
		t.Error("safe city punctuation rejected as hostname")
	}
	for _, value := range []string{"abc\u061cdef", "abc\u200edef", "abc\u200fdef", "unsafe.example", "https://private.example"} {
		if safeLabel(value) {
			t.Errorf("unsafe label accepted: %q", value)
		}
	}
}
func TestAuditExpiredEmptyAuxiliaryLookups(t *testing.T) {
	g := golden(t)
	now := g.Clock
	r := memoryRelease(t, g, func() int64 { return now })
	now = g.Manifest.ValidUntil
	if _, err := r.ClassC(context.Background(), "8.8.8.8"); ErrorCode(err) != "expired" {
		t.Errorf("expired class C became unknown: %v", err)
	}
	if _, err := r.Prefixes(context.Background(), "AS3356", 0); ErrorCode(err) != "expired" {
		t.Errorf("expired ASN prefixes became unknown: %v", err)
	}
}

func auditReleaseFromFacts(t *testing.T, facts ...Shard) (*Release, map[string][]byte) {
	t.Helper()
	built := []BuiltObject{}
	files := map[string][]byte{}
	for _, shard := range facts {
		data, err := Write(context.Background(), shard)
		if err != nil {
			t.Fatal(err)
		}
		info := ObjectInfo{Bytes: len(data), Kind: shard.Kind, Partition: "all", SHA256: Hash(data)}
		built = append(built, BuiltObject{Info: info, Bytes: data})
		files[info.SHA256] = data
	}
	directory, index := makeObjectDir(built...)
	row := make([]byte, 16)
	p16(row, 4, uint16(len(built)))
	router := newShard(1, row)
	router.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	router.set(7, directory)
	sort.Slice(built, func(i, j int) bool { return built[i].Info.Kind < built[j].Info.Kind })
	references := []uint32{}
	infos := []ObjectInfo{}
	for _, object := range built {
		references = append(references, index(object))
		infos = append(infos, object.Info)
	}
	router.set(4, intVector(references...))
	data, err := Write(context.Background(), router)
	if err != nil {
		t.Fatal(err)
	}
	info := ObjectInfo{Bytes: len(data), Kind: 1, Partition: "all", SHA256: Hash(data)}
	infos = append(infos, info)
	files[info.SHA256] = data
	sort.Slice(infos, func(i, j int) bool { return infos[i].SHA256 < infos[j].SHA256 })
	desc := Descriptor{Codec: "zstd-1", FormatVersion: 3, Mode: "synthetic", Objects: infos, SchemaVersion: 3, ValidFrom: 1700000000, ValidUntil: 1700003600}
	id := Hash(canonical(desc))
	manifest := Manifest{Codec: desc.Codec, FormatVersion: 3, Mode: desc.Mode, Objects: infos, ReleaseID: id, SchemaVersion: 3, ValidFrom: desc.ValidFrom, ValidUntil: desc.ValidUntil}
	pointer := Pointer{3, "/_atlas/releases/" + id + "/manifest.json", Hash(canonical(manifest)), id}
	reader, err := NewRelease(canonical(pointer), canonical(manifest), func(hash string) ([]byte, error) { return files[hash], nil }, func() int64 { return 1700000001 })
	if err != nil {
		t.Fatal(err)
	}
	return reader, files
}
func auditNetwork(prefix string, overlay bool, origin uint32) Shard {
	row := make([]byte, 40)
	p32(row, 0, bits(19))
	p32(row, 8, 1)
	nullRef(row, 16)
	nullRef(row, 24)
	nullRef(row, 32)
	s := newShard(4, row)
	id := uint16(1)
	if overlay {
		id = 8
	}
	s.set(id, prefixRows(key(prefix, false, 0)))
	s.set(4, intVector(origin))
	return s
}
func TestAuditRPKIInheritedOriginAndNetworkConsistency(t *testing.T) {
	t.Run("inherited_RPKI_preserves_original_prefix_origin", func(t *testing.T) {
		rpki := make([]byte, 16)
		p32(rpki, 0, bits(20))
		p32(rpki, 4, 13335)
		rpki[8], rpki[9] = 1, 16
		shard := newShard(9, rpki)
		shard.set(8, prefixRows(key("203.0.0.0/16", false, 0)))
		reader, _ := auditReleaseFromFacts(t, auditNetwork("203.0.0.0/16", true, 13335), shard)
		answer, err := reader.Lookup(context.Background(), "203.0.113.1")
		if err != nil || len(answer.BGP.RPKI) != 1 || answer.BGP.RPKI[0].Status != "valid" {
			t.Fatalf("inherited RPKI lost: %+v, %v", answer.BGP.RPKI, err)
		}
	})
	t.Run("network_origin_fact_conflict_rejected", func(t *testing.T) {
		row := make([]byte, 16)
		p32(row, 0, bits(19))
		p32(row, 8, 1)
		origins := newShard(10, row)
		origins.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
		origins.set(4, intVector(3356))
		reader, _ := auditReleaseFromFacts(t, auditNetwork("203.0.113.0/24", false, 13335), origins)
		if _, err := reader.Lookup(context.Background(), "203.0.113.1"); ErrorCode(err) != "record" {
			t.Fatalf("conflicting network/BGP origin lists accepted: %v", err)
		}
	})
	t.Run("parent_announcement_validity_not_inherited_by_child", func(t *testing.T) {
		rpki := make([]byte, 16)
		p32(rpki, 0, bits(20))
		p32(rpki, 4, 13335)
		rpki[8], rpki[9] = 1, 16
		shard := newShard(9, rpki)
		shard.set(8, prefixRows(key("203.0.0.0/16", false, 0)))
		originRow := make([]byte, 16)
		p32(originRow, 0, bits(19))
		p32(originRow, 8, 1)
		announcements := newShard(10, originRow)
		announcements.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
		announcements.set(4, intVector(13335))
		reader, _ := auditReleaseFromFacts(t, auditNetwork("203.0.113.0/24", false, 13335), announcements, shard)
		answer, err := reader.Lookup(context.Background(), "203.0.113.1")
		if err != nil || len(answer.BGP.RPKI) != 1 || answer.BGP.RPKI[0].Status != "unavailable" {
			t.Fatalf("parent route validity relabelled onto different child announcement: %+v %v", answer.BGP.RPKI, err)
		}
	})
}

func TestAuditTypedCompilerPartitionOrdering(t *testing.T) {
	parts := []PartitionInput{}
	for i, prefix := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		p := netip.MustParsePrefix(prefix)
		parts = append(parts, PartitionInput{Partition: "all", PrefixRoutes: []netip.Prefix{p}, Records: []PublicRecord{{Version: 3, Kind: 5, Prefix: p, Usage: &UsageData{Type: uint8(i + 1)}}}})
	}
	first, err := Build(context.Background(), CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: parts})
	if err != nil {
		t.Fatal(err)
	}
	parts[0], parts[1] = parts[1], parts[0]
	second, err := Build(context.Background(), CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: parts})
	if err != nil {
		t.Fatal(err)
	}
	if first.Pointer.ReleaseID != second.Pointer.ReleaseID {
		t.Fatal("equivalent partition input order changed immutable release bytes")
	}
}
func TestAuditTypedCompilerAmbiguousPathRank(t *testing.T) {
	records := []PublicRecord{{Version: 3, Kind: 11, ASN: 13335, Rank: 0, Path: &PathData{GraphEligible: true, Segments: []SegmentData{{Type: 1, ASNs: []uint32{13335, 3356}}}}}, {Version: 3, Kind: 11, ASN: 13335, Rank: 0, Path: &PathData{GraphEligible: true, Segments: []SegmentData{{Type: 1, ASNs: []uint32{13335, 174}}}}}}
	first, firstErr := CompilePartition(context.Background(), PartitionInput{Partition: "all", ASNRoutes: []uint32{13335}, Records: records})
	records[0], records[1] = records[1], records[0]
	second, secondErr := CompilePartition(context.Background(), PartitionInput{Partition: "all", ASNRoutes: []uint32{13335}, Records: records})
	if firstErr != nil || secondErr != nil {
		if ErrorCode(firstErr) != "record" || ErrorCode(secondErr) != "record" {
			t.Fatalf("ambiguous path ranks rejected inconsistently: %v/%v", firstErr, secondErr)
		}
		return
	}
	if first.Destinations[11].Info.SHA256 != second.Destinations[11].Info.SHA256 {
		t.Fatal("equal path ranks preserve input-order dependence instead of rejecting or canonical tie-break")
	}
}

func TestAuditGeoMaterializedFieldLPMAndExplicitUnknown(t *testing.T) {
	f, err := os.Open("../../configs/scoring.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := intelligence.LoadPolicy(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	observations := []intelligence.GeoEvidence{{Family: "synthetic-a", Weight: 80, Prefix: netip.MustParsePrefix("203.0.0.0/16"), PhysicalCountry: "US", Current: true}, {Family: "synthetic-b", Weight: 80, Prefix: netip.MustParsePrefix("203.0.0.0/16"), PhysicalCountry: "US", Current: true}, {Family: "synthetic-a", Weight: 80, Prefix: netip.MustParsePrefix("203.0.113.2/32"), RegistrationCountry: "CA", Current: true}, {Family: "synthetic-a", Weight: 80, Prefix: netip.MustParsePrefix("203.0.113.3/32"), PhysicalCountry: "CA", Current: true}, {Family: "synthetic-b", Weight: 80, Prefix: netip.MustParsePrefix("203.0.113.3/32"), PhysicalCountry: "US", Current: true}}
	index, err := intelligence.NewGeoIndex(policy, observations)
	if err != nil {
		t.Fatal(err)
	}
	records := []PublicRecord{}
	for i, prefix := range []string{"203.0.0.0/16", "203.0.113.2/32", "203.0.113.3/32"} {
		key := netip.MustParsePrefix(prefix)
		value, err := index.Lookup(key.Addr(), false)
		if err != nil {
			t.Fatal(err)
		}
		geo := &GeoData{}
		if value.PhysicalCountry != nil {
			geo.Country = *value.PhysicalCountry
		}
		if value.RegistrationCountry != nil {
			geo.RegistrationCountry = *value.RegistrationCountry
		}
		records = append(records, PublicRecord{Version: 3, Kind: 2, Prefix: key, Exact: i > 0, Inherited: i == 0, Geo: geo})
	}
	built, err := Build(context.Background(), CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{Partition: "4:000000000000000000000000cb007100/24", PrefixRoutes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Records: records}}})
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, object := range built.Objects {
		objects[object.Info.SHA256] = object.Bytes
	}
	reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return 1700000001 })
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ ip, country, registration string }{{"203.0.113.1", "US", ""}, {"203.0.113.2", "US", "CA"}, {"203.0.113.3", "", ""}} {
		answer, err := reader.Lookup(context.Background(), item.ip)
		if err != nil {
			t.Fatal(err)
		}
		if answer.Geo == nil {
			t.Fatal("materialized empty Geo row disappeared")
		}
		value := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		if value(answer.Geo.Country) != item.country || value(answer.Geo.RegistrationCountry) != item.registration {
			t.Fatalf("parent inheritance or exact unknown changed: %s %+v", item.ip, answer.Geo)
		}
	}
}

func TestAuditCoordinateUnknownTombstonePreservesNeighbors(t *testing.T) {
	parent := netip.MustParsePrefix("203.0.0.0/16")
	child := netip.MustParsePrefix("203.0.113.2/32")
	partition := PartitionInput{Partition: "4:000000000000000000000000cb007100/24", PrefixRoutes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Records: []PublicRecord{{Version: 3, Kind: 3, Prefix: parent, Inherited: true, Coordinates: &CoordinateData{Latitude: 10.25, Longitude: 20.25, Precision: 3}}, {Version: 3, Kind: 3, Prefix: child, Exact: true, Coordinates: &CoordinateData{Unknown: true}}}}
	built, err := Build(context.Background(), CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{partition}})
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, object := range built.Objects {
		objects[object.Info.SHA256] = object.Bytes
	}
	reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return 1700000001 })
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		answer, err := reader.Lookup(context.Background(), ip)
		if err != nil {
			t.Fatal(err)
		}
		if ip == "203.0.113.2" {
			if answer.Geo != nil && (answer.Geo.Latitude != nil || answer.Geo.Longitude != nil || answer.Geo.Precision != nil) {
				t.Fatal("explicit unknown coordinate resurrected ancestor")
			}
		} else if answer.Geo == nil || answer.Geo.Latitude == nil || *answer.Geo.Latitude != 10.25 || answer.Geo.Longitude == nil || *answer.Geo.Longitude != 20.25 {
			t.Fatal("coordinate tombstone escaped its exact key")
		}
	}
	partition.Records[1].Coordinates.Latitude = 1
	if _, err := CompilePartition(context.Background(), partition); ErrorCode(err) != "record" {
		t.Fatal("unknown coordinates retained hidden nonzero values")
	}
}

type auditObject struct {
	SHA256 string `json:"sha256"`
	Base64 string `json:"base64"`
}
type auditReleaseCase struct {
	Name     string        `json:"name"`
	Pointer  Pointer       `json:"pointer"`
	Manifest Manifest      `json:"manifest"`
	Objects  []auditObject `json:"objects"`
	Q        string        `json:"q"`
	Error    string        `json:"error"`
	Clock    int64         `json:"clock"`
}

func auditRelease(t *testing.T, item auditCase) auditReleaseCase {
	t.Helper()
	data := auditUncheckedContainer(t, item.shard)
	fact := BuiltObject{Info: ObjectInfo{Bytes: len(data), Kind: item.shard.Kind, Partition: "all", SHA256: Hash(data)}, Bytes: data}
	directory, _ := makeObjectDir(fact)
	row := make([]byte, 16)
	p16(row, 4, 1)
	router := newShard(1, row)
	router.set(4, intVector(0))
	router.set(7, directory)
	if item.shard.Kind == 8 || item.shard.Kind >= 11 {
		router.set(2, asnKeys(13335))
	} else if addr, err := netip.ParseAddr(item.query); err == nil && addr.Is6() {
		router.set(1, prefixRows(key("2001:db8::/32", false, 0)))
	} else {
		router.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
	}
	encoded, err := Write(context.Background(), router)
	if err != nil {
		t.Fatal(err)
	}
	routerInfo := ObjectInfo{Bytes: len(encoded), Kind: 1, Partition: "all", SHA256: Hash(encoded)}
	objects := []ObjectInfo{routerInfo, fact.Info}
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA256 < objects[j].SHA256 })
	desc := Descriptor{Codec: "zstd-1", FormatVersion: 3, Mode: "synthetic", Objects: objects, SchemaVersion: 3, ValidFrom: 1700000000, ValidUntil: 1700003600}
	id := Hash(canonical(desc))
	manifest := Manifest{Codec: desc.Codec, FormatVersion: 3, Mode: desc.Mode, Objects: objects, ReleaseID: id, SchemaVersion: 3, ValidFrom: desc.ValidFrom, ValidUntil: desc.ValidUntil}
	pointer := Pointer{3, "/_atlas/releases/" + id + "/manifest.json", Hash(canonical(manifest)), id}
	return auditReleaseCase{item.name, pointer, manifest, []auditObject{{routerInfo.SHA256, base64.StdEncoding.EncodeToString(encoded)}, {fact.Info.SHA256, base64.StdEncoding.EncodeToString(data)}}, item.query, "record", 1700000001}
}

// Export is opt-in, synthetic, and private. The shared corpus lets Node/Chrome
// exercise the exact same hostile bytes with valid object/manifest hashes.
func TestAuditExportHostileCorpus(t *testing.T) {
	if os.Getenv("ATLAS_EXPORT_AUDIT_CORPUS") != "1" {
		t.Skip("opt-in private hostile corpus export")
	}
	cases := []auditReleaseCase{}
	for _, item := range auditCases() {
		cases = append(cases, auditRelease(t, item))
	}
	data, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join("..", "..", ".atlas-private")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "via3-audit.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
