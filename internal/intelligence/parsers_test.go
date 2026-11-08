package intelligence

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func parserLimits() ParseLimits {
	return ParseLimits{Bytes: 1 << 20, Records: 1000, LineBytes: 1 << 16}
}
func TestRelationshipAndVRPStreamingSchemas(t *testing.T) {
	ctx := context.Background()
	relations, err := ParseRelationships(ctx, strings.NewReader("# discarded annotation\n100|200|-1|private-annotation\n200|300|0\n"), true, parserLimits())
	if err != nil {
		t.Fatal(err)
	}
	if relations.Relation(200, 100) != TransitUpstream || relations.Relation(200, 300) != Peer {
		t.Fatal("parser reversed directed relationship")
	}
	vrps := []VRP{}
	sink := func(v VRP) error { vrps = append(vrps, v); return nil }
	if err := ParseVRPCSV(ctx, strings.NewReader("asn,prefix,maxLength\nAS100,192.0.2.0/24,24\n"), parserLimits(), sink); err != nil {
		t.Fatal(err)
	}
	if err := ParseVRPJSON(ctx, strings.NewReader(`{"roas":[{"asn":200,"prefix":"2001:db8::/32","maxLength":48}]}`), parserLimits(), sink); err != nil {
		t.Fatal(err)
	}
	if len(vrps) != 2 || vrps[1].ASN != 200 || vrps[1].MaxLength != 48 {
		t.Fatal("VRP typed records lost")
	}
	for _, input := range []string{`{"roas":[{"asn":100,"asn":200,"prefix":"192.0.2.0/24","maxLength":24}]}`, `{"roas":[{"asn":100,"prefix":"192.0.2.0/24","maxLength":23}]}`, `{"roas":[],"roas":[]}`, `{"roas":[{"asn":"1e99999","prefix":"192.0.2.0/24","maxLength":24}]}`, `{"roas":[{"asn":100,"prefix":"192.0.2.0/24","maxLength":24,"source":"secret"}]}`} {
		if err := ParseVRPJSON(ctx, strings.NewReader(input), parserLimits(), sink); err == nil {
			t.Fatalf("malformed JSON admitted: %s", input)
		}
	}
}
func TestParserCancellationBoundsAndSinkFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseRelationships(ctx, strings.NewReader("100|200|-1"), true, parserLimits()); err == nil {
		t.Fatal("cancellation ignored")
	}
	limits := parserLimits()
	limits.Bytes = 5
	if _, err := ParseRelationships(context.Background(), strings.NewReader("100|200|-1\n"), true, limits); err == nil {
		t.Fatal("byte limit ignored")
	}
	limits = parserLimits()
	limits.Records = 1
	if _, err := ParseRelationships(context.Background(), strings.NewReader("100|200|-1\n200|300|-1\n"), true, limits); err == nil {
		t.Fatal("record limit ignored")
	}
	stop := errors.New("bounded sink stopped")
	if err := ParseVRPCSV(context.Background(), strings.NewReader("asn,prefix,maxLength\n100,192.0.2.0/24,24\n"), parserLimits(), func(VRP) error { return stop }); err != stop {
		t.Fatal("sink failure not propagated")
	}
}

func mrtFrame(subtype uint16, payload []byte) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint32(header[:4], 1_794_096_000)
	binary.BigEndian.PutUint16(header[4:6], 13)
	binary.BigEndian.PutUint16(header[6:8], subtype)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	return append(header, payload...)
}
func mrtFixture(ipv6, addPath bool, segments []PathSegment) []byte {
	// The peer ASN is two octets. TABLE_DUMP_V2 path ASNs remain four octets.
	peer := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 192, 0, 2, 1, 0, 100}
	path := []byte{}
	for _, segment := range segments {
		wire := byte(segment.Type)
		if segment.Type == ASSequence {
			wire = 2
		} else if segment.Type == ASSet {
			wire = 1
		}
		path = append(path, wire, byte(len(segment.ASNs)))
		for _, asn := range segment.ASNs {
			path = binary.BigEndian.AppendUint32(path, asn)
		}
	}
	attributes := []byte{0x40, 2, byte(len(path))}
	attributes = append(attributes, path...)
	rib := []byte{0, 0, 0, 1}
	subtype := uint16(2)
	if ipv6 {
		rib = append(rib, 32, 0x20, 0x01, 0x0d, 0xb8)
		subtype = 4
	} else {
		rib = append(rib, 24, 192, 0, 2)
	}
	rib = binary.BigEndian.AppendUint16(rib, 1)
	rib = binary.BigEndian.AppendUint16(rib, 0)
	rib = binary.BigEndian.AppendUint32(rib, 1_794_096_000)
	if addPath {
		rib = binary.BigEndian.AppendUint32(rib, 123)
		if ipv6 {
			subtype = 10
		} else {
			subtype = 8
		}
	}
	rib = binary.BigEndian.AppendUint16(rib, uint16(len(attributes)))
	rib = append(rib, attributes...)
	return append(mrtFrame(1, peer), mrtFrame(subtype, rib)...)
}
func mrtLimits() MRTLimits {
	return MRTLimits{Bytes: 1 << 20, FrameBytes: 1 << 16, Records: 1000, Peers: 100}
}
func TestMRTTypedFourOctetASNsIPv6AddPathAndNonlinear(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, addPath := range []bool{false, true} {
			input := mrtFixture(ipv6, addPath, []PathSegment{{ASSequence, []uint32{100, 100, 420000, 200}}})
			records := []MRTRecord{}
			err := ParseMRT(context.Background(), bytes.NewReader(input), mrtLimits(), func(v MRTRecord) error { records = append(records, v); return nil })
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].Origin != 200 || records[0].Segments[0].Type != ASSequence || !reflect.DeepEqual(records[0].Segments[0].ASNs, []uint32{100, 100, 420000, 200}) || records[0].Prefix.Addr().Is6() != ipv6 {
				t.Fatalf("MRT orientation/ASN width/schema mismatch: %+v", records)
			}
		}
	}
	input := mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100}}, {ASSet, []uint32{200, 300}}})
	if err := ParseMRT(context.Background(), bytes.NewReader(input), mrtLimits(), func(v MRTRecord) error {
		if v.Origin != 0 || v.Segments[1].Type != ASSet {
			t.Fatal("AS set invented ordered origin")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestMRTTruncationCorruptionLimitsAndCancellation(t *testing.T) {
	input := mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100, 200}}})
	for _, size := range []int{0, 1, 11, 12, len(input) - 1} {
		if err := ParseMRT(context.Background(), bytes.NewReader(input[:size]), mrtLimits(), func(MRTRecord) error { return nil }); err == nil {
			t.Fatalf("MRT truncation accepted at %d", size)
		}
	}
	limits := mrtLimits()
	limits.FrameBytes = 4
	if err := ParseMRT(context.Background(), bytes.NewReader(input), limits, func(MRTRecord) error { return nil }); err == nil {
		t.Fatal("frame allocation cap ignored")
	}
	limits = mrtLimits()
	limits.Bytes = int64(len(input) - 1)
	if err := ParseMRT(context.Background(), bytes.NewReader(input), limits, func(MRTRecord) error { return nil }); err == nil {
		t.Fatal("total byte cap ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ParseMRT(ctx, bytes.NewReader(input), mrtLimits(), func(MRTRecord) error { return nil }); err != context.Canceled {
		t.Fatal("MRT cancellation ignored")
	}
	bad := append([]byte(nil), input...)
	binary.BigEndian.PutUint16(bad[4:6], 16)
	if err := ParseMRT(context.Background(), bytes.NewReader(bad), mrtLimits(), func(MRTRecord) error { return nil }); err == nil {
		t.Fatal("unsupported MRT type guessed")
	}
}
func FuzzParseMRT(f *testing.F) {
	f.Add(mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100, 200}}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := mrtLimits()
		limits.FrameBytes = 4096
		limits.Bytes = 1 << 16
		_ = ParseMRT(context.Background(), bytes.NewReader(data), limits, func(record MRTRecord) error {
			if !record.Prefix.IsValid() || len(record.Segments) > 255 {
				t.Fatal("invalid typed MRT result")
			}
			return nil
		})
	})
}
func TestVRPLongestCoverAndMOAS(t *testing.T) {
	index, err := NewVRPIndex([]VRP{{netip.MustParsePrefix("2001:db8::/32"), 48, 100}, {netip.MustParsePrefix("2001:db8:1::/48"), 48, 200}}, true)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("2001:db8:1::/48")
	if index.Validate(prefix, 100) != RPKIValid || index.Validate(prefix, 200) != RPKIValid || index.Validate(prefix, 300) != RPKIInvalid {
		t.Fatal("all covering VRPs/origins not considered")
	}
}
