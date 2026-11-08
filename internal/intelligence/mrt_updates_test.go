package intelligence

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func bgpAttribute(flags, kind byte, payload []byte) []byte {
	if len(payload) > 255 {
		out := []byte{flags | 0x10, kind}
		out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
		return append(out, payload...)
	}
	return append([]byte{flags, kind, byte(len(payload))}, payload...)
}
func bgpPath(width int, segments ...PathSegment) []byte {
	var out []byte
	for _, segment := range segments {
		kind := byte(segment.Type)
		if segment.Type == ASSequence {
			kind = 2
		} else if segment.Type == ASSet {
			kind = 1
		}
		out = append(out, kind, byte(len(segment.ASNs)))
		for _, asn := range segment.ASNs {
			if width == 2 {
				out = binary.BigEndian.AppendUint16(out, uint16(asn))
			} else {
				out = binary.BigEndian.AppendUint32(out, asn)
			}
		}
	}
	return out
}
func bgpNLRI(prefix string, addPath bool, id uint32) []byte {
	p := netip.MustParsePrefix(prefix)
	var out []byte
	if addPath {
		out = binary.BigEndian.AppendUint32(out, id)
	}
	out = append(out, byte(p.Bits()))
	return append(out, p.Addr().AsSlice()[:(p.Bits()+7)/8]...)
}
func bgpMessage(kind byte, payload []byte) []byte {
	out := bytes.Repeat([]byte{0xff}, 16)
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)+19))
	out = append(out, kind)
	return append(out, payload...)
}
func bgpUpdate(attributes, withdrawn, nlri []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	out = append(out, withdrawn...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(attributes)))
	out = append(out, attributes...)
	return bgpMessage(2, append(out, nlri...))
}
func bgp4mpFrame(subtype uint16, extended, transport6 bool, message []byte) []byte {
	wide := subtype == 4 || subtype == 5 || subtype == 7 || subtype == 9 || subtype == 11
	var payload []byte
	if wide {
		payload = binary.BigEndian.AppendUint32(payload, 100)
		payload = binary.BigEndian.AppendUint32(payload, 200)
	} else {
		payload = binary.BigEndian.AppendUint16(payload, 100)
		payload = binary.BigEndian.AppendUint16(payload, 200)
	}
	payload = binary.BigEndian.AppendUint16(payload, 0)
	if transport6 {
		payload = binary.BigEndian.AppendUint16(payload, 2)
		payload = append(payload, netip.MustParseAddr("2001:db8::1").AsSlice()...)
		payload = append(payload, netip.MustParseAddr("2001:db8::2").AsSlice()...)
	} else {
		payload = binary.BigEndian.AppendUint16(payload, 1)
		payload = append(payload, 192, 0, 2, 1, 192, 0, 2, 2)
	}
	payload = append(payload, message...)
	kind := uint16(16)
	if extended {
		kind = 17
		payload = append(binary.BigEndian.AppendUint32(nil, 123456), payload...)
	}
	out := mrtFrame(subtype, payload)
	binary.BigEndian.PutUint16(out[4:6], kind)
	return out
}
func updateAttributes(width int, path ...PathSegment) []byte {
	out := bgpAttribute(0x40, 1, []byte{0})
	out = append(out, bgpAttribute(0x40, 2, bgpPath(width, path...))...)
	return append(out, bgpAttribute(0x40, 3, []byte{192, 0, 2, 1})...)
}
func readUpdates(input []byte) ([]MRTUpdate, error) {
	var records []MRTUpdate
	err := ParseBGP4MP(context.Background(), bytes.NewReader(input), mrtLimits(), func(v MRTUpdate) error { records = append(records, v); return nil })
	return records, err
}

func TestBGP4MPWidthsAddPathTransportAndExtendedTime(t *testing.T) {
	for _, subtype := range []uint16{1, 4, 6, 7, 8, 9, 10, 11} {
		wide := subtype == 4 || subtype == 7 || subtype == 9 || subtype == 11
		addPath := subtype >= 8
		width := 2
		origin := uint32(200)
		if wide {
			width = 4
			origin = 420000
		}
		path := []PathSegment{{ASSequence, []uint32{100, 100, origin}}}
		for _, transport6 := range []bool{false, true} {
			for _, extended := range []bool{false, true} {
				input := bgp4mpFrame(subtype, extended, transport6, bgpUpdate(updateAttributes(width, path...), nil, bgpNLRI("192.0.2.0/24", addPath, 99)))
				got, err := readUpdates(input)
				if err != nil || len(got) != 1 {
					t.Fatalf("subtype=%d: %+v %v", subtype, got, err)
				}
				if got[0].Kind != MRTAnnounce || got[0].Origin != origin || got[0].Prefix.String() != "192.0.2.0/24" || got[0].AddPath != addPath || !reflect.DeepEqual(got[0].Segments, path) {
					t.Fatalf("path semantics lost: %+v", got)
				}
				if addPath && got[0].PathID != 99 {
					t.Fatal("ADDPATH identity discarded before replay")
				}
				if got[0].Local != (subtype == 6 || subtype == 7 || subtype == 10 || subtype == 11) {
					t.Fatal("local direction lost")
				}
				if extended && got[0].ObservedAt.Nanosecond() != 123456000 {
					t.Fatal("extended timestamp lost")
				}
			}
		}
	}
}

func TestAS4TransitionReconstructionPreservesSetsPrependsAndConfederations(t *testing.T) {
	for _, tc := range []struct {
		name           string
		old, as4, want []PathSegment
		extra          []byte
	}{
		{"prepends", []PathSegment{{ASSequence, []uint32{100, 100, 23456, 23456}}}, []PathSegment{{ASSequence, []uint32{70000, 80000}}}, []PathSegment{{ASSequence, []uint32{100, 100}}, {ASSequence, []uint32{70000, 80000}}}, nil},
		{"set-counts-once", []PathSegment{{ASSequence, []uint32{100, 23456}}, {ASSet, []uint32{200, 23456, 300}}}, []PathSegment{{ASSequence, []uint32{70000}}, {ASSet, []uint32{80000, 90000}}}, []PathSegment{{ASSequence, []uint32{100}}, {ASSequence, []uint32{70000}}, {ASSet, []uint32{80000, 90000}}}, nil},
		{"leading-confederation", []PathSegment{{ConfederationSequence, []uint32{65000, 65001}}, {ASSequence, []uint32{100, 23456}}}, []PathSegment{{ASSequence, []uint32{70000}}}, []PathSegment{{ConfederationSequence, []uint32{65000, 65001}}, {ASSequence, []uint32{100}}, {ASSequence, []uint32{70000}}}, nil},
		{"as4-too-long-ignored", []PathSegment{{ASSequence, []uint32{100}}}, []PathSegment{{ASSequence, []uint32{70000, 80000}}}, []PathSegment{{ASSequence, []uint32{100}}}, nil},
		{"old-aggregator-ignores-as4", []PathSegment{{ASSequence, []uint32{100, 23456}}}, []PathSegment{{ASSequence, []uint32{70000}}}, []PathSegment{{ASSequence, []uint32{100, 23456}}}, append(bgpAttribute(0xc0, 7, []byte{0, 100, 192, 0, 2, 1}), bgpAttribute(0xc0, 18, []byte{0, 1, 17, 112, 192, 0, 2, 1})...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := updateAttributes(2, tc.old...)
			attrs = append(attrs, bgpAttribute(0xc0, 17, bgpPath(4, tc.as4...))...)
			attrs = append(attrs, tc.extra...)
			got, err := readUpdates(bgp4mpFrame(1, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.2.0/24", false, 0))))
			if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].Segments, tc.want) {
				t.Fatalf("got %+v, want %+v: %v", got, tc.want, err)
			}
		})
	}
}

func TestBGP4MPWithdrawalsMPReachSessionResetAndEndOfRIB(t *testing.T) {
	attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420000}})
	mp := []byte{0, 2, 1, 16}
	mp = append(mp, make([]byte, 16)...)
	mp = append(mp, 0)
	mp = append(mp, bgpNLRI("2001:db8::/32", true, 7)...)
	attrs = append(attrs, bgpAttribute(0x80, 14, mp)...)
	attrs = append(attrs, bgpAttribute(0x80, 15, append([]byte{0, 2, 1}, bgpNLRI("2001:db8:1::/48", true, 6)...))...)
	input := bgp4mpFrame(9, false, false, bgpUpdate(attrs, bgpNLRI("192.0.2.0/24", true, 5), nil))
	input = append(input, bgp4mpFrame(4, false, false, bgpUpdate(nil, nil, nil))...)
	input = append(input, bgp4mpFrame(5, false, false, []byte{0, 6, 0, 1})...)
	got, err := readUpdates(input)
	if err != nil || len(got) != 5 {
		t.Fatalf("got %+v: %v", got, err)
	}
	want := []MRTUpdateKind{MRTWithdraw, MRTWithdraw, MRTAnnounce, MRTEndOfRIB, MRTSessionReset}
	for i, kind := range want {
		if got[i].Kind != kind {
			t.Fatalf("event order changed: %+v", got)
		}
		if got[i].Session != got[0].Session {
			t.Fatal("session width changed identity")
		}
	}
	if got[2].Prefix.String() != "2001:db8::/32" || got[2].PathID != 7 || got[2].Origin != 420000 {
		t.Fatal("IPv6 MP announcement lost")
	}
	if got[3].AFI != 1 || got[4].Prefix.IsValid() {
		t.Fatal("control event fabricated a prefix")
	}
}

func TestBGP4MPFailsClosedAndHonorsBudgetsSinkAndCancellation(t *testing.T) {
	valid := bgp4mpFrame(4, false, false, bgpUpdate(updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420000}}), nil, bgpNLRI("192.0.2.0/24", false, 0)))
	for _, size := range []int{0, 1, 11, 12, len(valid) - 1} {
		if _, err := readUpdates(valid[:size]); err == nil {
			t.Fatalf("truncation %d accepted", size)
		}
	}
	for _, offset := range []int{4, 6, 32, 48, 50, 59} {
		bad := append([]byte(nil), valid...)
		bad[offset] ^= 0x7f
		if _, err := readUpdates(bad); err == nil {
			t.Fatalf("corrupt field at %d admitted", offset)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ParseBGP4MP(ctx, bytes.NewReader(valid), mrtLimits(), func(MRTUpdate) error { return nil }); err != context.Canceled {
		t.Fatal("cancellation ignored")
	}
	stop := errors.New("stop")
	if err := ParseBGP4MP(context.Background(), bytes.NewReader(valid), mrtLimits(), func(MRTUpdate) error { return stop }); err != stop {
		t.Fatal("sink error lost")
	}
	limits := mrtLimits()
	limits.Records = 1
	if err := ParseBGP4MP(context.Background(), bytes.NewReader(append(valid, valid...)), limits, func(MRTUpdate) error { return nil }); err == nil {
		t.Fatal("record bound ignored")
	}
	if _, err := readUpdates(bgp4mpFrame(4, false, false, bgpUpdate(bgpAttribute(0x80, 14, []byte{0, 2, 128, 0, 0}), nil, nil))); err == nil {
		t.Fatal("unsupported SAFI guessed")
	}
}

func TestAS4TransitionAttributeDiscardAndTerminalSet(t *testing.T) {
	old := []PathSegment{{ASSequence, []uint32{100, 23456}}}
	for _, tc := range []struct {
		name  string
		width int
		extra []byte
		want  []PathSegment
	}{
		{"malformed-as4-discarded", 2, bgpAttribute(0xc0, 17, []byte{2, 2, 0, 1}), old},
		{"new-new-as4-discarded", 4, bgpAttribute(0xc0, 17, []byte{0xff}), old},
		{"confederation-removed-from-as4", 2, bgpAttribute(0xc0, 17, bgpPath(4, PathSegment{ConfederationSequence, []uint32{65000}}, PathSegment{ASSequence, []uint32{70000}})), []PathSegment{{ASSequence, []uint32{100}}, {ASSequence, []uint32{70000}}}},
		{"as-trans-aggregator-permits-reconstruction", 2, append(append(bgpAttribute(0xc0, 17, bgpPath(4, PathSegment{ASSequence, []uint32{70000}})), bgpAttribute(0xc0, 7, []byte{0x5b, 0xa0, 192, 0, 2, 1})...), bgpAttribute(0xc0, 18, []byte{0, 1, 17, 112, 192, 0, 2, 1})...), []PathSegment{{ASSequence, []uint32{100}}, {ASSequence, []uint32{70000}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := append(updateAttributes(tc.width, old...), tc.extra...)
			subtype := uint16(1)
			if tc.width == 4 {
				subtype = 4
			}
			got, err := readUpdates(bgp4mpFrame(subtype, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.2.0/24", false, 0))))
			if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].Segments, tc.want) {
				t.Fatalf("path %+v, want %+v: %v", got, tc.want, err)
			}
		})
	}
	attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100}}, PathSegment{ASSet, []uint32{200, 300}})
	got, err := readUpdates(bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.2.0/24", false, 0))))
	if err != nil || len(got) != 1 || got[0].Origin != 0 || got[0].Segments[1].Type != ASSet {
		t.Fatalf("terminal set invented origin: %+v %v", got, err)
	}
}

func TestMRTTableDumpRequiresFourOctetPathAndIgnoresTransitionAttribute(t *testing.T) {
	for _, width := range []int{2, 4} {
		input := mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100, 420000}}})
		peerEnd := 12 + int(binary.BigEndian.Uint32(input[8:12]))
		prefix := append([]byte(nil), input[peerEnd+12:peerEnd+12+16]...)
		path := bgpAttribute(0x40, 2, bgpPath(width, PathSegment{ASSequence, []uint32{100, 23456}}))
		attrs := append(path, bgpAttribute(0xc0, 17, bgpPath(4, PathSegment{ASSequence, []uint32{70000}}))...)
		prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(attrs)))
		input = append(append([]byte(nil), input[:peerEnd]...), mrtFrame(2, append(prefix, attrs...))...)
		var got []MRTRecord
		err := ParseMRT(context.Background(), bytes.NewReader(input), mrtLimits(), func(record MRTRecord) error { got = append(got, record); return nil })
		if width == 2 {
			if err == nil {
				t.Fatal("TABLE_DUMP_V2 guessed a forbidden two-octet AS_PATH")
			}
		} else if err != nil || len(got) != 1 || got[0].Origin != 23456 {
			t.Fatalf("four-octet TABLE_DUMP_V2 used legacy transition attribute: %+v %v", got, err)
		}
	}
}

func TestBGP4MPControlMessagesAndMalformedNLRIAreNotRIBFacts(t *testing.T) {
	open := []byte{4, 0, 100, 0, 90, 192, 0, 2, 1, 0}
	extendedOpen := append(append([]byte(nil), open[:9]...), 255, 255, 0, 4, 2, 0, 1, 0)
	var input []byte
	for _, message := range [][]byte{bgpMessage(1, open), bgpMessage(1, extendedOpen), bgpMessage(4, nil), bgpMessage(5, []byte{0, 1, 0, 1}), bgpMessage(3, []byte{6, 0})} {
		input = append(input, bgp4mpFrame(4, false, false, message)...)
	}
	got, err := readUpdates(input)
	if err != nil || len(got) != 3 {
		t.Fatalf("controls: %+v %v", got, err)
	}
	for _, event := range got {
		if event.Kind != MRTSessionReset || event.Prefix.IsValid() || len(event.Segments) != 0 {
			t.Fatal("control synthesized route")
		}
	}
	for _, message := range [][]byte{
		bgpMessage(1, append(open, 1)), bgpMessage(4, []byte{0}), bgpMessage(3, []byte{0}),
		bgpMessage(5, []byte{0, 1, 1, 1}),
		bgpUpdate(nil, []byte{33, 192, 0, 2, 0, 0}, nil),
		bgpUpdate(nil, nil, bgpNLRI("192.0.2.0/24", false, 0)),
		bgpUpdate(append(updateAttributes(4, PathSegment{ASSequence, []uint32{100}}), bgpAttribute(0x40, 2, nil)...), nil, nil),
	} {
		if _, err := readUpdates(bgp4mpFrame(4, false, false, message)); err == nil {
			t.Fatal("malformed/control semantics admitted")
		}
	}
	// An empty MP_UNREACH is only an EOR marker when it is the sole attribute.
	eor := bgpAttribute(0x80, 15, []byte{0, 2, 1})
	got, err = readUpdates(bgp4mpFrame(4, false, false, bgpUpdate(eor, nil, nil)))
	if err != nil || len(got) != 1 || got[0].Kind != MRTEndOfRIB || got[0].AFI != 2 {
		t.Fatal("IPv6 EOR lost")
	}
	got, err = readUpdates(bgp4mpFrame(4, false, false, bgpUpdate(append(eor, bgpAttribute(0x40, 1, []byte{0})...), nil, nil)))
	if err != nil || len(got) != 0 {
		t.Fatal("ordinary empty NLRI invented EOR")
	}
}

func TestBGP4MPFrameBytePeerAndEventBounds(t *testing.T) {
	attrs := updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420000}})
	valid := bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, bgpNLRI("192.0.2.0/24", false, 0)))
	for _, limits := range []MRTLimits{
		{Bytes: int64(len(valid) - 1), FrameBytes: 65536, Records: 100, Peers: 100},
		{Bytes: 1048576, FrameBytes: 10, Records: 100, Peers: 100},
	} {
		if err := ParseBGP4MP(context.Background(), bytes.NewReader(valid), limits, func(MRTUpdate) error { return nil }); err == nil {
			t.Fatal("allocation/byte bound ignored")
		}
	}
	other := append([]byte(nil), valid...)
	other[24]++ // peer transport tuple differs
	limits := mrtLimits()
	limits.Peers = 1
	if err := ParseBGP4MP(context.Background(), bytes.NewReader(append(valid, other...)), limits, func(MRTUpdate) error { return nil }); err == nil {
		t.Fatal("session bound ignored")
	}
	dual := bgp4mpFrame(4, false, false, bgpUpdate(attrs, nil, append(bgpNLRI("192.0.2.0/24", false, 0), bgpNLRI("198.51.100.0/24", false, 0)...)))
	limits = mrtLimits()
	limits.Records = 1
	called := false
	if err := ParseBGP4MP(context.Background(), bytes.NewReader(dual), limits, func(MRTUpdate) error { called = true; return nil }); err == nil || called {
		t.Fatal("event budget must reject update before sink emission")
	}
}

func FuzzParseBGP4MP(f *testing.F) {
	f.Add(bgp4mpFrame(4, false, false, bgpUpdate(updateAttributes(4, PathSegment{ASSequence, []uint32{100, 420000}}), nil, bgpNLRI("192.0.2.0/24", false, 0))))
	f.Add(bgp4mpFrame(1, false, false, bgpUpdate(append(updateAttributes(2, PathSegment{ASSequence, []uint32{100, 23456}}), bgpAttribute(0xc0, 17, bgpPath(4, PathSegment{ASSequence, []uint32{70000}}))...), nil, bgpNLRI("192.0.2.0/24", false, 0))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := mrtLimits()
		limits.FrameBytes = 4096
		limits.Bytes = 65536
		_ = ParseBGP4MP(context.Background(), bytes.NewReader(data), limits, func(event MRTUpdate) error {
			if len(event.Segments) > 255 || event.Kind < MRTAnnounce || event.Kind > MRTEndOfRIB {
				t.Fatal("invalid typed event")
			}
			if event.Kind == MRTAnnounce || event.Kind == MRTWithdraw {
				if !event.Prefix.IsValid() {
					t.Fatal("route event without prefix")
				}
			}
			return nil
		})
	})
}
