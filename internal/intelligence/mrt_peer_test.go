package intelligence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestMRTPeerKeyNormalizesMappedAddressesAndPreservesIPv6Tail(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	first := netip.MustParseAddr("2001:db8::1")
	second := netip.MustParseAddr("2001:db8::2")
	key := mrtPeerKey(ipv4.AsSlice(), 100)
	if key == ([32]byte{}) || key != mrtPeerKey(mapped.AsSlice(), 100) || key == mrtPeerKey(ipv4.AsSlice(), 101) || mrtPeerKey(first.AsSlice(), 100) == mrtPeerKey(second.AsSlice(), 100) || mrtPeerKey(ipv4.AsSlice(), 0) != ([32]byte{}) {
		t.Fatal("private peer hashing lost normalized ASN/address identity")
	}
}

func TestMRTColdCaptureIntervalBoundsAndLegacySerialization(t *testing.T) {
	policy, snapshot, binding := stateFixture()
	p := &MRTSourceProof{Version: 1, Collector: sha256.Sum256([]byte("fixture collector")), BasePayloadHash: snapshot.PayloadHash, BaseBytes: 1, CapturedAt: clock(), Through: clock()}
	data, err := json.Marshal(p)
	if err != nil || bytes.Contains(data, []byte("CaptureUntil")) || !p.CaptureEnd().Equal(p.CapturedAt) {
		t.Fatal("optional capture-end changed legacy cold proof", string(data), err)
	}
	p.CaptureUntil = clock().Add(-time.Second)
	if _, err = p.ContentHash(); err == nil {
		t.Fatal("reversed capture interval accepted")
	}
	p.CaptureUntil = clock().Add(25 * time.Hour)
	snapshot.MRTProof = p
	snapshot.ProofKind, policy.ProofKind = "embedded", "embedded"
	result, err := Reconcile(BuildState{}, []SourcePolicy{policy}, []SourceSnapshot{snapshot}, clock(), binding)
	if err != nil || len(result.State.Sources) != 0 {
		t.Fatal("last capture clock bypassed future bound", result, err)
	}
}

func TestMRTParserFlagsDuplicatePeerAddressASNBeforeReplay(t *testing.T) {
	raw := mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100, 200}}})
	ribOffset := 12 + int(binary.BigEndian.Uint32(raw[8:12]))
	peer := append([]byte(nil), raw[12:ribOffset]...)
	binary.BigEndian.PutUint16(peer[6:8], 2)
	peer = append(peer, peer[8:]...)
	raw = append(mrtFrame(1, peer), raw[ribOffset:]...)
	var record MRTRecord
	if err := ParseMRT(context.Background(), bytes.NewReader(raw), mrtLimits(), func(v MRTRecord) error { record = v; return nil }); err != nil {
		t.Fatal(err)
	}
	if !record.PeerAmbiguous || record.PeerKey == ([32]byte{}) || record.PeerIndex != 0 || record.PeerTable != 1 {
		t.Fatal("duplicate peer IP/ASN could bootstrap an arbitrary transport session", record)
	}
}
