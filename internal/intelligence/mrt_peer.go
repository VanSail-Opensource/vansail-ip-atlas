package intelligence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// MRTRouteIdentity is private replay metadata, never an IP fact. PeerKey hashes
// the normalized literal peer address and ASN; addresses and collector labels
// are not retained. PeerIndex remains an ordinal, never a transport session ID.
type MRTRouteIdentity struct {
	PeerKey       [32]byte
	PeerIndex     uint16
	PeerTable     uint32
	PathID        uint32
	AddPath       bool
	PeerAmbiguous bool
	CapturedAt    time.Time
}

func mrtPeerKey(address []byte, asn uint32) [32]byte {
	addr, ok := netip.AddrFromSlice(address)
	if !ok || asn == 0 {
		return [32]byte{}
	}
	addr = addr.Unmap()
	var input [25]byte
	copy(input[:4], "MRTP")
	binary.BigEndian.PutUint32(input[4:8], asn)
	copy(input[8:24], addr.AsSlice())
	input[24] = byte(addr.BitLen())
	return sha256.Sum256(input[:])
}

type MRTPeerSession struct {
	PeerKey, Session [32]byte
	ObservedAt       time.Time
	Local            bool
}

type MRTArchiveProof struct {
	PayloadHash [32]byte
	From, Until time.Time
}

type MRTPeerBinding struct {
	PeerKey, Session [32]byte
	PeerIndex        uint16
	PeerTable        uint32
	AFI              uint16
	AddPath          bool
}

// MRTSourceProof binds private replay state to one actual collector, the base
// RIB bytes and a contiguous set of complete UPDATE payloads. Collector identity
// is separate from content hashing, so mirrors cannot manufacture family votes.
type MRTSourceProof struct {
	Version             uint16
	Collector           [32]byte
	BasePayloadHash     [32]byte
	BaseBytes           int64
	CapturedAt, Through time.Time
	CaptureUntil        time.Time `json:",omitzero"`
	Archives            []MRTArchiveProof
	Peers               []MRTPeerBinding
}

// CaptureEnd is the last fully validated base-RIB frame clock. Legacy proofs
// described a single capture epoch. The separate Through clock remains the
// conservative earliest cold epoch until verified UPDATE intervals advance it.
func (p *MRTSourceProof) CaptureEnd() time.Time {
	if p == nil {
		return time.Time{}
	}
	if p.CaptureUntil.IsZero() {
		return p.CapturedAt
	}
	return p.CaptureUntil
}

func cloneMRTProof(proof *MRTSourceProof) *MRTSourceProof {
	if proof == nil {
		return nil
	}
	copy := *proof
	copy.Archives = append([]MRTArchiveProof(nil), proof.Archives...)
	copy.Peers = append([]MRTPeerBinding(nil), proof.Peers...)
	return &copy
}

// ContentHash deduplicates exact input sets independently of collector labels.
// Source/peer binding remains authenticated by the complete private state seal.
func (p *MRTSourceProof) ContentHash() ([32]byte, error) {
	if p == nil || p.Version != 1 || p.Collector == ([32]byte{}) || p.BasePayloadHash == ([32]byte{}) || p.BaseBytes <= 0 || p.BaseBytes > 1<<30 || p.CapturedAt.IsZero() || p.CaptureEnd().Before(p.CapturedAt) || p.Through.Before(p.CapturedAt) || len(p.Archives) > 512 || len(p.Peers) > 2*65535 {
		return [32]byte{}, errors.New("private MRT source proof invalid")
	}
	seenPeers := map[struct {
		Peer [32]byte
		AFI  uint16
	}]bool{}
	peerSessions := map[[32]byte][32]byte{}
	sessionPeers := map[[32]byte][32]byte{}
	for _, peer := range p.Peers {
		key := struct {
			Peer [32]byte
			AFI  uint16
		}{peer.PeerKey, peer.AFI}
		if peer.PeerKey == ([32]byte{}) || peer.Session == ([32]byte{}) || peer.PeerTable != 1 || peer.AFI != 1 && peer.AFI != 2 || seenPeers[key] {
			return [32]byte{}, errors.New("private MRT peer binding invalid")
		}
		if prior, ok := peerSessions[peer.PeerKey]; ok && prior != peer.Session {
			return [32]byte{}, errors.New("private MRT peer maps to multiple sessions")
		}
		if prior, ok := sessionPeers[peer.Session]; ok && prior != peer.PeerKey {
			return [32]byte{}, errors.New("private MRT session maps to multiple peers")
		}
		seenPeers[key] = true
		peerSessions[peer.PeerKey] = peer.Session
		sessionPeers[peer.Session] = peer.PeerKey
	}
	if len(p.Archives) == 0 {
		if !p.Through.Equal(p.CapturedAt) {
			return [32]byte{}, errors.New("cold MRT proof cannot advance its capture clock")
		}
		return p.BasePayloadHash, nil
	}
	archives := append([]MRTArchiveProof(nil), p.Archives...)
	for i := range archives {
		v := &archives[i]
		if v.PayloadHash == ([32]byte{}) || !v.Until.After(v.From) || i == 0 && (v.From.After(p.CapturedAt) || !v.Until.After(p.CapturedAt)) || i > 0 && !v.From.Equal(archives[i-1].Until) {
			return [32]byte{}, errors.New("private MRT archive continuity invalid")
		}
		v.From, v.Until = v.From.UTC(), v.Until.UTC()
	}
	if !p.Through.Equal(archives[len(archives)-1].Until) || len(p.Peers) == 0 {
		return [32]byte{}, errors.New("private MRT replay proof incomplete")
	}
	data, err := json.Marshal(struct {
		Version  uint16
		Base     [32]byte
		Archives []MRTArchiveProof
	}{1, p.BasePayloadHash, archives})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}
