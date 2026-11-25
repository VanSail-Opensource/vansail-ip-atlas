package intelligence

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"
)

// These inputs are private protocol adapters, never source certification. The
// admission coordinator authenticates the exact base state and archive hashes.
type MRTStreamBase struct {
	Family string
	Proof  *MRTSourceProof
	Walk   func(context.Context, func(NormalizedRecord) error) error
}
type MRTStreamArchive struct {
	Collector [32]byte
	Proof     MRTArchiveProof
	Scan      func(context.Context, int, func(MRTUpdate) error, func(MRTPeerSession) error) (MRTSnapshotClock, error)
}
type MRTStreamResult struct {
	Proof        *MRTSourceProof
	Updates      int
	ColdFallback bool
	Reason       string
}
type MRTReplayBudget struct {
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
	updates  int
}

func NewMRTReplayBudget(ctx context.Context) *MRTReplayBudget {
	bounded, cancel := context.WithTimeout(ctx, 180*time.Second)
	return &MRTReplayBudget{ctx: bounded, cancel: cancel, deadline: time.Now().Add(180 * time.Second)}
}
func (b *MRTReplayBudget) Close() {
	if b != nil {
		b.cancel()
	}
}
func (b *MRTReplayBudget) Context() context.Context { return b.ctx }
func (b *MRTReplayBudget) exhausted() bool {
	return b == nil || b.ctx.Err() != nil || !time.Now().Before(b.deadline)
}

type streamMRTKey struct {
	peer    [32]byte
	prefix  netip.Prefix
	id      uint32
	addPath bool
}
type streamMRTPeer struct {
	index uint16
	table uint32
	afis  byte
	modes byte
}
type streamMRTChange struct {
	event MRTUpdate
	cost  int
}

func compareMRTPrefix(a, b netip.Prefix) int {
	if n := a.Addr().Compare(b.Addr()); n != 0 {
		return n
	}
	if a.Bits() < b.Bits() {
		return -1
	}
	if a.Bits() > b.Bits() {
		return 1
	}
	return 0
}
func streamKey(record NormalizedRecord) streamMRTKey {
	return streamMRTKey{record.MRT.PeerKey, record.Path.Prefix, record.MRT.PathID, record.MRT.AddPath}
}

// StreamMRTReplay keeps only peer identities and changed routes in memory. The
// full RIB is validated and merged through bounded private record partitions;
// it is never copied into a million-entry resident route map. The sink remains
// transactional until Proof is returned. Missing/ambiguous joins always cold
// fallback, including duplicate peer indexes and ADDPATH-key collisions.
func StreamMRTReplay(ctx context.Context, base MRTStreamBase, archives []MRTStreamArchive, now time.Time, budget *MRTReplayBudget, sink func(NormalizedRecord) error) (result MRTStreamResult, failure error) {
	cold := func(reason string) (MRTStreamResult, error) {
		result.Proof = nil
		result.ColdFallback = true
		result.Reason = reason
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, nil
	}
	if base.Proof == nil || base.Walk == nil || sink == nil || base.Family == "" || len(base.Family) > 256 || len(archives) == 0 || len(base.Proof.Archives)+len(archives) > 512 || budget.exhausted() {
		return cold("replay_inputs_missing_or_budget")
	}
	if _, err := base.Proof.ContentHash(); err != nil {
		return cold("base_content_proof_invalid")
	}
	if !base.Proof.CaptureEnd().Equal(base.Proof.CapturedAt) {
		return cold("multi_clock_rib_requires_cold_snapshot")
	}
	if now.IsZero() || !now.Before(base.Proof.CapturedAt.Add(720*time.Hour)) {
		return cold("base_capture_expired")
	}
	through := base.Proof.Through
	for i, archive := range archives {
		if archive.Scan == nil || archive.Collector != base.Proof.Collector || archive.Proof.PayloadHash == ([32]byte{}) || !archive.Proof.Until.After(archive.Proof.From) || archive.Proof.Until.After(now) || i == 0 && (archive.Proof.From.After(through) || !archive.Proof.Until.After(through)) || i > 0 && !archive.Proof.From.Equal(archives[i-1].Proof.Until) {
			return cold("archive_collector_hash_interval_or_gap_invalid")
		}
	}
	peers := map[[32]byte]streamMRTPeer{}
	sessions := map[[32]byte][32]byte{}
	reverse := map[[32]byte][32]byte{}
	for _, binding := range base.Proof.Peers {
		info := peers[binding.PeerKey]
		info.index, info.table = binding.PeerIndex, binding.PeerTable
		info.afis |= 1 << binding.AFI
		if binding.AddPath {
			info.modes |= 1 << binding.AFI
		}
		peers[binding.PeerKey] = info
		sessions[binding.PeerKey] = binding.Session
		reverse[binding.Session] = binding.PeerKey
	}
	var previous netip.Prefix
	seenPrefix := map[streamMRTKey]bool{}
	paths := 0
	err := base.Walk(budget.ctx, func(record NormalizedRecord) error {
		if budget.exhausted() {
			return context.DeadlineExceeded
		}
		// This replay model reconstructs origin rows from supported paths. An
		// empty observed-origin boundary has no such path and must survive in a
		// full capture; ignoring it here would restore a false broader origin.
		if record.Kind == RecordOrigins && (record.Origins == nil || len(record.Origins.Origins) == 0) {
			return errMRTReplayCold
		}
		if record.Kind != RecordPath {
			return nil
		}
		if record.Validate() != nil || record.MRT == nil || record.MRT.PeerAmbiguous || record.MRT.PeerKey == ([32]byte{}) || record.MRT.PeerTable != 1 || record.MRTOriginatedAt == nil || !record.Path.Observation.Current || !IsPublicASN(record.Path.Observation.Origin) {
			return errMRTReplayCold
		}
		p := record.Path.Prefix
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" || record.MRT.CapturedAt.Before(base.Proof.CapturedAt) || record.MRT.CapturedAt.After(through) {
			return errMRTReplayCold
		}
		if len(base.Proof.Archives) == 0 && !record.MRT.CapturedAt.Equal(base.Proof.CapturedAt) {
			return errMRTReplayCold
		}
		if previous.IsValid() && compareMRTPrefix(previous, p) > 0 {
			return errMRTReplayCold
		}
		if !previous.IsValid() || previous != p {
			clear(seenPrefix)
			previous = p
		}
		key := streamKey(record)
		if seenPrefix[key] || len(seenPrefix) >= 65535 {
			return errMRTReplayCold
		}
		seenPrefix[key] = true
		info, exists := peers[key.peer]
		if exists && (info.index != record.MRT.PeerIndex || info.table != record.MRT.PeerTable) {
			return errMRTReplayCold
		}
		info.index, info.table = record.MRT.PeerIndex, record.MRT.PeerTable
		afi := uint16(2)
		if p.Addr().Is4() {
			afi = 1
		}
		if info.afis&(1<<afi) != 0 && (info.modes&(1<<afi) != 0) != record.MRT.AddPath {
			return errMRTReplayCold
		}
		info.afis |= 1 << afi
		if record.MRT.AddPath {
			info.modes |= 1 << afi
		}
		peers[key.peer] = info
		if len(peers) > 65535 {
			return errMRTReplayCold
		}
		paths++
		return nil
	})
	if err != nil || paths == 0 {
		return cold("ambiguous_unsorted_or_incomplete_rib_identity")
	}
	preflight := 0
	for _, archive := range archives {
		clock, err := archive.Scan(budget.ctx, max(1, maxMRTReplayUpdates-budget.updates), func(event MRTUpdate) error {
			if budget.exhausted() || budget.updates >= maxMRTReplayUpdates {
				return errMRTReplayCold
			}
			budget.updates++
			preflight++
			if event.Local || event.ObservedAt.Before(through) || event.Kind == MRTSessionReset {
				return nil
			}
			if event.Kind == MRTAnnounce && !IsPublicASN(event.Origin) {
				return errMRTReplayCold
			}
			info, exists := peers[event.PeerKey]
			if !exists || event.AFI != 1 && event.AFI != 2 || info.afis&(1<<event.AFI) == 0 {
				return errMRTReplayCold
			}
			if event.Kind != MRTEndOfRIB && (info.modes&(1<<event.AFI) != 0) != event.AddPath {
				return errMRTReplayCold
			}
			return nil
		}, func(peer MRTPeerSession) error {
			if budget.exhausted() {
				return context.DeadlineExceeded
			}
			if peer.Local || peer.ObservedAt.Before(through) || peer.PeerKey == ([32]byte{}) {
				return nil
			}
			if _, exists := peers[peer.PeerKey]; !exists {
				return errMRTReplayCold
			}
			if prior, exists := sessions[peer.PeerKey]; exists && prior != peer.Session {
				return errMRTReplayCold
			}
			if prior, exists := reverse[peer.Session]; exists && prior != peer.PeerKey {
				return errMRTReplayCold
			}
			sessions[peer.PeerKey], reverse[peer.Session] = peer.Session, peer.PeerKey
			return nil
		})
		if err != nil || clock.Frames == 0 || clock.First.Before(archive.Proof.From) || !clock.Last.Before(archive.Proof.Until) {
			return cold("update_preflight_clock_mapping_or_limit_failed")
		}
	}
	for peer := range peers {
		if sessions[peer] == ([32]byte{}) {
			return cold("rib_peer_has_no_unique_transport_session")
		}
	}
	changes := map[streamMRTKey]streamMRTChange{}
	reset := map[[32]byte]bool{}
	working, applied := 0, 0
	last := through
	for _, archive := range archives {
		clock, err := archive.Scan(budget.ctx, maxMRTReplayUpdates, func(event MRTUpdate) error {
			if budget.exhausted() {
				return context.DeadlineExceeded
			}
			applied++
			if applied > preflight {
				return errMRTReplayCold
			}
			if event.ObservedAt.Before(through) || event.Local && event.Kind != MRTSessionReset {
				return nil
			}
			if event.ObservedAt.Before(last) {
				return errMRTReplayCold
			}
			last = event.ObservedAt
			peer, exists := reverse[event.Session]
			if !exists {
				if event.Kind == MRTSessionReset {
					return nil
				}
				return errMRTReplayCold
			}
			if event.Kind == MRTSessionReset {
				reset[peer] = true
				visited := 0
				for key, value := range changes {
					visited++
					if visited%1024 == 0 && budget.exhausted() {
						return context.DeadlineExceeded
					}
					if key.peer == peer {
						working -= value.cost
						delete(changes, key)
					}
				}
				return nil
			}
			if event.Kind == MRTEndOfRIB {
				return nil
			}
			if event.PeerKey != peer || event.Kind != MRTAnnounce && event.Kind != MRTWithdraw || reset[peer] && event.Kind == MRTAnnounce {
				return errMRTReplayCold
			}
			if event.Kind == MRTAnnounce && !IsPublicASN(event.Origin) {
				return errMRTReplayCold
			}
			key := streamMRTKey{peer, event.Prefix, event.PathID, event.AddPath}
			cost := replayRouteBytes(event)
			if prior, exists := changes[key]; exists {
				working -= prior.cost
			}
			if cost > maxMRTReplayBytes-working {
				return errMRTReplayCold
			}
			working += cost
			changes[key] = streamMRTChange{event: cloneReplayRoute(event), cost: cost}
			return nil
		}, nil)
		if err != nil || clock.Frames == 0 || clock.First.Before(archive.Proof.From) || !clock.Last.Before(archive.Proof.Until) {
			return cold("update_apply_failed_or_deadline")
		}
	}
	if applied != preflight {
		return cold("update_payload_changed_between_passes")
	}
	keys := make([]streamMRTKey, 0, len(changes))
	for key := range changes {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if n := compareMRTPrefix(a.prefix, b.prefix); n != 0 {
			return n < 0
		}
		if n := bytes.Compare(a.peer[:], b.peer[:]); n != 0 {
			return n < 0
		}
		if a.id != b.id {
			return a.id < b.id
		}
		return !a.addPath && b.addPath
	})
	emitEvent := func(key streamMRTKey, event MRTUpdate) error {
		if event.Kind == MRTWithdraw {
			return nil
		}
		info := peers[key.peer]
		identity := &MRTRouteIdentity{PeerKey: key.peer, PeerIndex: info.index, PeerTable: info.table, PathID: key.id, AddPath: key.addPath, CapturedAt: event.ObservedAt}
		originated := event.ObservedAt
		return emitMRTReplayPath(sink, NormalizedRecord{Version: 3, Kind: RecordPath, MRT: identity, MRTOriginatedAt: &originated, Path: &ScopedPath{Prefix: key.prefix, Observation: PathObservation{Origin: event.Origin, Segments: event.Segments, Family: base.Family, Current: true}}})
	}
	position := 0
	emitBefore := func(prefix netip.Prefix, include bool) error {
		for position < len(keys) {
			key := keys[position]
			n := compareMRTPrefix(key.prefix, prefix)
			if n > 0 || n == 0 && !include {
				break
			}
			position++
			if value, exists := changes[key]; exists {
				if err := emitEvent(key, value.event); err != nil {
					return err
				}
				delete(changes, key)
			}
		}
		return nil
	}
	previous = netip.Prefix{}
	err = base.Walk(budget.ctx, func(record NormalizedRecord) error {
		if budget.exhausted() {
			return context.DeadlineExceeded
		}
		if record.Kind == RecordOrigins && (record.Origins == nil || len(record.Origins.Origins) == 0) {
			return errMRTReplayCold
		}
		if record.Kind != RecordPath {
			return nil
		}
		if record.Validate() != nil || record.MRT == nil || record.Path == nil {
			return errMRTReplayCold
		}
		p := record.Path.Prefix
		if previous.IsValid() && p != previous {
			if err := emitBefore(previous, true); err != nil {
				return err
			}
		}
		if err := emitBefore(p, false); err != nil {
			return err
		}
		previous = p
		key := streamKey(record)
		if change, exists := changes[key]; exists {
			delete(changes, key)
			return emitEvent(key, change.event)
		}
		if reset[key.peer] {
			return nil
		}
		return emitMRTReplayPath(sink, record)
	})
	if err != nil {
		return cold("replay_materialization_aborted")
	}
	for position < len(keys) {
		key := keys[position]
		position++
		if change, exists := changes[key]; exists {
			if err := emitEvent(key, change.event); err != nil {
				return cold("replay_materialization_aborted")
			}
		}
	}
	if budget.exhausted() {
		return cold("replay_deadline_exceeded")
	}
	proof := cloneMRTProof(base.Proof)
	proof.Archives = append(proof.Archives, make([]MRTArchiveProof, len(archives))...)
	for i, archive := range archives {
		proof.Archives[len(base.Proof.Archives)+i] = archive.Proof
	}
	proof.Through = archives[len(archives)-1].Proof.Until
	proof.Peers = nil
	for peer, info := range peers {
		if reset[peer] {
			continue
		}
		for _, afi := range []uint16{1, 2} {
			if info.afis&(1<<afi) != 0 {
				proof.Peers = append(proof.Peers, MRTPeerBinding{PeerKey: peer, Session: sessions[peer], PeerIndex: info.index, PeerTable: info.table, AFI: afi, AddPath: info.modes&(1<<afi) != 0})
			}
		}
	}
	sort.Slice(proof.Peers, func(i, j int) bool {
		a, b := proof.Peers[i], proof.Peers[j]
		if n := bytes.Compare(a.PeerKey[:], b.PeerKey[:]); n != 0 {
			return n < 0
		}
		return a.AFI < b.AFI
	})
	if len(proof.Peers) == 0 {
		return cold("all_bootstrap_sessions_closed")
	}
	if _, err := proof.ContentHash(); err != nil {
		return cold("replay_content_set_proof_invalid")
	}
	result.Proof, result.Updates = proof, preflight
	return result, nil
}

func emitMRTReplayPath(sink func(NormalizedRecord) error, record NormalizedRecord) error {
	if record.Path == nil || !IsPublicASN(record.Path.Observation.Origin) || record.MRT == nil || record.MRTOriginatedAt == nil {
		return errors.New("MRT replay path invalid")
	}
	origin := NormalizedRecord{Version: 3, Kind: RecordOrigins, MRT: record.MRT, MRTOriginatedAt: record.MRTOriginatedAt, Origins: &OriginMapping{Prefix: record.Path.Prefix, Origins: []uint32{record.Path.Observation.Origin}}}
	if err := sink(origin); err != nil {
		return err
	}
	return sink(record)
}
