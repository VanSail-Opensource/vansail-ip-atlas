package intelligence

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// MRTSnapshotRecord retains the RIB entry's originated time privately while
// distinguishing the frame capture clock used for current snapshot evidence.
// An old, still-present route does not become stale merely because it was first
// heard more than 720 hours before a freshly captured complete RIB.
type MRTSnapshotRecord struct {
	Record     MRTRecord
	CapturedAt time.Time
}

type MRTSnapshotClock struct {
	First, Last time.Time
	Frames      uint64
}

type mrtCaptureReader struct {
	ctx      context.Context
	input    io.Reader
	now      time.Time
	maxAge   time.Duration
	maxFrame uint32
	ribOnly  bool
	header   [12]byte
	headerAt int
	body     uint32
	current  time.Time
	clock    MRTSnapshotClock
	failure  error
}

func (r *mrtCaptureReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.body > 0 {
		if uint64(len(p)) > uint64(r.body) {
			p = p[:r.body]
		}
		n, err := r.input.Read(p)
		r.body -= uint32(n)
		return n, err
	}
	if len(p) > len(r.header)-r.headerAt {
		p = p[:len(r.header)-r.headerAt]
	}
	n, err := r.input.Read(p)
	copy(r.header[r.headerAt:], p[:n])
	r.headerAt += n
	if r.headerAt != len(r.header) {
		return n, err
	}
	r.headerAt = 0
	r.body = binary.BigEndian.Uint32(r.header[8:])
	r.current = time.Unix(int64(binary.BigEndian.Uint32(r.header[:4])), 0).UTC()
	kind := binary.BigEndian.Uint16(r.header[4:])
	if (r.ribOnly && kind != 13 || !r.ribOnly && kind != 16 && kind != 17) || r.body > r.maxFrame || r.current.After(r.now.Add(24*time.Hour)) || !r.now.Before(r.current.Add(r.maxAge)) {
		r.failure = errors.New("MRT frame capture proof invalid or expired")
		// io.ReadFull ignores an error returned alongside a complete header.
		// Return zero so the parser cannot allocate its body before rejection.
		return 0, r.failure
	}
	if r.clock.Frames == 0 || r.current.Before(r.clock.First) {
		r.clock.First = r.current
	}
	if r.clock.Frames == 0 || r.current.After(r.clock.Last) {
		r.clock.Last = r.current
	}
	r.clock.Frames++
	return n, err
}

// ParseMRTSnapshot validates every frame and capture clock in the exact stream.
// A sink must remain transactional until success: neither a prefix fragment nor
// an HTTP timestamp can prove the complete snapshot. Callers separately bind
// this proof to the downloaded payload's collision-resistant SHA-256 and size.
func ParseMRTSnapshot(ctx context.Context, input io.Reader, limits MRTLimits, now time.Time, maxAge time.Duration, sink func(MRTSnapshotRecord) error) (MRTSnapshotClock, error) {
	if now.IsZero() || maxAge <= 0 || maxAge > 720*time.Hour || sink == nil {
		return MRTSnapshotClock{}, errors.New("explicit bounded MRT snapshot clock required")
	}
	reader := &mrtCaptureReader{ctx: ctx, input: input, now: now, maxAge: maxAge, maxFrame: limits.FrameBytes, ribOnly: true}
	err := ParseMRT(ctx, reader, limits, func(record MRTRecord) error {
		return sink(MRTSnapshotRecord{Record: record, CapturedAt: reader.current})
	})
	if err != nil {
		return MRTSnapshotClock{}, err
	}
	if reader.failure != nil || reader.headerAt != 0 || reader.body != 0 || reader.clock.Frames == 0 {
		return MRTSnapshotClock{}, errors.New("MRT snapshot framing proof incomplete")
	}
	return reader.clock, nil
}

// ParseMRTUpdatesSnapshot proves the complete UPDATE framing/capture interval
// while exposing private peer/session observations for verified RIB joins.
func ParseMRTUpdatesSnapshot(ctx context.Context, input io.Reader, limits MRTLimits, now time.Time, maxAge time.Duration, sink func(MRTUpdate) error, observe func(MRTPeerSession) error) (MRTSnapshotClock, error) {
	if now.IsZero() || maxAge <= 0 || maxAge > 720*time.Hour || sink == nil {
		return MRTSnapshotClock{}, errors.New("explicit bounded MRT update clock required")
	}
	reader := &mrtCaptureReader{ctx: ctx, input: input, now: now, maxAge: maxAge, maxFrame: limits.FrameBytes}
	err := ParseBGP4MPWithPeers(ctx, reader, limits, sink, func(peer MRTPeerSession) error {
		if peer.ObservedAt.After(now.Add(24 * time.Hour)) {
			return errors.New("MRT extended frame capture exceeds future-clock bound")
		}
		if peer.ObservedAt.After(reader.clock.Last) {
			reader.clock.Last = peer.ObservedAt
		}
		if observe != nil {
			return observe(peer)
		}
		return nil
	})
	if err != nil {
		return MRTSnapshotClock{}, err
	}
	if reader.failure != nil || reader.headerAt != 0 || reader.body != 0 || reader.clock.Frames == 0 {
		return MRTSnapshotClock{}, errors.New("MRT update framing proof incomplete")
	}
	return reader.clock, nil
}
