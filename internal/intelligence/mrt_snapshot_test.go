package intelligence

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func setMRTCapture(input []byte, clock time.Time) {
	for p := 0; p < len(input); {
		binary.BigEndian.PutUint32(input[p:], uint32(clock.Unix()))
		p += 12 + int(binary.BigEndian.Uint32(input[p+8:]))
	}
}

func TestMRTCaptureClockDoesNotExpireFreshRIBsOldOriginatedRoutes(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	input := mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100, 200}}})
	setMRTCapture(input, now)
	rib := 12 + int(binary.BigEndian.Uint32(input[8:]))
	old := now.Add(-1000 * time.Hour)
	binary.BigEndian.PutUint32(input[rib+12+12:], uint32(old.Unix()))
	var got []MRTSnapshotRecord
	clock, err := ParseMRTSnapshot(context.Background(), bytes.NewReader(input), mrtLimits(), now, 720*time.Hour, func(record MRTSnapshotRecord) error {
		got = append(got, record)
		return nil
	})
	if err != nil || len(got) != 1 || !got[0].CapturedAt.Equal(now) || !got[0].Record.ObservedAt.Equal(old) || clock.Frames != 2 || !clock.First.Equal(now) || !clock.Last.Equal(now) {
		t.Fatal("snapshot capture and route originated clocks were confused", got, clock, err)
	}
}

func TestMRTSnapshotProofRequiresEveryCompleteCurrentFrame(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	for _, scenario := range []string{"stale_first", "future_last", "truncated_tail", "hidden_tail", "one_byte_reads"} {
		t.Run(scenario, func(t *testing.T) {
			input := mrtFixture(false, false, []PathSegment{{ASSequence, []uint32{100, 200}}})
			setMRTCapture(input, now)
			rib := 12 + int(binary.BigEndian.Uint32(input[8:]))
			switch scenario {
			case "stale_first":
				binary.BigEndian.PutUint32(input, uint32(now.Add(-720*time.Hour).Unix()))
			case "future_last":
				binary.BigEndian.PutUint32(input[rib:], uint32(now.Add(25*time.Hour).Unix()))
			case "truncated_tail":
				input = input[:len(input)-1]
			case "hidden_tail":
				input = append(input, 0)
			}
			var reader io.Reader = bytes.NewReader(input)
			if scenario == "one_byte_reads" {
				reader = oneByteMRTReader{reader}
			}
			clock, err := ParseMRTSnapshot(context.Background(), reader, mrtLimits(), now, 720*time.Hour, func(MRTSnapshotRecord) error { return nil })
			if scenario == "one_byte_reads" {
				if err != nil || clock.Frames != 2 {
					t.Fatal("partial reads changed capture framing", clock, err)
				}
			} else if err == nil || clock != (MRTSnapshotClock{}) {
				t.Fatal("incomplete, stale or future capture produced a publication proof", clock, err)
			}
		})
	}
}

type oneByteMRTReader struct{ io.Reader }

func (r oneByteMRTReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestMRTExtendedCaptureMicrosecondsCannotCrossFutureBound(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	input := bgp4mpFrame(4, true, false, bgpMessage(4, nil))
	setMRTCapture(input, now.Add(24*time.Hour))
	clock, err := ParseMRTUpdatesSnapshot(context.Background(), bytes.NewReader(input), mrtLimits(), now, 720*time.Hour, func(MRTUpdate) error { return nil }, nil)
	if err == nil || clock != (MRTSnapshotClock{}) {
		t.Fatal("extended timestamp crossed the explicit future ceiling", clock, err)
	}
}
