package admission

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"vansail-ip-atlas/internal/acquire"
	"vansail-ip-atlas/internal/intelligence"
)

func mrtUpdatesSource(source Source) (Source, error) {
	if source.MRTUpdatesFixture == nil || len(source.ID) > 120 {
		return Source{}, errors.New("reviewed MRT UPDATE fixture required")
	}
	companion := source
	companion.ID = source.ID + "-updates"
	companion.Parser = Parser{"mrt-bgp4mp", "mrt-bgp4mp-unicast-v1", 1}
	companion.Fixture = *source.MRTUpdatesFixture
	companion.MRTUpdatesFixture = nil
	companion.MRTArchivePolicy = "" // the base alone selects complete RIB archives
	return companion, nil
}

func scanMRTUpdatesFile(ctx context.Context, file *os.File, size int64, source Source, now time.Time, maxEvents int, sink func(intelligence.MRTUpdate) error, observe func(intelligence.MRTPeerSession) error) (intelligence.MRTSnapshotClock, error) {
	if maxEvents <= 0 || maxEvents > 1_000_000 || sink == nil {
		return intelligence.MRTSnapshotClock{}, errors.New("bounded MRT UPDATE stream required")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return intelligence.MRTSnapshotClock{}, err
	}
	format := "plain"
	if source.Format == "mrt-gz" {
		format = "gzip"
	} else if source.Format == "mrt-bz2" {
		format = "bzip2"
	}
	var proof intelligence.MRTSnapshotClock
	limits := acquire.ArchiveLimits{CompressedBytes: source.MaxCompressedBytes, DecodedBytes: 3 << 30, EntryBytes: 3 << 30, Entries: 1, NameBytes: 4096}
	err := acquire.WalkArchive(ctx, acquire.ArchiveInput{Reader: file, ReaderAt: file, Size: size}, format, limits, func(_ string, input io.Reader) error {
		var err error
		proof, err = intelligence.ParseMRTUpdatesSnapshot(ctx, input, intelligence.MRTLimits{Bytes: 3 << 30, FrameBytes: 8 << 20, Records: maxEvents, Peers: 65535}, now, source.MaxAge, sink, observe)
		return err
	})
	if err != nil {
		return intelligence.MRTSnapshotClock{}, err
	}
	return proof, nil
}
