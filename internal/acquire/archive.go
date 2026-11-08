package acquire

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

// ErrArchive intentionally contains no downloaded name, URL or archive content.
var ErrArchive = errors.New("bulk archive rejected")

type ArchiveLimits struct {
	CompressedBytes int64
	DecodedBytes    int64
	EntryBytes      int64
	Entries         int
	NameBytes       int
}

func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{1 << 30, 3 << 30, 3 << 30, 10000, 4096}
}

// ArchiveInput refers to an already downloaded private asset. ZIP requires its
// bounded random-access file and size; this adapter never buffers a ZIP in RAM.
type ArchiveInput struct {
	Reader   io.Reader
	ReaderAt io.ReaderAt
	Size     int64
}

type archiveBudget struct {
	ctx       context.Context
	r         io.Reader
	remaining int64
}

type archiveRandomBudget struct {
	ctx       context.Context
	r         io.ReaderAt
	remaining int64
}

func (r *archiveRandomBudget) ReadAt(p []byte, offset int64) (int, error) {
	if r.ctx.Err() != nil || int64(len(p)) > r.remaining {
		return 0, ErrArchive
	}
	n, err := r.r.ReadAt(p, offset)
	r.remaining -= int64(n)
	if r.ctx.Err() != nil {
		return 0, ErrArchive
	}
	return n, err
}

func (r *archiveBudget) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil || r.remaining < 0 {
		return 0, ErrArchive
	}
	if int64(len(p)) > r.remaining+1 {
		p = p[:r.remaining+1]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	if r.remaining < 0 || r.ctx.Err() != nil {
		return 0, ErrArchive
	}
	return n, err
}

type archiveNames struct {
	seen       map[string]bool
	descendant map[string]bool
	limit      int
}

func (n *archiveNames) add(name string, directory bool) (string, error) {
	if !utf8.ValidString(name) || len(name) == 0 || len(name) > n.limit || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return "", ErrArchive
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || path.Clean(name) != name {
		return "", ErrArchive
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return "", ErrArchive
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.TrimRight(part, ". ") != part {
			return "", ErrArchive
		}
		for _, c := range part {
			if c < 32 || c == 127 {
				return "", ErrArchive
			}
		}
	}
	key := strings.ToLower(name)
	if _, exists := n.seen[key]; exists || (!directory && n.descendant[key]) {
		return "", ErrArchive
	}
	for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
		if isDir, exists := n.seen[parent]; exists && !isDir {
			return "", ErrArchive
		}
		n.descendant[parent] = true
	}
	n.seen[key] = directory
	return name, nil
}

func archiveConsume(ctx context.Context, r io.Reader, name string, size int64, limits ArchiveLimits, consume func(string, io.Reader) error) error {
	if ctx.Err() != nil || size > limits.EntryBytes {
		return ErrArchive
	}
	bounded := &archiveBudget{ctx: ctx, r: r, remaining: limits.EntryBytes}
	if err := consume(name, bounded); err != nil {
		return ErrArchive
	}
	// Always finish each entry: do not let a parser's early return skip a bomb,
	// trailer checksum or corrupt compressed stream.
	if _, err := io.Copy(io.Discard, bounded); err != nil || ctx.Err() != nil {
		return ErrArchive
	}
	return nil
}

// WalkArchive streams entry bytes to a typed source parser. It creates no files,
// follows no links and executes no bytes. XZ dictionaries and ZIP/ZIP64 entry
// counts are preflighted before the library can allocate them.
func WalkArchive(ctx context.Context, input ArchiveInput, format string, limits ArchiveLimits, consume func(string, io.Reader) error) error {
	if ctx.Err() != nil || consume == nil || limits.CompressedBytes <= 0 || limits.CompressedBytes > 1<<30 || limits.DecodedBytes <= 0 || limits.DecodedBytes > 3<<30 || limits.EntryBytes <= 0 || limits.EntryBytes > limits.DecodedBytes || limits.Entries <= 0 || limits.Entries > 10000 || limits.NameBytes <= 0 || limits.NameBytes > 4096 {
		return ErrArchive
	}
	names := &archiveNames{seen: map[string]bool{}, descendant: map[string]bool{}, limit: limits.NameBytes}
	if format == "zip" {
		return walkZIP(ctx, input, limits, names, consume)
	}
	if input.Reader == nil {
		return ErrArchive
	}
	compressed := &archiveBudget{ctx: ctx, r: input.Reader, remaining: limits.CompressedBytes}
	buffered := bufio.NewReaderSize(compressed, 4096)
	var decoded io.Reader = buffered
	var gz *gzip.Reader
	switch format {
	case "plain", "tar":
	case "gzip", "gz", "tar.gz", "tgz":
		var err error
		gz, err = gzip.NewReader(buffered)
		if err != nil {
			return ErrArchive
		}
		defer gz.Close()
		gz.Multistream(false)
		decoded = gz
	case "bzip2", "bz2", "tar.bz2":
		decoded = bzip2.NewReader(buffered)
	case "xz", "tar.xz":
		reader, err := newBoundedXZ(ctx, input, limits)
		if err != nil {
			return ErrArchive
		}
		decoded = reader
	default:
		return ErrArchive
	}
	budget := &archiveBudget{ctx: ctx, r: decoded, remaining: limits.DecodedBytes}
	if format == "tar" || format == "tar.gz" || format == "tgz" || format == "tar.bz2" || format == "tar.xz" {
		reader := tar.NewReader(budget)
		entries := 0
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			entries++
			if err != nil || entries > limits.Entries || ctx.Err() != nil || header.Size < 0 || header.Size > limits.EntryBytes || header.Linkname != "" {
				return ErrArchive
			}
			directory := header.Typeflag == tar.TypeDir
			if directory && header.Size != 0 || !directory && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				return ErrArchive
			}
			name, err := names.add(header.Name, directory)
			if err != nil {
				return ErrArchive
			}
			if !directory && archiveConsume(ctx, reader, name, header.Size, limits, consume) != nil {
				return ErrArchive
			}
		}
		// TAR allows zero padding after end-of-archive, never hidden content.
		var padding [4096]byte
		for {
			n, err := budget.Read(padding[:])
			for _, b := range padding[:n] {
				if b != 0 {
					return ErrArchive
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return ErrArchive
			}
		}
	} else if err := archiveConsume(ctx, budget, "payload", -1, limits, consume); err != nil {
		return ErrArchive
	}
	// For gzip, Multistream(false) plus a ByteReader preserves unconsumed bytes.
	// Concatenated/trailing streams are rejected rather than silently ignored.
	if format == "xz" || format == "tar.xz" {
		return nil
	}
	if _, err := buffered.ReadByte(); err != io.EOF || ctx.Err() != nil {
		return ErrArchive
	}
	return nil
}

func zipEntryCount(input ArchiveInput, limit int) error {
	if input.ReaderAt == nil || input.Size < 22 {
		return ErrArchive
	}
	size := min(input.Size, 22+65535)
	tail := make([]byte, int(size))
	if _, err := input.ReaderAt.ReadAt(tail, input.Size-size); err != nil {
		return ErrArchive
	}
	for offset := len(tail) - 22; offset >= 0; offset-- {
		if binary.LittleEndian.Uint32(tail[offset:]) != 0x06054b50 {
			continue
		}
		// Use the same last signature as archive/zip. Never skip a malformed
		// later end record and validate different metadata than the library.
		if offset+22+int(binary.LittleEndian.Uint16(tail[offset+20:])) != len(tail) {
			return ErrArchive
		}
		count := binary.LittleEndian.Uint16(tail[offset+10:])
		dirSize := binary.LittleEndian.Uint32(tail[offset+12:])
		dirOffset := binary.LittleEndian.Uint32(tail[offset+16:])
		if binary.LittleEndian.Uint16(tail[offset+4:]) != 0 || binary.LittleEndian.Uint16(tail[offset+6:]) != 0 || binary.LittleEndian.Uint16(tail[offset+8:]) != count {
			return ErrArchive
		}
		end := input.Size - size + int64(offset)
		if count == 0xffff || dirSize == 0xffffffff || dirOffset == 0xffffffff {
			return zip64EntryCount(input, end, limit, count, dirSize, dirOffset)
		}
		if int(count) > limit || uint64(dirOffset)+uint64(dirSize) != uint64(end) {
			return ErrArchive
		}
		return zipDirectoryCount(input, uint64(dirOffset), uint64(dirSize), uint64(count), limit)
	}
	return ErrArchive
}

// Validate ZIP64 framing/counts before archive/zip builds its file slice. No
// multi-disk, prefixed/self-extracting or unbounded extensible-sector archives.
func zip64EntryCount(input ArchiveInput, end int64, limit int, oldCount uint16, oldSize, oldOffset uint32) error {
	if end < 20 {
		return ErrArchive
	}
	var locator [20]byte
	if _, err := input.ReaderAt.ReadAt(locator[:], end-20); err != nil || binary.LittleEndian.Uint32(locator[:]) != 0x07064b50 || binary.LittleEndian.Uint32(locator[4:]) != 0 || binary.LittleEndian.Uint32(locator[16:]) != 1 {
		return ErrArchive
	}
	offset := binary.LittleEndian.Uint64(locator[8:])
	if offset > uint64(end-20) || uint64(end-20)-offset < 56 {
		return ErrArchive
	}
	var record [56]byte
	if _, err := input.ReaderAt.ReadAt(record[:], int64(offset)); err != nil || binary.LittleEndian.Uint32(record[:]) != 0x06064b50 {
		return ErrArchive
	}
	length := binary.LittleEndian.Uint64(record[4:])
	if length < 44 || length > 1<<20 || length+12 != uint64(end-20)-offset || binary.LittleEndian.Uint32(record[16:]) != 0 || binary.LittleEndian.Uint32(record[20:]) != 0 {
		return ErrArchive
	}
	count := binary.LittleEndian.Uint64(record[32:])
	size := binary.LittleEndian.Uint64(record[40:])
	start := binary.LittleEndian.Uint64(record[48:])
	if count > uint64(limit) || binary.LittleEndian.Uint64(record[24:]) != count || start > offset || size != offset-start || oldCount != 0xffff && uint64(oldCount) != count || oldSize != 0xffffffff && uint64(oldSize) != size || oldOffset != 0xffffffff && uint64(oldOffset) != start {
		return ErrArchive
	}
	return zipDirectoryCount(input, start, size, count, limit)
}

// archive/zip reads actual central-directory records before comparing the end
// record's (modulo-65536) claimed count. Scan actual bounded entries first, so a
// forged count cannot trigger an enormous File slice allocation in zip.NewReader.
func zipDirectoryCount(input ArchiveInput, start, size, count uint64, limit int) error {
	if start > uint64(input.Size) || size > uint64(input.Size)-start {
		return ErrArchive
	}
	end := start + size
	actual := uint64(0)
	var header [46]byte
	for start < end {
		if actual >= uint64(limit) || end-start < 46 {
			return ErrArchive
		}
		if _, err := input.ReaderAt.ReadAt(header[:], int64(start)); err != nil || binary.LittleEndian.Uint32(header[:]) != 0x02014b50 {
			return ErrArchive
		}
		bytes := uint64(46) + uint64(binary.LittleEndian.Uint16(header[28:])) + uint64(binary.LittleEndian.Uint16(header[30:])) + uint64(binary.LittleEndian.Uint16(header[32:]))
		if bytes > end-start {
			return ErrArchive
		}
		start += bytes
		actual++
	}
	if actual != count {
		return ErrArchive
	}
	return nil
}

func walkZIP(ctx context.Context, input ArchiveInput, limits ArchiveLimits, names *archiveNames, consume func(string, io.Reader) error) error {
	if input.ReaderAt == nil || input.Size > limits.CompressedBytes {
		return ErrArchive
	}
	// Bound repeated random reads too: overlapping ZIP entries must not turn a
	// small on-disk asset into unbounded compressed-byte work with zero output.
	input.ReaderAt = &archiveRandomBudget{ctx: ctx, r: input.ReaderAt, remaining: 2*limits.CompressedBytes + 65557}
	if zipEntryCount(input, limits.Entries) != nil {
		return ErrArchive
	}
	reader, err := zip.NewReader(input.ReaderAt, input.Size)
	if err != nil || len(reader.File) > limits.Entries {
		return ErrArchive
	}
	remaining := limits.DecodedBytes
	for _, file := range reader.File {
		if ctx.Err() != nil || file.UncompressedSize64 > uint64(limits.EntryBytes) || file.UncompressedSize64 > uint64(remaining) || file.CompressedSize64 > uint64(limits.CompressedBytes) || (!file.Mode().IsRegular() && !file.FileInfo().IsDir()) {
			return ErrArchive
		}
		directory := file.FileInfo().IsDir()
		name, err := names.add(file.Name, directory)
		if err != nil || file.Flags&1 != 0 {
			return ErrArchive
		}
		if directory {
			if file.UncompressedSize64 != 0 || file.CompressedSize64 != 0 {
				return ErrArchive
			}
			continue
		}
		entry, err := file.Open()
		if err != nil {
			return ErrArchive
		}
		budget := &archiveBudget{ctx: ctx, r: entry, remaining: remaining}
		err = archiveConsume(ctx, budget, name, int64(file.UncompressedSize64), limits, consume)
		remaining = budget.remaining
		closeErr := entry.Close()
		if err != nil || closeErr != nil {
			return ErrArchive
		}
	}
	return nil
}
