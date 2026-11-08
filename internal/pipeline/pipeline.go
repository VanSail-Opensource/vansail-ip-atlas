// Package pipeline implements a bounded, disk-backed compiler for already fused
// public facts, with bounded normalized-state engineering materializers. It
// never admits a source or treats downloaded raw source bytes as public facts.
package pipeline

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"vansail-ip-atlas/internal/facts"
	"vansail-ip-atlas/internal/via3"
)

// Limits are ceilings, not reservations. The default sort buffer matches the
// reviewed 96-MiB normalization contract. Smaller limits are useful in fixtures.
type Limits struct {
	SortBytes, PartitionBytes, RecordBytes   int64
	ScratchBytes, RSSBytes, MinimumFreeBytes uint64
	ObjectBytes                              uint64
	PartitionRecords, MaxObjects, MergeFanIn int
}

func DefaultLimits() Limits {
	return Limits{96 << 20, 16 << 20, 8 << 20, 10240 << 20, 6656 << 20, 1024 << 20, via3.MaxFile - 1, 32768, 18499, 16}
}

func (l Limits) validate() error {
	d := DefaultLimits()
	if l.RecordBytes < 1024 || l.RecordBytes > d.RecordBytes || l.SortBytes < l.RecordBytes || l.SortBytes > d.SortBytes ||
		l.PartitionBytes < l.RecordBytes || l.PartitionBytes > d.PartitionBytes || l.ScratchBytes == 0 || l.ScratchBytes > d.ScratchBytes ||
		l.RSSBytes == 0 || l.RSSBytes > d.RSSBytes || l.MinimumFreeBytes < d.MinimumFreeBytes ||
		l.ObjectBytes < 1024 || l.ObjectBytes > d.ObjectBytes ||
		l.PartitionRecords < 1 || l.PartitionRecords > d.PartitionRecords || l.MaxObjects < 2 || l.MaxObjects > d.MaxObjects || l.MergeFanIn < 2 || l.MergeFanIn > 16 {
		return errors.New("pipeline limits must remain within reviewed ceilings")
	}
	return nil
}

type Options struct {
	Workspace, Output, Mode string
	Clock, ValidUntil       int64
	Limits                  Limits
	ProductionGate          func(context.Context) error
	// InputGate binds source/config/state inputs throughout a build in either
	// mode. It is independent of the mandatory production capability gate.
	InputGate func(context.Context) error
}

// Stats account this compiler's files and process, not unrelated processes or
// the complete physical runner. Hosted process-group accounting remains needed.
type Stats struct {
	InputRecords, UniqueRecords, SortRuns, Partitions                int64
	BinaryByteRepacks                                                int64
	SortBufferPeak, PartitionBufferPeak, ScratchPeak, ProcessRSSPeak uint64
	ProcessRSSMeasured                                               bool
	OutputBytes                                                      uint64
}

type Candidate struct {
	Descriptor via3.Descriptor
	Manifest   via3.Manifest
	Pointer    via3.Pointer
	Stats      Stats
}

type Producer func(context.Context, func(via3.PublicRecord) error) error

type compiler struct {
	ctx                   context.Context
	options               Options
	root, scratch, output string
	stats                 Stats
	used                  uint64
	serial                int
	objects               map[string]via3.ObjectInfo
	routes                []route
	routerBytes           uint64
}

type route struct {
	prefix       netip.Prefix
	asns         []uint32
	destinations []via3.ObjectInfo
}

func canonical(value any) ([]byte, error) { return json.Marshal(value) }

// Build streams public facts through bounded sort runs, deduplicates equal rows,
// rejects conflicting identities, repacks using actual binary sizes, and writes
// objects as each partition completes. Only router metadata is retained globally.
// Output must be a new directory beneath Workspace/build-private; no current
// release is replaced on a failed build. Production admission is checked twice.
func Build(ctx context.Context, options Options, produce Producer) (Candidate, error) {
	var result Candidate
	if options.Limits == (Limits{}) {
		options.Limits = DefaultLimits()
	}
	if err := options.Limits.validate(); err != nil {
		return result, err
	}
	if produce == nil || options.Mode != "synthetic" && options.Mode != "production" || options.Clock < 0 || options.ValidUntil <= options.Clock || options.ValidUntil-options.Clock > 720*3600 || options.ValidUntil > 9007199254740991 {
		return result, errors.New("invalid pipeline contract")
	}
	gate := func(gateCtx context.Context) error {
		if options.InputGate != nil {
			if err := options.InputGate(gateCtx); err != nil {
				return err
			}
		}
		if options.Mode != "production" {
			return nil
		}
		if options.ProductionGate == nil {
			return &via3.Error{Code: "production_blocked"}
		}
		return options.ProductionGate(gateCtx)
	}
	if err := gate(ctx); err != nil {
		return result, err
	}
	root, err := filepath.Abs(options.Workspace)
	if err != nil {
		return result, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return result, err
	}
	private := filepath.Join(root, ".atlas-private")
	if err := os.MkdirAll(private, 0700); err != nil {
		return result, err
	}
	resolved, err := filepath.EvalSymlinks(private)
	if err != nil || resolved != private {
		return result, errors.New("private scratch path escaped workspace")
	}
	output, err := filepath.Abs(options.Output)
	if err != nil {
		return result, err
	}
	allowed := filepath.Join(root, "build-private")
	rel, err := filepath.Rel(allowed, output)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return result, errors.New("output must be beneath workspace/build-private")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return result, errors.New("pipeline output already exists or cannot be checked")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return result, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil || parent != filepath.Dir(output) {
		return result, errors.New("output parent contains a symlink")
	}
	scratch, err := os.MkdirTemp(private, "pipeline-")
	if err != nil {
		return result, err
	}
	// This exact MkdirTemp-owned directory is the only recursive cleanup target.
	defer os.RemoveAll(scratch)
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	c := &compiler{ctx: workCtx, options: options, root: root, scratch: scratch, output: filepath.Join(scratch, "candidate"), objects: map[string]via3.ObjectInfo{}}
	if err := os.MkdirAll(filepath.Join(c.output, "objects"), 0700); err != nil {
		return result, err
	}
	var rssPeak atomic.Uint64
	var measured atomic.Bool
	checkResources := func() error {
		rss, free, ok, err := processResources(scratch)
		if err != nil {
			return err
		}
		if ok {
			measured.Store(true)
			for old := rssPeak.Load(); rss > old && !rssPeak.CompareAndSwap(old, rss); old = rssPeak.Load() {
			}
			if rss >= options.Limits.RSSBytes {
				return errors.New("pipeline process RSS ceiling exceeded")
			}
		}
		if free < options.Limits.MinimumFreeBytes {
			return errors.New("pipeline physical free-space floor crossed")
		}
		return nil
	}
	if err := checkResources(); err != nil {
		return result, err
	}
	monitorDone := make(chan struct{})
	defer func() { cancel(nil); <-monitorDone }()
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				if err := checkResources(); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	runs, err := c.sort(produce)
	if err != nil {
		return result, c.cause(err)
	}
	merged, err := c.merge(runs)
	if err != nil {
		return result, c.cause(err)
	}
	groups, err := c.classify(merged)
	if err != nil {
		return result, c.cause(err)
	}
	for i, path := range groups {
		if path == "" {
			continue
		}
		var scope scope
		if i == 0 {
			scope.prefix = netip.MustParsePrefix("0.0.0.0/0")
		} else if i == 1 {
			scope.prefix = netip.MustParsePrefix("::/0")
		} else {
			scope.asn = true
			scope.last = ^uint32(0)
		}
		if err := c.partition(path, scope); err != nil {
			return result, c.cause(err)
		}
	}
	if len(c.routes) == 0 {
		return result, errors.New("pipeline requires at least one public fact")
	}
	if err := c.router(); err != nil {
		return result, c.cause(err)
	}
	infos := make([]via3.ObjectInfo, 0, len(c.objects))
	for _, info := range c.objects {
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].SHA256 < infos[j].SHA256 })
	result.Descriptor = via3.Descriptor{Codec: "zstd-1", FormatVersion: 3, Mode: options.Mode, Objects: infos, SchemaVersion: 3, ValidFrom: options.Clock, ValidUntil: options.ValidUntil}
	descriptor, err := canonical(result.Descriptor)
	if err != nil {
		return result, err
	}
	id := via3.Hash(descriptor)
	result.Manifest = via3.Manifest{Codec: "zstd-1", FormatVersion: 3, Mode: options.Mode, Objects: infos, ReleaseID: id, SchemaVersion: 3, ValidFrom: options.Clock, ValidUntil: options.ValidUntil}
	manifest, err := canonical(result.Manifest)
	if err != nil {
		return result, err
	}
	result.Pointer = via3.Pointer{FormatVersion: 3, ManifestPath: "/_atlas/releases/" + id + "/manifest.json", ManifestSHA256: via3.Hash(manifest), ReleaseID: id}
	pointer, err := canonical(result.Pointer)
	if err != nil {
		return result, err
	}
	if err := c.write(filepath.Join(c.output, "releases", id, "manifest.json"), manifest); err != nil {
		return result, err
	}
	if err := c.write(filepath.Join(c.output, "current.json"), pointer); err != nil {
		return result, err
	}
	if err := gate(workCtx); err != nil {
		return result, err
	}
	if err := checkResources(); err != nil {
		return result, err
	}
	if err := workCtx.Err(); err != nil {
		return result, c.cause(err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return result, errors.New("pipeline output appeared before publication")
	}
	if err := os.Rename(c.output, output); err != nil {
		return result, err
	}
	c.stats.ProcessRSSMeasured = measured.Load()
	c.stats.ProcessRSSPeak = rssPeak.Load()
	result.Stats = c.stats
	return result, nil
}

func (c *compiler) cause(err error) error {
	if cause := context.Cause(c.ctx); cause != nil {
		return cause
	}
	return err
}
func (c *compiler) next() string {
	c.serial++
	return filepath.Join(c.scratch, fmt.Sprintf("run-%08d.bin", c.serial))
}
func (c *compiler) reserve(n uint64) error {
	if n > c.options.Limits.ScratchBytes-c.used {
		return errors.New("pipeline scratch ceiling exceeded")
	}
	c.used += n
	if c.used > c.stats.ScratchPeak {
		c.stats.ScratchPeak = c.used
	}
	return nil
}
func (c *compiler) remove(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	c.used -= uint64(info.Size())
	return nil
}
func (c *compiler) write(path string, data []byte) error {
	if err := c.reserve(uint64(len(data))); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

type encoded struct {
	key  string
	data []byte
}

func normalize(record via3.PublicRecord) (via3.PublicRecord, error) {
	if record.Version != 3 || record.Kind < 2 || record.Kind > 13 || record.Inherited {
		return record, errors.New("unfused or invalid public record")
	}
	if record.Kind == 8 || record.Kind >= 11 {
		if !facts.PublicASN(record.ASN) || record.Prefix.IsValid() || record.Exact {
			return record, errors.New("invalid public ASN record")
		}
	} else {
		if !record.Prefix.IsValid() || record.Prefix.Addr().Zone() != "" {
			return record, errors.New("invalid public prefix record")
		}
		if record.Prefix.Addr().Is4In6() {
			if record.Prefix.Bits() < 96 {
				return record, errors.New("mapped prefix crosses address families")
			}
			record.Prefix = netip.PrefixFrom(record.Prefix.Addr().Unmap(), record.Prefix.Bits()-96)
		}
		record.Prefix = record.Prefix.Masked()
		if record.Exact && record.Prefix.Bits() != record.Prefix.Addr().BitLen() {
			return record, errors.New("exact fact requires full address length")
		}
	}
	return normalizePayload(record)
}

func identity(r via3.PublicRecord) string {
	var key [32]byte
	key[0] = byte(r.Kind)
	if r.Kind == 8 || r.Kind >= 11 {
		binary.BigEndian.PutUint32(key[1:5], r.ASN)
		if r.Kind == 12 && r.Relationship != nil {
			binary.BigEndian.PutUint32(key[5:9], r.Relationship.To)
		} else {
			binary.BigEndian.PutUint16(key[5:7], r.Rank)
		}
	} else {
		key[1] = byte(r.Prefix.Addr().BitLen())
		a := r.Prefix.Addr().As16()
		copy(key[2:18], a[:])
		key[18] = byte(r.Prefix.Bits())
		if r.Exact {
			key[19] = 1
		}
		if r.Kind == 9 {
			binary.BigEndian.PutUint32(key[20:24], r.ASN)
		}
	}
	return string(key[:])
}

func decode(data []byte) (via3.PublicRecord, error) {
	var r via3.PublicRecord
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, errors.New("invalid private sort record")
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return r, errors.New("trailing private sort record")
	}
	return r, nil
}

func (c *compiler) sort(produce Producer) ([]string, error) {
	var batch []encoded
	var size int64
	var runs []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		sort.Slice(batch, func(i, j int) bool {
			if batch[i].key != batch[j].key {
				return batch[i].key < batch[j].key
			}
			return bytes.Compare(batch[i].data, batch[j].data) < 0
		})
		path := c.next()
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		writer := bufio.NewWriterSize(file, 64<<10)
		for _, row := range batch {
			if err := c.writeRecord(writer, row.data); err != nil {
				return err
			}
		}
		if err := writer.Flush(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		runs = append(runs, path)
		if len(runs) > 8192 {
			return errors.New("bounded sort-run directory exceeded")
		}
		c.stats.SortRuns++
		batch = nil
		size = 0
		return nil
	}
	err := produce(c.ctx, func(input via3.PublicRecord) error {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		r, err := normalize(input)
		if err != nil {
			return err
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if int64(len(data)) > c.options.Limits.RecordBytes {
			return errors.New("single fact exceeds bounded record size")
		}
		cost := int64(len(data) + 128)
		if cost > c.options.Limits.SortBytes {
			return errors.New("single fact exceeds sort buffer")
		}
		if size+cost > c.options.Limits.SortBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, encoded{identity(r), data})
		size += cost
		c.stats.InputRecords++
		if uint64(size) > c.stats.SortBufferPeak {
			c.stats.SortBufferPeak = uint64(size)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return runs, nil
}

func (c *compiler) writeRecord(w io.Writer, data []byte) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := c.reserve(uint64(4 + len(data))); err != nil {
		return err
	}
	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(data)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

type runReader struct {
	file   *os.File
	reader *bufio.Reader
	limit  int64
	row    encoded
}

func openRun(path string, limit int64) (*runReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &runReader{file: f, reader: bufio.NewReaderSize(f, 64<<10), limit: limit}, nil
}
func (r *runReader) next() error {
	var head [4]byte
	if _, err := io.ReadFull(r.reader, head[:]); err != nil {
		return err
	}
	n := int64(binary.LittleEndian.Uint32(head[:]))
	if n <= 0 || n > r.limit {
		return errors.New("private sort frame exceeds limit")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r.reader, data); err != nil {
		return err
	}
	record, err := decode(data)
	if err != nil {
		return err
	}
	r.row = encoded{identity(record), data}
	return nil
}

type mergeHeap []*runReader

func (h mergeHeap) Len() int { return len(h) }
func (h mergeHeap) Less(i, j int) bool {
	if h[i].row.key != h[j].row.key {
		return h[i].row.key < h[j].row.key
	}
	return bytes.Compare(h[i].row.data, h[j].row.data) < 0
}
func (h mergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(x any)   { *h = append(*h, x.(*runReader)) }
func (h *mergeHeap) Pop() any     { old := *h; x := old[len(old)-1]; *h = old[:len(old)-1]; return x }

func (c *compiler) mergeGroup(paths []string) (string, error) {
	path := c.next()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 64<<10)
	var h mergeHeap
	for _, path := range paths {
		r, err := openRun(path, c.options.Limits.RecordBytes)
		if err != nil {
			return "", err
		}
		defer r.file.Close()
		if err := r.next(); err == nil {
			heap.Push(&h, r)
		} else if err != io.EOF {
			return "", err
		}
	}
	var previous encoded
	for h.Len() > 0 {
		r := heap.Pop(&h).(*runReader)
		if previous.key == r.row.key {
			if !bytes.Equal(previous.data, r.row.data) {
				return "", errors.New("conflicting fused fact identity")
			}
		} else {
			if err := c.writeRecord(w, r.row.data); err != nil {
				return "", err
			}
			previous = r.row
		}
		if err := r.next(); err == nil {
			heap.Push(&h, r)
		} else if err != io.EOF {
			return "", err
		}
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	// Windows requires readers to close before their temporary runs are removed.
	for _, r := range h {
		r.file.Close()
	}
	return path, nil
}
func (c *compiler) merge(runs []string) (string, error) {
	if len(runs) == 0 {
		return "", errors.New("no public facts")
	}
	// Even a single initial run passes through the merge to deduplicate/reject.
	for {
		var next []string
		for first := 0; first < len(runs); first += c.options.Limits.MergeFanIn {
			end := min(first+c.options.Limits.MergeFanIn, len(runs))
			path, err := c.mergeGroup(runs[first:end])
			if err != nil {
				return "", err
			}
			for _, old := range runs[first:end] {
				if err := c.remove(old); err != nil {
					return "", err
				}
			}
			next = append(next, path)
		}
		if len(next) == 1 {
			return next[0], nil
		}
		runs = next
	}
}

func (c *compiler) classify(path string) ([3]string, error) {
	var paths [3]string
	var files [3]*os.File
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
			}
		}
	}()
	r, err := openRun(path, c.options.Limits.RecordBytes)
	if err != nil {
		return paths, err
	}
	defer r.file.Close()
	for {
		if err := r.next(); err == io.EOF {
			break
		} else if err != nil {
			return paths, err
		}
		record, err := decode(r.row.data)
		if err != nil {
			return paths, err
		}
		i := 0
		if record.Kind == 8 || record.Kind >= 11 {
			i = 2
		} else if record.Prefix.Addr().Is6() {
			i = 1
		}
		if files[i] == nil {
			paths[i] = c.next()
			files[i], err = os.OpenFile(paths[i], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return paths, err
			}
		}
		if err := c.writeRecord(files[i], r.row.data); err != nil {
			return paths, err
		}
		c.stats.UniqueRecords++
	}
	for _, f := range files {
		if f != nil {
			if err := f.Close(); err != nil {
				return paths, err
			}
		}
	}
	r.file.Close()
	if err := c.remove(path); err != nil {
		return paths, err
	}
	return paths, nil
}

type scope struct {
	prefix      netip.Prefix
	asn         bool
	first, last uint32
}

func (s scope) name() string {
	if s.asn {
		return "asn:" + strconv.FormatUint(uint64(s.first), 10) + ":" + strconv.FormatUint(uint64(s.last), 10)
	}
	a := s.prefix.Addr().As16()
	if s.prefix.Addr().Is4() {
		for i := 0; i < 12; i++ {
			a[i] = 0
		}
	}
	family := "6:"
	if s.prefix.Addr().Is4() {
		family = "4:"
	}
	return family + hex.EncodeToString(a[:]) + "/" + strconv.Itoa(s.prefix.Bits())
}
func (s scope) children() (scope, scope, error) {
	if s.asn {
		if s.first == s.last {
			return scope{}, scope{}, errors.New("single ASN cannot be repacked without truncation")
		}
		mid := s.first + (s.last-s.first)/2
		return scope{asn: true, first: s.first, last: mid}, scope{asn: true, first: mid + 1, last: s.last}, nil
	}
	// A /24 is indivisible because its sparse profile owns all 256 cells.
	ceiling := s.prefix.Addr().BitLen()
	if s.prefix.Addr().Is4() {
		ceiling = 24
	}
	if s.prefix.Bits() >= ceiling {
		return scope{}, scope{}, errors.New("single IP/profile scope cannot be repacked without truncation")
	}
	n := s.prefix.Bits() + 1
	left := netip.PrefixFrom(s.prefix.Addr(), n)
	var right netip.Addr
	if s.prefix.Addr().Is4() {
		a := s.prefix.Addr().As4()
		a[(n-1)/8] |= 1 << uint(7-(n-1)%8)
		right = netip.AddrFrom4(a)
	} else {
		a := s.prefix.Addr().As16()
		a[(n-1)/8] |= 1 << uint(7-(n-1)%8)
		right = netip.AddrFrom16(a)
	}
	return scope{prefix: left}, scope{prefix: netip.PrefixFrom(right, n)}, nil
}

func (c *compiler) partition(path string, s scope) error {
	r, err := openRun(path, c.options.Limits.RecordBytes)
	if err != nil {
		return err
	}
	var records []via3.PublicRecord
	var size int64
	overflow := false
	for {
		if err := r.next(); err == io.EOF {
			break
		} else if err != nil {
			r.file.Close()
			return err
		}
		cost := int64(len(r.row.data) + 512)
		if len(records) >= c.options.Limits.PartitionRecords || size+cost > c.options.Limits.PartitionBytes {
			overflow = true
			break
		}
		record, err := decode(r.row.data)
		if err != nil {
			r.file.Close()
			return err
		}
		records = append(records, record)
		size += cost
		if uint64(size) > c.stats.PartitionBufferPeak {
			c.stats.PartitionBufferPeak = uint64(size)
		}
	}
	r.file.Close()
	var compiled via3.CompiledPartition
	if !overflow {
		compiled, err = via3.CompilePartition(c.ctx, via3.PartitionInput{Partition: s.name(), Records: records})
		if err != nil {
			code := via3.ErrorCode(err)
			if code == "partition_budget" || code == "resource_limit" || code == "length" {
				overflow = true
			} else {
				return err
			}
		}
		if err == nil {
			for _, object := range compiled.Objects {
				if uint64(len(object.Bytes)) > c.options.Limits.ObjectBytes {
					overflow = true
					c.stats.BinaryByteRepacks++
					break
				}
			}
		}
	}
	if overflow {
		records = nil
		compiled = via3.CompiledPartition{}
		left, right, err := s.children()
		if err != nil {
			return err
		}
		children, err := c.split(path, left, right)
		if err != nil {
			return err
		}
		if children[0] != "" {
			if err := c.partition(children[0], left); err != nil {
				return err
			}
		}
		if children[1] != "" {
			if err := c.partition(children[1], right); err != nil {
				return err
			}
		}
		return nil
	}
	for _, object := range compiled.Objects {
		if err := c.object(object); err != nil {
			return err
		}
	}
	route := route{destinations: make([]via3.ObjectInfo, 0, len(compiled.Destinations))}
	for _, dest := range compiled.Destinations {
		route.destinations = append(route.destinations, dest.Info)
	}
	sort.Slice(route.destinations, func(i, j int) bool { return route.destinations[i].Kind < route.destinations[j].Kind })
	if s.asn {
		for _, record := range records {
			if len(route.asns) == 0 || route.asns[len(route.asns)-1] != record.ASN {
				route.asns = append(route.asns, record.ASN)
			}
		}
		sort.Slice(route.asns, func(i, j int) bool { return route.asns[i] < route.asns[j] })
		route.asns = compact(route.asns)
	} else {
		route.prefix = s.prefix
	}
	charge := uint64(16 + 4*len(route.destinations))
	if route.prefix.IsValid() {
		charge += 32
	} else {
		charge += 8 * uint64(len(route.asns))
	}
	if charge > via3.PublicObjectDecoded-c.routerBytes || uint64(len(c.objects))*40+charge+c.routerBytes > via3.PublicObjectDecoded {
		return &via3.Error{Code: "resource_limit"}
	}
	c.routerBytes += charge
	c.routes = append(c.routes, route)
	c.stats.Partitions++
	return c.remove(path)
}
func compact(values []uint32) []uint32 {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, v := range values[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func (c *compiler) split(path string, left, right scope) ([2]string, error) {
	var paths [2]string
	var files [2]*os.File
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
			}
		}
	}()
	r, err := openRun(path, c.options.Limits.RecordBytes)
	if err != nil {
		return paths, err
	}
	defer r.file.Close()
	for {
		if err := r.next(); err == io.EOF {
			break
		} else if err != nil {
			return paths, err
		}
		record, err := decode(r.row.data)
		if err != nil {
			return paths, err
		}
		for i, child := range []scope{left, right} {
			copy := record
			if child.asn {
				if record.ASN < child.first || record.ASN > child.last {
					continue
				}
			} else if record.Prefix.Bits() < child.prefix.Bits() && record.Prefix.Contains(child.prefix.Addr()) {
				if record.Kind == 7 || record.Exact {
					return paths, errors.New("profile or exact row cannot become an inherited overlay")
				}
				copy.Inherited = true
			} else if !child.prefix.Contains(record.Prefix.Addr()) {
				continue
			}
			data, err := json.Marshal(copy)
			if err != nil {
				return paths, err
			}
			if files[i] == nil {
				paths[i] = c.next()
				files[i], err = os.OpenFile(paths[i], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return paths, err
				}
			}
			if err := c.writeRecord(files[i], data); err != nil {
				return paths, err
			}
		}
	}
	for _, f := range files {
		if f != nil {
			if err := f.Close(); err != nil {
				return paths, err
			}
		}
	}
	r.file.Close()
	if err := c.remove(path); err != nil {
		return paths, err
	}
	return paths, nil
}

func (c *compiler) object(object via3.BuiltObject) error {
	if uint64(len(object.Bytes)) > c.options.Limits.ObjectBytes {
		return &via3.Error{Code: "resource_limit"}
	}
	if old, ok := c.objects[object.Info.SHA256]; ok {
		// Identical inherited-only shards can serve several partition ranges.
		// Their immutable bytes are shared and their manifest scope becomes all;
		// router entries still bind each lookup to the exact planned range.
		if old.Partition != object.Info.Partition {
			old.Partition = "all"
			c.objects[old.SHA256] = old
		}
		return nil
	}
	if len(c.objects) >= c.options.Limits.MaxObjects {
		return &via3.Error{Code: "partition_budget"}
	}
	if len(object.Bytes) != object.Info.Bytes || via3.Hash(object.Bytes) != object.Info.SHA256 {
		return errors.New("compiled object hash mismatch")
	}
	if err := c.write(filepath.Join(c.output, "objects", object.Info.SHA256+".via3"), object.Bytes); err != nil {
		return err
	}
	// Hash the actual completed file, not merely the source buffer, before any
	// manifest/pointer can refer to it. This read has a fixed-size working set.
	file, err := os.Open(filepath.Join(c.output, "objects", object.Info.SHA256+".via3"))
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	var buffer [64 << 10]byte
	size := 0
	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		n, err := file.Read(buffer[:])
		size += n
		if size > object.Info.Bytes {
			return errors.New("written object length mismatch")
		}
		if n > 0 {
			hasher.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if size != object.Info.Bytes || hex.EncodeToString(hasher.Sum(nil)) != object.Info.SHA256 {
		return errors.New("written object integrity mismatch")
	}
	c.objects[object.Info.SHA256] = object.Info
	c.stats.OutputBytes += uint64(len(object.Bytes))
	return nil
}

func (c *compiler) router() error {
	byHash := map[string]via3.ObjectInfo{}
	for _, r := range c.routes {
		for _, dest := range r.destinations {
			byHash[dest.SHA256] = dest
		}
	}
	directory := make([]via3.ObjectInfo, 0, len(byHash))
	for _, info := range byHash {
		directory = append(directory, info)
	}
	sort.Slice(directory, func(i, j int) bool {
		if directory[i].Kind != directory[j].Kind {
			return directory[i].Kind < directory[j].Kind
		}
		return directory[i].SHA256 < directory[j].SHA256
	})
	ids := map[string]uint32{}
	var objectRows [][]byte
	for i, info := range directory {
		row := make([]byte, 40)
		binary.LittleEndian.PutUint16(row, info.Kind)
		binary.LittleEndian.PutUint32(row[4:], uint32(info.Bytes))
		hash, _ := hex.DecodeString(info.SHA256)
		copy(row[8:], hash)
		objectRows = append(objectRows, row)
		ids[info.SHA256] = uint32(i)
	}
	sort.Slice(c.routes, func(i, j int) bool {
		a, b := c.routes[i], c.routes[j]
		if a.prefix.IsValid() != b.prefix.IsValid() {
			return a.prefix.IsValid()
		}
		if a.prefix.IsValid() {
			if a.prefix.Addr().Is4() != b.prefix.Addr().Is4() {
				return a.prefix.Addr().Is4()
			}
			if a.prefix.Addr() != b.prefix.Addr() {
				return a.prefix.Addr().Less(b.prefix.Addr())
			}
			return a.prefix.Bits() < b.prefix.Bits()
		}
		return a.asns[0] < b.asns[0]
	})
	var rows, integers, prefixes, asns [][]byte
	for _, r := range c.routes {
		row := make([]byte, 16)
		binary.LittleEndian.PutUint32(row, uint32(len(integers)))
		binary.LittleEndian.PutUint16(row[4:], uint16(len(r.destinations)))
		for _, dest := range r.destinations {
			v := make([]byte, 4)
			binary.LittleEndian.PutUint32(v, ids[dest.SHA256])
			integers = append(integers, v)
		}
		ordinal := uint32(len(rows))
		rows = append(rows, row)
		if r.prefix.IsValid() {
			prefixes = append(prefixes, via3.PrefixKey(r.prefix, false, ordinal))
		} else {
			for _, asn := range r.asns {
				v := make([]byte, 8)
				binary.LittleEndian.PutUint32(v, asn)
				binary.LittleEndian.PutUint32(v[4:], ordinal)
				asns = append(asns, v)
			}
		}
	}
	shard := via3.Shard{Kind: 1, Sections: []via3.Section{{ID: 1, Data: via3.Vector(32, prefixes...)}, {ID: 2, Data: via3.Vector(8, asns...)}, {ID: 3, Data: via3.Vector(16, rows...)}, {ID: 4, Data: via3.Vector(4, integers...)}, {ID: 7, Data: via3.Vector(40, objectRows...)}}}
	if err := via3.ValidatePublicProfile(shard); err != nil {
		return err
	}
	data, err := via3.Write(c.ctx, shard)
	if err != nil {
		return err
	}
	return c.object(via3.BuiltObject{Info: via3.ObjectInfo{Bytes: len(data), Kind: 1, Partition: "all", SHA256: via3.Hash(data)}, Bytes: data, Shard: shard})
}
