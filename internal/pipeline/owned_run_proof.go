package pipeline

import (
	"crypto/sha256"
	"errors"
	"os"

	"vansail-ip-atlas/internal/via3"
)

const (
	ownedProofLimit       = 16 << 20
	ownedProofBuckets     = 256
	ownedProofBlockLength = 16
	// Each block contains 16 original 40-byte headers and 32-byte digests,
	// plus a link. Round above the allocation class for this structure.
	ownedProofBlockCost = 1536
)

var errOwnedRunProof = errors.New("compiler-owned run no longer matches its original bytes")

type ownedSegmentProof struct {
	header [privateRunSegmentHeader]byte
	stored [sha256.Size]byte
}

type ownedProofBlock struct {
	segments [ownedProofBlockLength]ownedSegmentProof
	next     *ownedProofBlock
}

type ownedRunProof struct {
	path     string
	file     os.FileInfo
	size     int64
	segments int
	first    *ownedProofBlock
	last     *ownedProofBlock
	next     *ownedRunProof
	cost     int
	registry *ownedRunRegistry
	readers  int
	retired  bool
	scatter  *ownedScatterPlan
}

func (p *ownedRunProof) checkFile(info os.FileInfo) error {
	if info == nil || p.file == nil || !info.Mode().IsRegular() || !os.SameFile(p.file, info) || info.Size() != p.size {
		return errOwnedRunProof
	}
	return nil
}

// These chains avoid heap-allocated directory growth and keep every live entry
// charged until its last reader closes. The compiler uses the registry serially.
type ownedRunRegistry struct {
	buckets [ownedProofBuckets]*ownedRunProof
	used    int
}

func ownedProofBucket(path string) uint8 {
	// This digest only selects a bucket. The complete path is always compared.
	var n uint32 = 2166136261
	for i := range len(path) {
		n = (n ^ uint32(path[i])) * 16777619
	}
	return uint8(n)
}

func (r *ownedRunRegistry) lookup(path string) *ownedRunProof {
	for p := r.buckets[ownedProofBucket(path)]; p != nil; p = p.next {
		if p.path == path {
			return p
		}
	}
	return nil
}

func (r *ownedRunRegistry) remove(path string) {
	link := &r.buckets[ownedProofBucket(path)]
	for *link != nil {
		p := *link
		if p.path == path {
			*link = p.next
			p.next = nil
			p.retire()
			return
		}
		link = &p.next
	}
}

func (r *ownedRunRegistry) charge(cost int) bool {
	// Includes the always-resident directory's pointers and bookkeeping.
	if cost > ownedProofLimit-8*ownedProofBuckets-64-r.used {
		return false
	}
	r.used += cost
	return true
}

func (r *ownedRunRegistry) begin(path string) *ownedRunProof {
	// Covers the entry, os.FileInfo and path backing storage including the
	// retained file's name; the codec's independently bounded buffers are not
	// part of this optional index.
	cost := 1024 + len(path)*2
	if !r.charge(cost) {
		return nil
	}
	return &ownedRunProof{registry: r, cost: cost, path: path, size: int64(len(privateRunMagic) + privateRunSegmentHeader)}
}

func (p *ownedRunProof) releaseIfUnused() {
	if p.retired && p.readers == 0 && p.cost != 0 {
		p.registry.used -= p.cost
		p.cost, p.first, p.last, p.file, p.path = 0, nil, nil, nil, ""
		p.scatter = nil
	}
}

func (p *ownedRunProof) retire() {
	p.retired = true
	p.releaseIfUnused()
}

func (p *ownedRunProof) record(header [privateRunSegmentHeader]byte, stored []byte) bool {
	i := p.segments % ownedProofBlockLength
	if i == 0 {
		if !p.registry.charge(ownedProofBlockCost) {
			return false
		}
		p.cost += ownedProofBlockCost
		b := new(ownedProofBlock)
		if p.last == nil {
			p.first = b
		} else {
			p.last.next = b
		}
		p.last = b
	}
	p.last.segments[i] = ownedSegmentProof{header, sha256.Sum256(stored)}
	p.segments++
	p.size += int64(len(header) + len(stored))
	return true
}

type ownedRunWriter struct {
	owner *compiler
	file  *os.File
	codec *privateRunWriter
	proof *ownedRunProof
	err   error
}

func (c *compiler) newOwnedRunWriter(path string) (*ownedRunWriter, error) {
	if c.runProofs.lookup(path) != nil {
		return nil, errOwnedRunProof
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	codec, err := newPrivateRunWriter(c, f)
	if err != nil {
		return nil, errors.Join(err, f.Close(), os.Remove(path))
	}
	w := &ownedRunWriter{owner: c, file: f, codec: codec, proof: c.runProofs.begin(path)}
	if w.proof != nil {
		codec.onSegment = w.record
	}
	return w, nil
}

func (w *ownedRunWriter) record(header [privateRunSegmentHeader]byte, stored []byte) {
	if !w.proof.record(header, stored) {
		w.disableProof()
	}
}

func (w *ownedRunWriter) disableProof() {
	if w.proof != nil {
		w.proof.retire()
		w.proof = nil
		w.codec.onSegment = nil
	}
}

func (w *ownedRunWriter) AppendCanonical(f ownedRunFrame) error {
	if !f.ownedBy(w.owner) || f.row.logicalBytes > w.owner.options.Limits.RecordBytes {
		w.err = errOwnedRunProof
		return w.err
	}
	return w.appendRow(f.row)
}

func (w *ownedRunWriter) AppendUnproved(row encoded) error {
	w.disableProof()
	return w.appendRow(row)
}

func (w *ownedRunWriter) appendFrame(f ownedRunFrame) error {
	if f.owner == nil {
		return w.AppendUnproved(f.row)
	}
	return w.AppendCanonical(f)
}

// A plan is optional and shares the preexisting aggregate proof budget. It
// belongs to this exact writer's byte-authenticated output, not its path.
func (w *ownedRunWriter) enablePartitionPlan(s scope) {
	if w.proof == nil || !w.proof.registry.charge(ownedScatterPlanCost) {
		return
	}
	plan := newOwnedScatterPlan(s)
	if plan == nil {
		w.proof.registry.used -= ownedScatterPlanCost
		return
	}
	w.proof.cost += ownedScatterPlanCost
	w.proof.scatter = plan
}

func (w *ownedRunWriter) appendPartitionFrame(frame ownedRunFrame, record via3.PublicRecord) error {
	if err := w.appendFrame(frame); err != nil {
		return err
	}
	if proof := w.proof; proof != nil && proof.scatter != nil {
		plan := proof.scatter
		// The copied frame may have acquired the inherited bit on its way
		// into the current child. Its prefix and wire size are unchanged.
		if !plan.tree.asn && record.Prefix.Bits() < plan.tree.prefix.Bits() {
			record.Inherited = true
		}
		if err := plan.count(record, frame); err != nil {
			// Only the ordinary partition traversal may report a planning
			// error. A producer-side plan is never required for correctness.
			proof.scatter = nil
			proof.cost -= ownedScatterPlanCost
			proof.registry.used -= ownedScatterPlanCost
		}
	}
	return nil
}

func (w *ownedRunWriter) appendRow(row encoded) error {
	if w.err != nil {
		return w.err
	}
	if w.file == nil {
		return os.ErrClosed
	}
	if err := w.owner.ctx.Err(); err != nil {
		w.err = err
	} else {
		w.err = writeRunFrame(w.codec, row)
	}
	return w.err
}

// Finish owns the complete close sequence. Close aborts an unfinished writer;
// an aborted writer can never publish by subsequently calling Finish.
func (w *ownedRunWriter) Finish() (err error) {
	if w.file == nil {
		return os.ErrClosed
	}
	defer func() { err = errors.Join(err, w.Close()) }()
	if w.err != nil {
		return w.err
	}
	if w.codec.finished {
		return os.ErrClosed
	}
	if err = w.codec.Flush(); err != nil {
		return err
	}
	p := w.proof
	if p != nil {
		p.file, err = w.file.Stat()
		if err != nil {
			return err
		}
		if err = p.checkFile(p.file); err != nil {
			return err
		}
	}
	err = w.file.Close()
	w.file = nil
	if err != nil || p == nil {
		return err
	}
	current, err := os.Lstat(p.path)
	if err != nil {
		return err
	}
	if err = p.checkFile(current); err != nil {
		return err
	}
	if err = w.owner.ctx.Err(); err != nil {
		return err
	}
	directory := &p.registry.buckets[ownedProofBucket(p.path)]
	p.next, *directory = *directory, p
	w.proof = nil
	return nil
}

func (w *ownedRunWriter) Close() error {
	w.disableProof()
	var codecErr, fileErr error
	if w.codec != nil {
		w.codec.onSegment = nil
		codecErr = w.codec.Close()
		w.codec = nil
	}
	if w.file != nil {
		fileErr = w.file.Close()
		w.file = nil
	}
	return errors.Join(codecErr, fileErr)
}

// Several classified or split outputs can finish in turn. If a later output
// or input removal fails, retire even the proofs that finished earlier.
func (c *compiler) closePartitionWriters(writers []*ownedRunWriter, paths []string, completed bool) {
	for i, w := range writers {
		if w != nil {
			_ = w.Close()
			if !completed {
				c.runProofs.remove(paths[i])
			}
		}
	}
}
