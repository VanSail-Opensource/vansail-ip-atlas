package pipeline

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net/netip"
	"os"

	"vansail-ip-atlas/internal/via3"
)

type scatteredRun struct {
	path string
	scope
}

type scatterTotals struct {
	size      partitionSize
	wireBytes int64
	cover     netip.Prefix
}

type scatterNode struct {
	scope
	scatterTotals
	first, last uint32
	children    [2]*scatterNode
	target      int
}

func (c *compiler) partitionFits(size partitionSize) bool {
	return size.records <= int64(c.options.Limits.PartitionRecords) && size.bytes <= c.options.Limits.PartitionBytes
}

func scatterTree(s scope, depth int) *scatterNode {
	node := &scatterNode{scope: s, target: -1}
	if depth == 4 {
		return node
	}
	left, right, err := s.children()
	if err == nil {
		node.children = [2]*scatterNode{scatterTree(left, depth+1), scatterTree(right, depth+1)}
	}
	return node
}

// The same canonical inherited bytes apply to every descendant where this row
// is an overlay. Fitting ancestors keep their original non-inherited bytes.
func scatterRow(record via3.PublicRecord, row ownedRunFrame, target scope, inherited *ownedRunFrame) (ownedRunFrame, bool, error) {
	if target.asn {
		return row, record.ASN >= target.first && record.ASN <= target.last, nil
	}
	if record.Prefix.Bits() < target.prefix.Bits() && record.Prefix.Contains(target.prefix.Addr()) {
		if record.Kind == 7 || record.Exact {
			return ownedRunFrame{}, false, errors.New("profile or exact row cannot become an inherited overlay")
		}
		if !record.Inherited {
			if inherited.row.data == nil {
				var err error
				*inherited, err = row.inherited(record)
				if err != nil {
					return ownedRunFrame{}, false, err
				}
			}
			return *inherited, true, nil
		}
		return row, true, nil
	}
	return row, target.prefix.Contains(record.Prefix.Addr()), nil
}

// A row at least four bits below this IP scope belongs to one terminal. Its
// original bytes and cover are identical at all four ancestors. Add these
// contributions once per terminal and fold the bounded totals after scanning.
type scatterPrefixes struct {
	root    *scatterNode
	bits    int
	totals  [16]scatterTotals
	targets [16]int
}

// At most 31 tree nodes and 16 prefix bins, charged to the existing private
// run-proof memory ceiling. The plan does not retain any frame or fact body.
const ownedScatterPlanCost = 8192

type ownedScatterPlan struct {
	tree *scatterNode
	bins *scatterPrefixes
}

func newOwnedScatterPlan(s scope) *ownedScatterPlan {
	tree := scatterTree(s, 0)
	if tree.children[0] == nil {
		return nil
	}
	return &ownedScatterPlan{tree: tree, bins: newScatterPrefixes(tree)}
}

func (p *ownedScatterPlan) count(record via3.PublicRecord, frame ownedRunFrame) error {
	if slot, ok := p.bins.slot(record.Prefix); ok {
		terminal := &p.bins.totals[slot]
		terminal.size.records++
		terminal.size.bytes += frame.row.logicalBytes + 512
		terminal.wireBytes += frame.row.frameBytes()
		terminal.cover = bulkPrefixCover(terminal.cover, record.Prefix)
		return nil
	}
	var inherited ownedRunFrame
	return p.tree.count(record, frame, &inherited)
}

func scatterEligible(s scope, total partitionSize, limits Limits) bool {
	threshold := int64(8)
	if !s.asn {
		threshold = 2
	}
	return total.records > threshold*int64(limits.PartitionRecords) || total.bytes > threshold*limits.PartitionBytes
}

func newScatterPrefixes(root *scatterNode) *scatterPrefixes {
	if root.asn {
		return nil
	}
	bits := root.prefix.Bits()
	ceiling := root.prefix.Addr().BitLen()
	if root.prefix.Addr().Is4() {
		ceiling = 24
	}
	if bits+4 > ceiling {
		return nil
	}
	return &scatterPrefixes{root: root, bits: bits}
}

func (s *scatterPrefixes) slot(p netip.Prefix) (int, bool) {
	if s == nil || p.Bits() < s.bits+4 || !s.root.prefix.Contains(p.Addr()) {
		return 0, false
	}
	bits := s.bits
	if p.Addr().Is4() {
		bits += 96
	}
	addr := p.Addr().As16()
	index, offset := bits/8, uint(bits%8)
	if offset <= 4 {
		return int(addr[index] >> (4 - offset) & 15), true
	}
	word := uint16(addr[index])<<8 | uint16(addr[index+1])
	return int(word >> (12 - offset) & 15), true
}

func (s *scatterPrefixes) addTotals() {
	if s == nil {
		return
	}
	for slot, sum := range s.totals {
		if sum.size.records == 0 {
			continue
		}
		node := s.root
		for bit := 3; ; bit-- {
			node.size.records += sum.size.records
			node.size.bytes += sum.size.bytes
			node.wireBytes += sum.wireBytes
			node.cover = bulkPrefixCover(node.cover, sum.cover)
			if bit < 0 {
				break
			}
			node = node.children[slot>>bit&1]
		}
	}
}

func (s *scatterPrefixes) selectTargets() {
	if s == nil {
		return
	}
	for slot := range s.targets {
		node := s.root
		for bit := 3; bit >= 0 && node.target < 0; bit-- {
			node = node.children[slot>>bit&1]
		}
		s.targets[slot] = node.target
	}
}

func (node *scatterNode) count(record via3.PublicRecord, row ownedRunFrame, inherited *ownedRunFrame) error {
	selected, keep, err := scatterRow(record, row, node.scope, inherited)
	if err != nil || !keep {
		return err
	}
	node.size.records++
	node.size.bytes += selected.row.logicalBytes + 512
	node.wireBytes += selected.row.frameBytes()
	if node.asn {
		if node.first == 0 || record.ASN < node.first {
			node.first = record.ASN
		}
		node.last = max(node.last, record.ASN)
	} else {
		node.cover = bulkPrefixCover(node.cover, record.Prefix)
	}
	return node.visitChildren(record, func(child *scatterNode) error {
		return child.count(record, row, inherited)
	})
}

// A more-specific row follows one binary branch; an ancestor overlay visits
// both. Avoid testing all sixteen terminal scopes for every ordinary row.
func (node *scatterNode) visitChildren(record via3.PublicRecord, visit func(*scatterNode) error) error {
	if node.children[0] == nil {
		return nil
	}
	if node.asn {
		i := 0
		if record.ASN > node.children[0].scope.last {
			i = 1
		}
		return visit(node.children[i])
	}
	if record.Prefix.Bits() > node.prefix.Bits() {
		i := 0
		if node.children[1].prefix.Contains(record.Prefix.Addr()) {
			i = 1
		}
		return visit(node.children[i])
	}
	if err := visit(node.children[0]); err != nil {
		return err
	}
	return visit(node.children[1])
}

func (node *scatterNode) visitTargets(record via3.PublicRecord, visit func(int) error) error {
	if node.size.records == 0 {
		return nil
	}
	if node.target >= 0 {
		return visit(node.target)
	}
	return node.visitChildren(record, func(child *scatterNode) error {
		return child.visitTargets(record, visit)
	})
}

func (node *scatterNode) narrow() {
	if node.asn {
		for node.scope.first != node.scope.last {
			left, right, _ := node.scope.children()
			if node.last <= left.last {
				node.scope = left
			} else if node.first >= right.first {
				node.scope = right
			} else {
				break
			}
		}
	} else if node.cover.IsValid() && node.cover.Bits() > node.prefix.Bits() {
		depth := node.cover.Bits()
		if node.cover.Addr().Is4() {
			depth = min(depth, 24)
		}
		node.prefix = netip.PrefixFrom(node.cover.Addr(), depth).Masked()
	}
}

func hashRunFrame(h hash.Hash, row encoded) {
	// The frame marker participates in identity checks between scatter passes.
	_ = writeRunFrame(h, row)
}

// scatterPartition amortizes up to four binary splits. A producer-side plan
// can replace the first scan of a proved run when a verified redistribution
// will follow. It selects the original first-fitting logical scopes, not a
// fixed sixteen-way partition. Binary size/profile checks remain in partition.
func (c *compiler) scatterPartition(path string, s scope) (runs []scatteredRun, applied bool, failure error) {
	total, known := c.partitionSizes[path]
	if !known || !scatterEligible(s, total, c.options.Limits) {
		return nil, false, nil
	}
	r, err := c.openIntermediateRun(path)
	if err != nil {
		return nil, false, err
	}
	defer r.file.Close()
	// Every scan of an owned run authenticates each segment, order, terminal
	// and actual EOF against this same process-local proof.
	var proof *ownedRunProof
	if r.owner != nil {
		proof = r.file.compressed.proof
	}
	var plan *ownedScatterPlan
	if proof != nil && proof.scatter != nil && proof.scatter.tree.scope == s {
		plan, proof.scatter = proof.scatter, nil
		plan.bins.addTotals()
		if plan.tree.size != total {
			return nil, false, errOwnedRunProof
		}
		// A unary scope jump would not run the subsequent full writer scan.
		// Authenticate its actual input now, exactly as the previous path did.
		if plan.tree.children[0].size.records == 0 || plan.tree.children[1].size.records == 0 {
			plan = nil
		}
	}
	var firstDigest []byte
	if plan == nil {
		plan = newOwnedScatterPlan(s)
		if plan == nil {
			return nil, false, nil
		}
		firstHash := sha256.New()
		for {
			if err := c.ctx.Err(); err != nil {
				return nil, false, err
			}
			if err := r.nextPartitionRow(); err == io.EOF {
				break
			} else if err != nil {
				return nil, false, err
			}
			if proof == nil {
				hashRunFrame(firstHash, r.row)
			}
			if err := plan.count(r.record, r.frame()); err != nil {
				return nil, false, err
			}
		}
		firstDigest = firstHash.Sum(nil)
		plan.bins.addTotals()
	}
	if err := r.file.Close(); err != nil {
		return nil, false, err
	}
	tree, bins := plan.tree, plan.bins
	if tree.size != total {
		return nil, false, errors.New("private run totals changed")
	}
	// Match the ordinary splitter's unary jump before considering lookahead
	// branches. The sole child owns every unchanged frame; a newly inherited
	// row would populate both children. Reuse this immutable run instead of
	// decoding and writing an identical copy merely to narrow its scope.
	if (tree.children[0].size.records == 0) != (tree.children[1].size.records == 0) {
		child := tree.children[0]
		if child.size.records == 0 {
			child = tree.children[1]
		}
		if child.size != total {
			return nil, false, errors.New("unary public scatter totals changed")
		}
		child.narrow()
		if err := c.ctx.Err(); err != nil {
			return nil, false, err
		}
		return []scatteredRun{{path, child.scope}}, true, nil
	}
	var selected []*scatterNode
	var selectNodes func(*scatterNode)
	selectNodes = func(node *scatterNode) {
		if node.size.records == 0 {
			return
		}
		if c.partitionFits(node.size) || node.children[0] == nil {
			if !c.partitionFits(node.size) {
				node.narrow()
			}
			node.target = len(selected)
			selected = append(selected, node)
			return
		}
		selectNodes(node.children[0])
		selectNodes(node.children[1])
	}
	selectNodes(tree.children[0])
	selectNodes(tree.children[1])
	if len(selected) == 0 || len(selected) > 16 {
		return nil, false, errors.New("public scatter fanout invalid")
	}
	var planned uint64
	for _, node := range selected {
		planned += privateRunStoredBound(uint64(node.wireBytes))
	}
	extra := uint64(0)
	if c.options.externalScratch != nil {
		extra = c.options.externalScratch()
	}
	if extra > c.options.Limits.ScratchBytes || c.used > c.options.Limits.ScratchBytes-extra || planned > c.options.Limits.ScratchBytes-extra-c.used {
		// The ordinary depth-first split may fit with fewer simultaneous rows.
		// No file or accounting mutation has occurred at this fallback point.
		return nil, false, nil
	}
	bins.selectTargets()
	return c.writeScatter(path, tree, selected, proof, firstDigest, bins)
}

func (c *compiler) writeScatter(path string, tree *scatterNode, selected []*scatterNode, proof *ownedRunProof, digest []byte, bins *scatterPrefixes) (runs []scatteredRun, applied bool, failure error) {
	before := c.used
	writers := make([]*ownedRunWriter, len(selected))
	sizes := make([]partitionSize, len(selected))
	wireBytes := make([]int64, len(selected))
	runs = make([]scatteredRun, len(selected))
	defer func() {
		for _, w := range writers {
			if w != nil {
				_ = w.Close()
			}
		}
		if !applied {
			for _, run := range runs {
				if run.path != "" {
					if err := os.Remove(run.path); err != nil && !os.IsNotExist(err) {
						failure = errors.Join(failure, err)
					}
					delete(c.partitionSizes, run.path)
					c.runProofs.remove(run.path)
				}
			}
			c.used = before
			if c.options.scratchUsage != nil {
				c.options.scratchUsage(c.used)
			}
		}
	}()
	r, err := c.openIntermediateRun(path)
	if err != nil {
		return runs, false, err
	}
	defer r.file.Close()
	if proof != nil && (r.owner == nil || r.file.compressed.proof != proof) {
		return runs, false, errOwnedRunProof
	}
	secondHash := sha256.New()
	for {
		if err := c.ctx.Err(); err != nil {
			return runs, false, err
		}
		if err := r.nextPartitionRow(); err == io.EOF {
			break
		} else if err != nil {
			return runs, false, err
		}
		if proof == nil {
			hashRunFrame(secondHash, r.row)
		}
		var inherited ownedRunFrame
		write := func(i int) error {
			node := selected[i]
			frame, keep, err := scatterRow(r.record, r.frame(), node.scope, &inherited)
			if err != nil {
				return err
			}
			if !keep {
				return nil
			}
			if writers[i] == nil {
				target := c.next()
				writers[i], err = c.newOwnedRunWriter(target)
				if err != nil {
					return err
				}
				if scatterEligible(node.scope, node.size, c.options.Limits) {
					writers[i].enablePartitionPlan(node.scope)
				}
				runs[i] = scatteredRun{target, node.scope}
			}
			if err := writers[i].appendPartitionFrame(frame, r.record); err != nil {
				return err
			}
			sizes[i].records++
			sizes[i].bytes += frame.row.logicalBytes + 512
			wireBytes[i] += frame.row.frameBytes()
			return nil
		}
		if slot, ok := bins.slot(r.record.Prefix); ok {
			target := bins.targets[slot]
			if target < 0 {
				return runs, false, errors.New("private run changed during scatter")
			}
			err = write(target)
		} else {
			err = tree.visitTargets(r.record, write)
		}
		if err != nil {
			return runs, false, err
		}
	}
	if proof == nil && !bytes.Equal(secondHash.Sum(nil), digest) {
		return runs, false, errors.New("private run changed during scatter")
	}
	for i, node := range selected {
		if writers[i] == nil || sizes[i] != node.size || wireBytes[i] != node.wireBytes {
			return runs, false, errors.New("public scatter totals changed")
		}
		if err := writers[i].Finish(); err != nil {
			return runs, false, err
		}
		c.rememberPartitionSize(runs[i].path, sizes[i])
	}
	if err := r.file.Close(); err != nil {
		return runs, false, err
	}
	if err := c.ctx.Err(); err != nil {
		return runs, false, err
	}
	if err := c.remove(path); err != nil {
		return runs, false, err
	}
	return runs, true, nil
}
