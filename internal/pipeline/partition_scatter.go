package pipeline

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
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

type scatterNode struct {
	scope
	size        partitionSize
	cover       netip.Prefix
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
func scatterRow(record via3.PublicRecord, data []byte, target scope, inherited *[]byte) ([]byte, bool, error) {
	if target.asn {
		return data, record.ASN >= target.first && record.ASN <= target.last, nil
	}
	if record.Prefix.Bits() < target.prefix.Bits() && record.Prefix.Contains(target.prefix.Addr()) {
		if record.Kind == 7 || record.Exact {
			return nil, false, errors.New("profile or exact row cannot become an inherited overlay")
		}
		if !record.Inherited {
			if *inherited == nil {
				record.Inherited = true
				var err error
				*inherited, err = json.Marshal(record)
				if err != nil {
					return nil, false, err
				}
			}
			return *inherited, true, nil
		}
		return data, true, nil
	}
	return data, target.prefix.Contains(record.Prefix.Addr()), nil
}

func (node *scatterNode) count(record via3.PublicRecord, data []byte, inherited *[]byte) error {
	encoded, keep, err := scatterRow(record, data, node.scope, inherited)
	if err != nil || !keep {
		return err
	}
	node.size.records++
	node.size.bytes += int64(len(encoded)) + 512
	if node.asn {
		if node.first == 0 || record.ASN < node.first {
			node.first = record.ASN
		}
		node.last = max(node.last, record.ASN)
	} else {
		node.cover = bulkPrefixCover(node.cover, record.Prefix)
	}
	return node.visitChildren(record, func(child *scatterNode) error {
		return child.count(record, data, inherited)
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

func hashRunFrame(h hash.Hash, data []byte) {
	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(data)))
	_, _ = h.Write(head[:])
	_, _ = h.Write(data)
}

// scatterPartition amortizes up to four binary split passes into two strict
// scans. It selects the original first-fitting logical scopes, not a fixed
// sixteen-way partition. Actual binary size/profile checks remain in partition.
func (c *compiler) scatterPartition(path string, s scope) (runs []scatteredRun, applied bool, failure error) {
	total, known := c.partitionSizes[path]
	if !known || total.records <= 8*int64(c.options.Limits.PartitionRecords) && total.bytes <= 8*c.options.Limits.PartitionBytes {
		return nil, false, nil
	}
	tree := scatterTree(s, 0)
	if tree.children[0] == nil {
		return nil, false, nil
	}
	r, err := openRun(path, c.options.Limits.RecordBytes)
	if err != nil {
		return nil, false, err
	}
	defer r.file.Close()
	firstHash := sha256.New()
	for {
		if err := c.ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := r.next(); err == io.EOF {
			break
		} else if err != nil {
			return nil, false, err
		}
		hashRunFrame(firstHash, r.row.data)
		var inherited []byte
		if err := tree.count(r.record, r.row.data, &inherited); err != nil {
			return nil, false, err
		}
	}
	if err := r.file.Close(); err != nil {
		return nil, false, err
	}
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
		planned += uint64(node.size.bytes - 508*node.size.records)
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
	return c.writeScatter(path, tree, selected, firstHash.Sum(nil))
}

func (c *compiler) writeScatter(path string, tree *scatterNode, selected []*scatterNode, digest []byte) (runs []scatteredRun, applied bool, failure error) {
	before := c.used
	files := make([]*os.File, len(selected))
	writers := make([]*bufio.Writer, len(selected))
	sizes := make([]partitionSize, len(selected))
	runs = make([]scatteredRun, len(selected))
	defer func() {
		for _, file := range files {
			if file != nil {
				_ = file.Close()
			}
		}
		if !applied {
			for _, run := range runs {
				if run.path != "" {
					if err := os.Remove(run.path); err != nil && !os.IsNotExist(err) {
						failure = errors.Join(failure, err)
					}
					delete(c.partitionSizes, run.path)
				}
			}
			c.used = before
			if c.options.scratchUsage != nil {
				c.options.scratchUsage(c.used)
			}
		}
	}()
	r, err := openRun(path, c.options.Limits.RecordBytes)
	if err != nil {
		return runs, false, err
	}
	defer r.file.Close()
	secondHash := sha256.New()
	for {
		if err := c.ctx.Err(); err != nil {
			return runs, false, err
		}
		if err := r.next(); err == io.EOF {
			break
		} else if err != nil {
			return runs, false, err
		}
		hashRunFrame(secondHash, r.row.data)
		var inherited []byte
		if err := tree.visitTargets(r.record, func(i int) error {
			node := selected[i]
			data, keep, err := scatterRow(r.record, r.row.data, node.scope, &inherited)
			if err != nil {
				return err
			}
			if !keep {
				return nil
			}
			if files[i] == nil {
				target := c.next()
				files[i], err = os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return err
				}
				runs[i] = scatteredRun{target, node.scope}
				writers[i] = bufio.NewWriterSize(files[i], 64<<10)
			}
			if err := c.writeRecord(writers[i], data); err != nil {
				return err
			}
			sizes[i].records++
			sizes[i].bytes += int64(len(data)) + 512
			return nil
		}); err != nil {
			return runs, false, err
		}
	}
	if !bytes.Equal(secondHash.Sum(nil), digest) {
		return runs, false, errors.New("private run changed during scatter")
	}
	for i, node := range selected {
		if files[i] == nil || sizes[i] != node.size {
			return runs, false, errors.New("public scatter totals changed")
		}
		if err := writers[i].Flush(); err != nil {
			return runs, false, err
		}
		if err := files[i].Close(); err != nil {
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
