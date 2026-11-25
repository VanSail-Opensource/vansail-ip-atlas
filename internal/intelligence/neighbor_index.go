package intelligence

import (
	"math"
	"net/netip"
	"sort"
)

type neighborCell struct {
	risk    float64
	host    uint8
	support uint8 // distinct families contributed by the other positive cells
}

type neighborBlock struct {
	cells   []neighborCell
	mass    float64
	support uint8
}

// Positive exact cells enter each /24 in the same global address order used
// by scoring. Track the families unique to each cell, so excluding that cell
// preserves the diversity of the remaining independently observed families.
func indexNeighbors(addresses []netip.Addr, facts map[netip.Addr]exactFact) map[netip.Prefix]neighborBlock {
	blocks := make(map[netip.Prefix]neighborBlock)
	owners := make(map[string]int)
	for first := 0; first < len(addresses) && addresses[first].Is4(); {
		prefix := netip.PrefixFrom(addresses[first], 24).Masked()
		end := first + 1
		for end < len(addresses) && prefix.Contains(addresses[end]) {
			end++
		}
		clear(owners)
		var exclusive [256]int
		var block neighborBlock
		for _, address := range addresses[first:end] {
			fact := facts[address]
			if fact.layer.Risk <= 0 {
				continue
			}
			host := address.As4()[3]
			if block.cells == nil {
				block.cells = make([]neighborCell, 0, end-first)
			}
			block.cells = append(block.cells, neighborCell{risk: fact.layer.Risk, host: host})
			block.mass += fact.layer.Risk
			for _, family := range fact.positiveFamilies {
				owner, exists := owners[family]
				if !exists {
					owners[family] = int(host)
					exclusive[host]++
				} else if owner >= 0 && owner != int(host) {
					owners[family] = -1
					exclusive[owner]--
				}
			}
		}
		if len(block.cells) > 0 {
			block.support = uint8(min(len(owners), 4))
			for i, cell := range block.cells {
				block.cells[i].support = uint8(min(len(owners)-exclusive[cell.host], 4))
			}
			blocks[prefix] = block
		}
		first = end
	}
	return blocks
}

func (e *Engine) NeighborContext(addr netip.Addr) ASNContext {
	if addr.Zone() != "" {
		return ASNContext{}
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return ASNContext{}
	}
	block := e.neighbors[netip.PrefixFrom(addr, 24).Masked()]
	count := len(block.cells)
	if count == 0 {
		return ASNContext{}
	}
	host := addr.As4()[3]
	mass, support := block.mass, block.support
	i := sort.Search(count, func(i int) bool { return block.cells[i].host >= host })
	if i < count && block.cells[i].host == host {
		count--
		support = block.cells[i].support
		// Subtracting the omitted risk from the rounded total could change
		// the final bits. Add the surviving cells in their original order.
		mass = 0
		for _, cell := range block.cells[:i] {
			mass += cell.risk
		}
		for _, cell := range block.cells[i+1:] {
			mass += cell.risk
		}
	}
	risk := 1 - math.Exp(-16*mass/255)
	confidence := math.Min(1, float64(count)/16) * math.Min(1, float64(support)/3)
	return ASNContext{risk, confidence, e.policy.Weights[3] * confidence * risk, count > 0, support}
}
