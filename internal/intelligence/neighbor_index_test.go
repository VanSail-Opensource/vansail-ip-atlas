package intelligence

import (
	"math"
	"net/netip"
	"testing"
)

func TestNeighborIndexPreservesOrderedOmissionsAndFamilyCounts(t *testing.T) {
	policy := testPolicy(t)
	var addresses []netip.Addr
	facts := make(map[netip.Addr]exactFact)
	for host := range 33 {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(host)})
		addresses = append(addresses, addr)
		risk := float64((host*19)%41+1) / 41
		families := []string{"shared"}
		if host == 7 {
			families = append(families, "only-a", "only-b", "only-c", "only-d")
		}
		if host%3 == 0 {
			families = append(families, "several")
		}
		if host == 32 {
			risk = 0
			families = []string{"zero-risk"}
		}
		facts[addr] = exactFact{LayerResult{Risk: risk}, families}
	}
	// Positive v6 evidence does not create an IPv4 neighbor.
	v6 := netip.MustParseAddr("2001:db8::1")
	addresses = append(addresses, v6)
	facts[v6] = exactFact{LayerResult{Risk: 1}, []string{"other"}}
	e := Engine{policy: policy, neighbors: indexNeighbors(addresses, facts)}
	total := 0.0
	for _, addr := range addresses {
		if addr.Is4() {
			total += facts[addr].layer.Risk
		}
	}
	distinguishesSubtraction := false
	for i := range 256 {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		count, mass := 0, 0.0
		families := make(map[string]bool)
		for _, other := range addresses {
			fact := facts[other]
			if !other.Is4() || addr == other || fact.layer.Risk <= 0 {
				continue
			}
			count++
			mass += fact.layer.Risk
			for _, family := range fact.positiveFamilies {
				families[family] = true
			}
		}
		risk := 1 - math.Exp(-16*mass/255)
		confidence := math.Min(1, float64(count)/16) * math.Min(1, float64(len(families))/3)
		want := ASNContext{risk, confidence, policy.Weights[3] * confidence * risk, count > 0, uint8(min(len(families), 4))}
		if got := e.NeighborContext(addr); got != want {
			t.Fatalf("host %d got %#v want %#v", i, got, want)
		}
		subtracted := total - facts[addr].layer.Risk
		if 1-math.Exp(-16*subtracted/255) != risk {
			distinguishesSubtraction = true
		}
	}
	if !distinguishesSubtraction {
		t.Fatal("fixture failed to distinguish ordered omissions from subtraction")
	}
	if e.NeighborContext(v6) != (ASNContext{}) || e.NeighborContext(netip.MustParseAddr("192.0.3.7")) != (ASNContext{}) {
		t.Fatal("foreign block contributed")
	}
}
