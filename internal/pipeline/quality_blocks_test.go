package pipeline

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestQualityBlockDefaultPreservesEveryExactAndDifferentValue(t *testing.T) {
	block := netip.MustParsePrefix("192.0.2.0/24")
	zero := 0.0
	score := uint8(0)
	common := &via3.QualityData{}
	variants := []*via3.QualityData{
		{Score: &score}, {Confidence: 1}, {Reasons: 1}, {Assessed: [4]bool{true}}, {CoverageComplete: true},
		{Exact: &zero}, {Prefix: &zero}, {ASN: &zero}, {Neighbors: &zero},
	}
	var output []via3.PublicRecord
	w := qualityBlockWriter{scope: block, emit: func(r via3.PublicRecord) error { output = append(output, r); return nil }}
	want := make(map[netip.Prefix]*via3.QualityData)
	exacts := make(map[netip.Prefix]bool)
	expectedCount := 1
	for i := 0; i < 256; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32)
		data := common
		if i%10 == 0 {
			data = variants[i/10%len(variants)]
		}
		exact := i%23 == 0
		want[p] = data
		exacts[p] = exact
		if exact || data != common {
			expectedCount++
		}
		if err := w.write(p, exact, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.flush(); err != nil {
		t.Fatal(err)
	}
	if len(output) != expectedCount || output[0].Prefix != block || output[0].Exact {
		t.Fatalf("invalid default or exceptions: records=%d", len(output))
	}
	for p, data := range want {
		matched := -1
		var value *via3.QualityData
		seenExact := false
		for _, r := range output {
			if r.Exact && r.Prefix == p {
				seenExact = true
			}
			if r.Prefix.Contains(p.Addr()) && r.Prefix.Bits() > matched {
				matched = r.Prefix.Bits()
				value = r.Quality
			}
		}
		if !reflect.DeepEqual(value, data) || seenExact != exacts[p] {
			t.Fatalf("changed fact at %v", p)
		}
	}
}

func TestQualityBlockNeedsCompleteDisjointCoverageAndAnExact(t *testing.T) {
	input := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/25"), netip.MustParsePrefix("192.0.2.128/26"), netip.MustParsePrefix("192.0.2.192/27"), netip.MustParsePrefix("192.0.2.255/32")}
	write := func(prefixes []netip.Prefix, exact bool, scope netip.Prefix) []via3.PublicRecord {
		t.Helper()
		var out []via3.PublicRecord
		w := qualityBlockWriter{scope: scope, emit: func(r via3.PublicRecord) error { out = append(out, r); return nil }}
		for _, p := range prefixes {
			if err := w.write(p, exact && p.Bits() == p.Addr().BitLen(), &via3.QualityData{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.flush(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// This complete block does qualify with an unrestricted owner. A sub-/24
	// owner must never synthesize a default across its boundary.
	complete := append([]netip.Prefix(nil), input[:3]...)
	for addr := 224; addr < 256; addr++ {
		complete = append(complete, netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(addr)}), 32))
	}
	if got := write(complete, true, netip.Prefix{}); len(got) >= len(complete) {
		t.Fatal("fixture failed to qualify in complete scope")
	}
	for _, tc := range []struct {
		prefixes []netip.Prefix
		exact    bool
		scope    netip.Prefix
	}{
		{input, true, netip.Prefix{}},
		{[]netip.Prefix{input[0], input[1], input[2], netip.MustParsePrefix("192.0.2.224/27")}, false, netip.Prefix{}},
		{complete, true, input[0]},
		{[]netip.Prefix{netip.MustParsePrefix("2001:db8::/127"), netip.MustParsePrefix("2001:db8::2/128")}, true, netip.Prefix{}},
	} {
		out := write(tc.prefixes, tc.exact, tc.scope)
		if len(out) != len(tc.prefixes) {
			t.Fatal("unexpected coarsening")
		}
		for i, p := range tc.prefixes {
			if out[i].Prefix != p {
				t.Fatalf("changed uncovered scope %v", p)
			}
		}
	}
	rejected := errors.New("sink rejected")
	writer := qualityBlockWriter{emit: func(via3.PublicRecord) error { return rejected }}
	for _, p := range input {
		if err := writer.write(p, false, &via3.QualityData{}); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(writer.flush(), rejected) {
		t.Fatal("sink failure lost")
	}
}
