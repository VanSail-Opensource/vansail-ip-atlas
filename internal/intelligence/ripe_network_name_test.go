package intelligence

import (
	"strings"
	"testing"
)

func TestRIPENetworkNameGrammarNeedsNoLabelRewrite(t *testing.T) {
	check := func(name string, want bool) {
		t.Helper()
		if got := ValidRIPENetworkName(name); got != want {
			t.Fatalf("ValidRIPENetworkName(%q) = %t, want %t", name, got, want)
		}
		if want && SafeLabel(name) != name {
			t.Fatalf("grammar accepted a name that SafeLabel would rewrite: %q", name)
		}
	}
	for i := range 256 {
		b := byte(i)
		letter := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
		digit := b >= '0' && b <= '9'
		check(string([]byte{b}), letter)
		check(string([]byte{b, 'A'}), letter)
		check(string([]byte{'A', b, 'A'}), letter || digit || b == '-' || b == '_')
		check(string([]byte{'A', b}), letter || digit)
	}
	check(strings.Repeat("a", 128), true)
	check(strings.Repeat("a", 129), false)
	check("A001-RIPE", false)
	check("Z9-riPE", false)
	check("Region-RIPE", true)
	check("A34A-RIPE", true)
	check("A_b-1-RIPE", true)
	check("Cafe\u0301", false)
	check("North\u202ewest", false)
}

func FuzzRIPENetworkNameGrammarAlreadySafe(f *testing.F) {
	for _, name := range []string{"A", "TEST-NETWORK-2", "fibre_BACKBONE9", "AA123-RIPE", "a.EU", "Cafe\u0301", "test\x00name", "registry:network", strings.Repeat("a", 128)} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if ValidRIPENetworkName(name) && SafeLabel(name) != name {
			t.Fatalf("accepted a name requiring label filtering: %q", name)
		}
	})
}

func BenchmarkRIPENetworkNameGrammar(b *testing.B) {
	names := [...]string{"Fibre-Backbone-West", "CABLE_SUBSCRIBER_AS1", "V6-Outreach-Network", "A123-RIPE"}
	for _, withLabel := range []bool{false, true} {
		label := "grammar-only"
		if withLabel {
			label = "previous-with-label-filter"
		}
		b.Run(label, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				name := names[i%len(names)]
				valid := (!withLabel || SafeLabel(name) == name) && ValidRIPENetworkName(name)
				if valid != (i%len(names) != len(names)-1) {
					b.Fatal("unexpected validation result")
				}
			}
		})
	}
}
