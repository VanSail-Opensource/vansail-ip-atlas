package intelligence

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func retestPrefixEvidence() []Evidence {
	makeRow := func(text, family string, signal Signal, weight float64, at time.Time) Evidence {
		return Evidence{Prefix: netip.MustParsePrefix(text), Scope: ExplicitPrefix, Family: family, Signal: signal,
			Weight: weight, Current: true, SourcePublishedAt: at}
	}
	return []Evidence{
		makeRow("192.0.0.0/16", "test-a", "proxy", 90, clock()),
		makeRow("192.0.2.0/24", "test-a", "cloudflare_proxyip", 100, clock().Add(-time.Hour)),
		makeRow("192.0.2.0/25", "test-b", "fraud", 80, clock()),
		makeRow("::ffff:192.0.2.0/121", "test-c", "abuse", 65, clock()),
		makeRow("2001:db8::/32", "test-a", "proxy", 100, clock()),
		makeRow("2001:db8:1::/48", "test-b", "hosting", 45, clock()),
	}
}

func TestPreparedPrefixScoresMatchEveryAncestorAndCurrentClock(t *testing.T) {
	for _, now := range []time.Time{clock(), clock().Add(140 * time.Hour)} {
		evidence := append(retestPrefixEvidence(), riskEvidence("192.0.2.2", "test-host", "malware"))
		p := testPolicy(t)
		origins := []OriginMapping{{netip.MustParsePrefix("192.0.0.0/16"), []uint32{100, 13335}}, {netip.MustParsePrefix("192.0.2.0/24"), []uint32{100}}}
		base, err := NewEngine(p, evidence, coverage(), origins, now)
		if err != nil {
			t.Fatal(err)
		}
		prepared := *base
		cancelled, stop := context.WithCancel(t.Context())
		stop()
		if err := prepared.PreparePrefixScores(cancelled); !errors.Is(err, context.Canceled) || prepared.prefixScores != nil {
			t.Fatal("cancelled preparation was retained")
		}
		if err := prepared.PreparePrefixScores(t.Context()); err != nil || len(prepared.prefixScores) != len(prepared.prefix) {
			t.Fatal("exact prepared coverage differs", err)
		}
		for _, raw := range []string{"192.0.1.4", "192.0.2.0", "192.0.2.2", "192.0.2.200", "::ffff:192.0.2.2", "8.8.4.4", "2001:db8::1", "2001:db8:1::1", "2001:db9::1"} {
			address := netip.MustParseAddr(raw)
			before, errBefore := base.Lookup(address)
			got, errAfter := prepared.Lookup(address)
			if errBefore != nil || errAfter != nil || !reflect.DeepEqual(before, got) {
				t.Fatalf("%s changed current-clock scoring: before %#v after %#v, %v %v", raw, before, got, errBefore, errAfter)
			}
		}
		address := netip.MustParseAddr("192.0.1.4")
		owned := prepared.Origins(address)
		owned[0] = 1
		if actual := prepared.Origins(address); actual[0] != 100 {
			t.Fatal("the public API shared its immutable origin set")
		}
	}
}

func BenchmarkCurrentClockPrefixScoring(b *testing.B) {
	p := testPolicy(b)
	queries := make([]netip.Addr, 256)
	for i := range queries {
		queries[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	for _, entry := range []struct {
		name string
		fast bool
	}{{"ordinary", false}, {"prepared", true}} {
		b.Run(entry.name, func(b *testing.B) {
			e, err := NewEngine(p, retestPrefixEvidence(), nil, mapping(), clock())
			if err != nil {
				b.Fatal(err)
			}
			if entry.fast {
				if err := e.PreparePrefixScores(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				q, err := e.Lookup(queries[i%len(queries)])
				if err != nil || q.Score == nil {
					b.Fatal("active prefix score missing", err)
				}
			}
		})
	}
}
