package intelligence

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestRoutedExactRiskStreamMatchesOrdinaryEngine(t *testing.T) {
	p := testPolicy(t)
	now := clock()
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	origins := []OriginMapping{{Prefix: prefix, Origins: []uint32{15169, 13335, 15169}}, {Prefix: netip.MustParsePrefix("203.0.113.128/25"), Origins: []uint32{13335}}}
	rows := []Evidence{riskEvidence("203.0.113.129", "a", "malware"), riskEvidence("198.51.100.1", "outside", "malware"), riskEvidence("203.0.113.3", "b", "proxy"), riskEvidence("203.0.113.3", "a", "malware"), riskEvidence("203.0.113.3", "a", "malware"), riskEvidence("203.0.113.5", "old", "malware")}
	rows[0].SubscriptionLiteral = true
	rows[4].Weight = 25
	rows[5].ItemPublishedAt = now.Add(-p.MaxAge)
	type event struct {
		addr     netip.Addr
		risk     uint64
		families []string
		origins  []uint32
	}
	for _, at := range []time.Time{now, now.Add(2 * time.Hour), now.Add(p.SubscriptionAge), now.Add(p.MaxAge)} {
		var expected, got []event
		capture := func(dest *[]event) func(netip.Addr, float64, []string, []uint32) error {
			return func(a netip.Addr, r float64, f []string, o []uint32) error {
				if len(o) > 0 {
					*dest = append(*dest, event{a, math.Float64bits(r), f, o})
				}
				return nil
			}
		}
		e, err := NewEngine(p, rows, nil, origins, at)
		if err != nil {
			t.Fatal(err)
		}
		if err = e.WalkExactRisks(context.Background(), capture(&expected)); err != nil {
			t.Fatal(err)
		}
		if err = WalkRoutedExactRisks(context.Background(), p, rows, origins, at, capture(&got)); err != nil || !reflect.DeepEqual(expected, got) {
			t.Fatal("changed score, family, MOAS mapping or canonical order", err)
		}
	}
	stop := errors.New("stopped")
	sink := func(netip.Addr, float64, []string, []uint32) error { return stop }
	if err := WalkRoutedExactRisks(context.Background(), p, rows, origins, now, sink); !errors.Is(err, stop) {
		t.Fatal("lost sink failure", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WalkRoutedExactRisks(ctx, p, rows, origins, now, sink); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	invalid := rows[0]
	invalid.SourcePublishedAt = now.Add(48 * time.Hour)
	if err := WalkRoutedExactRisks(context.Background(), p, []Evidence{invalid}, origins, now, sink); err == nil || errors.Is(err, stop) {
		t.Fatal("future observation bypassed admission", err)
	}
	invalid = rows[0]
	invalid.Scope = ExplicitPrefix
	if err := WalkRoutedExactRisks(context.Background(), p, []Evidence{invalid}, origins, now, sink); err == nil || errors.Is(err, stop) {
		t.Fatal("unrelated evidence accepted", err)
	}
}
