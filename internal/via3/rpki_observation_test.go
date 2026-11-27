package via3

import (
	"context"
	"net/netip"
	"testing"
)

func TestRPKISnapshotStatusSurvivesExpiryWithOwnedClocks(t *testing.T) {
	for _, status := range []uint8{1, 2, 3} {
		prefix := netip.MustParsePrefix("203.0.113.0/24")
		maximum := uint8(0)
		if status == 1 {
			maximum = 24
		}
		input := CompileInput{Mode: "synthetic", Clock: 1700000000, ValidUntil: 1700003600, Partitions: []PartitionInput{{Partition: "all", PrefixRoutes: []netip.Prefix{prefix}, Records: []PublicRecord{
			{Version: 3, Kind: 4, Prefix: prefix, Network: &NetworkData{Origins: []uint32{13335}}},
			{Version: 3, Kind: 10, Prefix: prefix, Origins: &OriginsData{ASNs: []uint32{13335}}},
			{Version: 3, Kind: 9, Prefix: prefix, ASN: 13335, RPKI: &RPKIData{Status: status, MaximumLength: maximum, ObservedAt: 1699990000, ValidUntil: 1699993600}},
		}}}}
		built, err := Build(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		objects := map[string][]byte{}
		for _, object := range built.Objects {
			objects[object.Info.SHA256] = object.Bytes
			old := append([]byte(nil), object.Bytes...)
			p16(old, 6, 4)
			if _, err := Read(context.Background(), old); ErrorCode(err) != "version" {
				t.Fatal("schema4 accepted by schema6 reader", err)
			}
		}
		now := input.Clock
		reader, err := NewRelease(canonical(built.Pointer), canonical(built.Manifest), func(hash string) ([]byte, error) { return objects[hash], nil }, func() int64 { return now })
		if err != nil {
			t.Fatal(err)
		}
		for repeat := 0; repeat < 2; repeat++ {
			answer, err := reader.Lookup(context.Background(), "203.0.113.1")
			if err != nil || len(answer.BGP.RPKI) != 1 {
				t.Fatal(err, answer.BGP.RPKI)
			}
			got := answer.BGP.RPKI[0]
			if got.Status != []string{"", "valid", "invalid", "not_found"}[status] || got.ObservedAt == nil || *got.ObservedAt != 1699990000 || got.ValidUntil == nil || *got.ValidUntil != 1699993600 {
				t.Fatal("expired snapshot status/clocks were hidden or changed", got)
			}
			*got.ObservedAt, *got.ValidUntil = 1, 2
		}
		now = input.ValidUntil
		if _, err := reader.Lookup(context.Background(), "203.0.113.1"); ErrorCode(err) != "expired" {
			t.Fatal("RPKI retention extended whole-release eligibility", err)
		}
		old := built.Manifest
		old.SchemaVersion = 4
		if _, err := NewRelease(canonical(built.Pointer), canonical(old), nil, nil); ErrorCode(err) != "manifest" {
			t.Fatal("schema4 manifest accepted", err)
		}
	}
}

func TestRPKISnapshotClockStorageBounds(t *testing.T) {
	for _, tc := range []struct {
		name              string
		status            uint8
		observedAt, until uint64
		valid             bool
	}{
		{"expired_snapshot", 1, 1699990000, 1699993600, true},
		{"unknown", 0, 0, 0, true},
		{"maximum_safe", 3, 9007199254740990, 9007199254740991, true},
		{"known_missing_observation", 1, 0, 1699993600, false},
		{"known_missing_expiry", 2, 1699990000, 0, false},
		{"empty_interval", 3, 1699990000, 1699990000, false},
		{"reversed_interval", 1, 1699993600, 1699990000, false},
		{"unsafe_expiry", 1, 1699990000, 9007199254740992, false},
		{"unsafe_observation", 1, 9007199254740992, 9007199254740993, false},
		{"unknown_claims_clocks", 0, 1699990000, 1699993600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := make([]byte, 32)
			p32(row, 0, bits(20))
			p32(row, 4, 13335)
			row[8] = tc.status
			if tc.status == 1 {
				row[9] = 24
			}
			p64(row, 16, tc.observedAt)
			p64(row, 24, tc.until)
			shard := newShard(9, row)
			shard.set(1, prefixRows(key("203.0.113.0/24", false, 0)))
			_, err := Write(context.Background(), shard)
			if (err == nil) != tc.valid {
				t.Fatal("clock validation diverged", err)
			}
		})
	}
}
