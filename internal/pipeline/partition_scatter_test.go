package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func scatterFixture(t *testing.T, rows []via3.PublicRecord) (*compiler, string) {
	t.Helper()
	limits := DefaultLimits()
	limits.PartitionRecords = 8
	limits.PartitionBytes = 8192
	c := &compiler{ctx: context.Background(), options: Options{Limits: limits}, scratch: t.TempDir()}
	path := c.next()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var size partitionSize
	for _, row := range rows {
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.writeRecord(file, data); err != nil {
			t.Fatal(err)
		}
		size.records++
		size.bytes += int64(len(data)) + 512
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	c.rememberPartitionSize(path, size)
	return c, path
}

func partitionFrameMap(t *testing.T, c *compiler, path string, s scope, useScatter bool) map[string][]string {
	t.Helper()
	result := map[string][]string{}
	var walk func(string, scope)
	walk = func(path string, s scope) {
		if !c.partitionFits(c.partitionSizes[path]) {
			if useScatter {
				runs, applied, err := c.scatterPartition(path, s)
				if err != nil {
					t.Fatal(err)
				}
				if applied {
					for _, run := range runs {
						walk(run.path, run.scope)
					}
					return
				}
			}
			left, right, err := s.children()
			if err != nil {
				t.Fatal(err)
			}
			scopes := [2]scope{left, right}
			paths, err := c.split(path, &scopes)
			if err != nil {
				t.Fatal(err)
			}
			for i, path := range paths {
				if path != "" {
					walk(path, scopes[i])
				}
			}
			return
		}
		r, err := openRun(path, c.options.Limits.RecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer r.file.Close()
		for {
			if err := r.next(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			result[s.name()] = append(result[s.name()], string(r.row.data))
		}
	}
	walk(path, s)
	for _, rows := range result {
		sort.Strings(rows)
	}
	return result
}

func TestScatterPrefixSlotsMatchBinaryScopesAcrossByteBoundaries(t *testing.T) {
	for _, addr := range []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8:1234:5678::9")} {
		ceiling := addr.BitLen()
		if addr.Is4() {
			ceiling = 24
		}
		for bits := 0; bits <= ceiling; bits++ {
			parent := scope{prefix: netip.PrefixFrom(addr, bits).Masked()}
			tree := scatterTree(parent, 0)
			bins := newScatterPrefixes(tree)
			if bins == nil {
				if bits+4 <= ceiling {
					t.Fatal("missing full-width scatter", parent.prefix)
				}
				continue
			}
			if _, ok := bins.slot(parent.prefix); ok {
				t.Fatal("parent overlay lost", parent.prefix)
			}
			for want := 0; want < 16; want++ {
				leaf := tree
				for bit := 3; bit >= 0; bit-- {
					leaf = leaf.children[want>>bit&1]
				}
				for _, prefix := range []netip.Prefix{leaf.prefix, netip.PrefixFrom(leaf.prefix.Addr(), addr.BitLen())} {
					if got, ok := bins.slot(prefix); !ok || got != want {
						t.Fatal("slot differs from binary scope", parent.prefix, prefix, got, want)
					}
				}
			}
		}
	}
}

func TestPublicScatterPreservesBinaryFirstFitAndInheritedBytes(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6", "ASN"} {
		t.Run(family, func(t *testing.T) {
			var rows []via3.PublicRecord
			root := scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}
			for i := 0; i < 80; i++ {
				switch family {
				case "IPv4":
					prefix := netip.MustParsePrefix(fmt.Sprintf("11.0.%d.0/24", i))
					rows = append(rows, via3.PublicRecord{Version: 3, Kind: 2, Prefix: prefix, Geo: &via3.GeoData{Country: "US"}}, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.PrefixFrom(prefix.Addr().Next(), 32), Exact: true, Geo: &via3.GeoData{Country: "DE"}})
				case "IPv6":
					root.prefix = netip.MustParsePrefix("::/0")
					rows = append(rows, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i)), Geo: &via3.GeoData{Country: "US"}})
				case "ASN":
					root = scope{asn: true, last: ^uint32(0)}
					rows = append(rows, via3.PublicRecord{Version: 3, Kind: 8, ASN: 13300 + uint32(i), ASNAggregate: &via3.ASNData{Name: "Synthetic Network"}})
				}
			}
			if family == "IPv4" {
				rows = append(rows, via3.PublicRecord{Version: 3, Kind: 3, Prefix: netip.MustParsePrefix("11.0.0.0/8"), Coordinates: &via3.CoordinateData{Unknown: true}}, via3.PublicRecord{Version: 3, Kind: 7, Prefix: netip.MustParsePrefix("11.0.0.0/24"), Profile: &via3.ProfileData{}})
			} else if family == "IPv6" {
				rows = append(rows, via3.PublicRecord{Version: 3, Kind: 3, Prefix: netip.MustParsePrefix("2001:db8::/32"), Coordinates: &via3.CoordinateData{Unknown: true}})
			}
			old, oldPath := scatterFixture(t, rows)
			current, path := scatterFixture(t, rows)
			want := partitionFrameMap(t, old, oldPath, root, false)
			got := partitionFrameMap(t, current, path, root, true)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scatter changed scopes or canonical inherited bytes: got %d scopes, want %d", len(got), len(want))
			}
		})
	}
}

func TestPublicScatterFallbackAndCancellationDoNotMutateInput(t *testing.T) {
	var rows []via3.PublicRecord
	for i := 0; i < 80; i++ {
		rows = append(rows, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("%d.0.%d.0/24", 11+134*(i%2), i)), Geo: &via3.GeoData{Country: "US"}})
	}
	root := scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}
	for _, mode := range []string{"budget", "cancel", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			c, path := scatterFixture(t, rows)
			before := c.used
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "budget":
				c.options.Limits.ScratchBytes = c.used
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				c.ctx = ctx
			case "metadata":
				size := c.partitionSizes[path]
				size.records++
				c.partitionSizes[path] = size
			}
			_, applied, err := c.scatterPartition(path, root)
			if applied || mode == "budget" && err != nil || mode != "budget" && err == nil || mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("scatter fallback/failure changed", applied, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(original) || c.used != before {
				t.Fatal("failed planning changed the owned input or accounting", err)
			}
			files, err := os.ReadDir(c.scratch)
			if err != nil || len(files) != 1 {
				t.Fatal("planning failure created files", err)
			}
		})
	}
}

func TestPublicScatterSecondPassFailureCleansOnlyOwnedChildren(t *testing.T) {
	var rows []via3.PublicRecord
	for i := 0; i < 80; i++ {
		rows = append(rows, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("%d.0.%d.0/24", 11+134*(i%2), i)), Geo: &via3.GeoData{Country: "US"}})
	}
	for _, mode := range []string{"mutation", "new-prefix", "cancel_write", "collision"} {
		t.Run(mode, func(t *testing.T) {
			c, path := scatterFixture(t, rows)
			before := c.used
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var collision string
			called := false
			if mode == "cancel_write" {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				c.ctx = ctx
				c.options.scratchUsage = func(used uint64) {
					if used > before {
						called = true
						cancel()
					}
				}
			} else {
				c.options.externalScratch = func() uint64 {
					if !called {
						called = true
						if mode == "mutation" || mode == "new-prefix" {
							from, to := `"US"`, `"DE"`
							if mode == "new-prefix" {
								from, to = `"11.0.`, `"75.0.`
							}
							changed := bytes.Replace(original, []byte(from), []byte(to), 1)
							if bytes.Equal(original, changed) {
								t.Fatal("fixture did not mutate the original")
							}
							original = changed
							if err := os.WriteFile(path, original, 0600); err != nil {
								t.Fatal(err)
							}
						} else {
							collision = filepath.Join(c.scratch, fmt.Sprintf("run-%08d.bin", c.serial+1))
							if err := os.WriteFile(collision, []byte("not owned by scatter"), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
					return 0
				}
			}
			_, applied, err := c.scatterPartition(path, scope{prefix: netip.MustParsePrefix("0.0.0.0/0")})
			if !called || applied || err == nil || mode == "cancel_write" && !errors.Is(err, context.Canceled) {
				t.Fatal("second-pass failure not observed", called, applied, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, original) || c.used != before || len(c.partitionSizes) != 1 {
				t.Fatal("failed scatter lost parent or retained child accounting", err)
			}
			files, err := os.ReadDir(c.scratch)
			wantFiles := 1
			if collision != "" {
				wantFiles++
				if data, err := os.ReadFile(collision); err != nil || string(data) != "not owned by scatter" {
					t.Fatal("failed exclusive create removed an unowned file", err)
				}
			}
			if err != nil || len(files) != wantFiles {
				t.Fatal("failed scatter retained owned child files", err, len(files))
			}
		})
	}
}

func TestPublicScatterLeavesFittingUnaryRunsToBinaryRepack(t *testing.T) {
	var rows []via3.PublicRecord
	for i := 0; i < 8; i++ {
		rows = append(rows, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("11.0.%d.0/24", i)), Geo: &via3.GeoData{Country: "US"}})
	}
	c, path := scatterFixture(t, rows)
	c.options.Limits.ObjectBytes = 1024
	root := scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}
	if _, applied, err := c.scatterPartition(path, root); err != nil || applied {
		t.Fatal("logical fit must retain the ordinary binary-size repack path", applied, err)
	}
	left, right, err := root.children()
	if err != nil {
		t.Fatal(err)
	}
	scopes := [2]scope{left, right}
	paths, err := c.split(path, &scopes)
	if err != nil || paths[0] == "" || paths[1] != "" || scopes[0].prefix != netip.MustParsePrefix("11.0.0.0/21") {
		t.Fatal("ordinary fitting unary-child scope changed", scopes, err)
	}
}

func TestPublicScatterUnaryHandoffReusesExactRunAndBinaryScope(t *testing.T) {
	var rows []via3.PublicRecord
	for i := 0; i < 80; i++ {
		// Both /4 lookahead children are populated, while the first binary
		// child is unary. Its original jump is the common 0.0.0.0/3 scope.
		rows = append(rows, via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix(fmt.Sprintf("%d.0.%d.0/24", 11+12*(i%2), i)), Geo: &via3.GeoData{Country: "US"}})
	}
	c, path := scatterFixture(t, rows)
	before, total, serial := c.used, c.partitionSizes[path], c.serial
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The handoff requires no extra scratch reservation or writer at all.
	c.options.Limits.ScratchBytes = c.used
	c.options.externalScratch = func() uint64 { t.Fatal("unary handoff must not prepare a rewrite"); return 0 }
	runs, applied, err := c.scatterPartition(path, scope{prefix: netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil || !applied || len(runs) != 1 || runs[0].path != path || runs[0].prefix != netip.MustParsePrefix("0.0.0.0/3") {
		t.Fatal("unary handoff changed the ordinary binary scope", runs, applied, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) || c.used != before || c.serial != serial || c.partitionSizes[path] != total {
		t.Fatal("unary handoff rewrote or changed ownership of the immutable run", err)
	}
}

func TestScatterRejectsModifiedOwnedRunAfterPlanning(t *testing.T) {
	for _, writerPlan := range []bool{false, true} {
		t.Run(fmt.Sprint(writerPlan), func(t *testing.T) { testScatterRejectsModifiedOwnedRunAfterPlanning(t, writerPlan) })
	}
}

func testScatterRejectsModifiedOwnedRunAfterPlanning(t *testing.T, writerPlan bool) {
	t.Helper()
	c := proofMergeCompiler(t)
	c.options.Limits.PartitionRecords = 8
	root := scope{prefix: netip.MustParsePrefix("0.0.0.0/0")}
	path := c.next()
	w, err := c.newOwnedRunWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if writerPlan {
		w.enablePartitionPlan(root)
	}
	var size partitionSize
	for i := 0; i < 32; i++ {
		addr := netip.AddrFrom4([4]byte{byte(16 + 4*i), 0, 0, 0})
		record := via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.PrefixFrom(addr, 24), Geo: &via3.GeoData{Country: "US"}}
		frame, err := c.newCanonicalRunFrame(record)
		if err != nil {
			t.Fatal(err)
		}
		if err = w.appendPartitionFrame(frame, record); err != nil {
			t.Fatal(err)
		}
		size.records++
		size.bytes += frame.row.logicalBytes + 512
	}
	if err = w.Finish(); err != nil {
		t.Fatal(err)
	}
	if p := c.runProofs.lookup(path); p == nil || (p.scatter != nil) != writerPlan {
		t.Fatal("fixture did not produce the expected owned plan state")
	}
	c.rememberPartitionSize(path, size)
	before := c.used
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	c.options.externalScratch = func() uint64 {
		if !changed {
			changed = true
			data[len(data)/2] ^= 1
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return 0
	}
	_, applied, err := c.scatterPartition(path, root)
	if !changed || err == nil || applied || c.used != before {
		t.Fatalf("changed=%v applied=%v err=%v scratch=%d, was %d", changed, applied, err, c.used, before)
	}
	remaining, err := os.ReadDir(c.scratch)
	if err != nil || len(remaining) != 1 || remaining[0].Name() != filepath.Base(path) {
		t.Fatal("could not isolate failure to owned parent", remaining, err)
	}
}

func TestOwnedScatterPlansKeepBinaryScopesAndBytes(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6", "ASN"} {
		t.Run(family, func(t *testing.T) {
			root := scope{prefix: netip.MustParsePrefix("0.0.0.0/0"), group: locationFacts}
			if family == "IPv6" {
				root.prefix = netip.MustParsePrefix("::/0")
			} else if family == "ASN" {
				root = scope{asn: true, last: ^uint32(0), group: aggregateFacts}
			}
			var records []via3.PublicRecord
			if !root.asn {
				records = append(records, via3.PublicRecord{Version: 3, Kind: 2, Prefix: root.prefix, Geo: &via3.GeoData{Country: "CA"}})
			}
			for i := range 160 {
				var r via3.PublicRecord
				switch family {
				case "IPv4":
					p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i*37 + 17), 120, byte(i), 0}), 24)
					if i%7 == 0 {
						p = netip.PrefixFrom(p.Addr(), 8).Masked()
					}
					r = via3.PublicRecord{Version: 3, Kind: 2, Prefix: p, Geo: &via3.GeoData{Country: "US"}}
				case "IPv6":
					p := netip.PrefixFrom(netip.AddrFrom16([16]byte{byte(i*37 + 17), 1, 1, byte(i)}), 32)
					if i%7 == 0 {
						p = netip.PrefixFrom(p.Addr(), 8).Masked()
					}
					r = via3.PublicRecord{Version: 3, Kind: 2, Prefix: p, Geo: &via3.GeoData{Country: "US"}}
				case "ASN":
					r = via3.PublicRecord{Version: 3, Kind: 8, ASN: uint32(300000+i) + 2200000000*uint32(i%2), ASNAggregate: &via3.ASNData{Name: "Synthetic Network"}}
				}
				records = append(records, r)
			}
			fixture := func(withPlan bool) (*compiler, string) {
				t.Helper()
				c := proofMergeCompiler(t)
				c.options.Limits.PartitionRecords = 8
				path := c.next()
				writer, err := c.newOwnedRunWriter(path)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				if withPlan {
					writer.enablePartitionPlan(root)
				}
				var size partitionSize
				for _, r := range records {
					frame, err := c.newCanonicalRunFrame(r)
					if err != nil {
						t.Fatal(err)
					}
					if err := writer.appendPartitionFrame(frame, r); err != nil {
						t.Fatal(err)
					}
					size.records++
					size.bytes += frame.row.logicalBytes + 512
				}
				if err := writer.Finish(); err != nil {
					t.Fatal(err)
				}
				c.rememberPartitionSize(path, size)
				if proof := c.runProofs.lookup(path); proof == nil || (proof.scatter != nil) != withPlan {
					t.Fatal("unexpected producer-side plan")
				}
				return c, path
			}
			old, oldPath := fixture(false)
			current, path := fixture(true)
			want := partitionFrameMap(t, old, oldPath, root, false)
			got := partitionFrameMap(t, current, path, root, true)
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("preplanning changed the binary first-fit geometry or canonical rows (%d versus %d leaves)", len(got), len(want))
			}
		})
	}
}
