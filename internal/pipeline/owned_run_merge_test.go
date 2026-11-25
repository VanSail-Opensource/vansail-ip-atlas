package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func proofMergeCompiler(t *testing.T) *compiler {
	t.Helper()
	return &compiler{ctx: context.Background(), options: Options{Limits: DefaultLimits()}, scratch: t.TempDir()}
}

func proofMergeOne(t *testing.T, c *compiler, frame ownedRunFrame) string {
	t.Helper()
	path := c.next()
	w, err := c.newOwnedRunWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.AppendCanonical(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOwnedIntermediateRunRefusesSubstitutionAndLateFailure(t *testing.T) {
	a := via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("8.0.0.0/8"), Geo: &via3.GeoData{Country: "US"}}
	b := a
	b.Geo = &via3.GeoData{Country: "FR"}
	for _, mode := range []string{"substituted", "raw", "late"} {
		t.Run(mode, func(t *testing.T) {
			c := proofMergeCompiler(t)
			frame, err := c.newCanonicalRunFrame(a)
			if err != nil {
				t.Fatal(err)
			}
			path := proofMergeOne(t, c, frame)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Clone(original)
			switch mode {
			case "substituted":
				frame, err = c.newCanonicalRunFrame(b)
				if err != nil {
					t.Fatal(err)
				}
				second := proofMergeOne(t, c, frame)
				changed, err = os.ReadFile(second)
				if err != nil || len(changed) != len(original) || bytes.Equal(changed, original) {
					t.Fatal("fixture requires distinct equally sized valid files", err)
				}
			case "raw":
				copy(changed[:4], "raww")
			case "late":
				changed[len(changed)-1] = 1
			}
			if err = os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			reader, err := c.openIntermediateRun(path)
			if err == nil {
				defer reader.file.Close()
				err = reader.next()
				if mode == "late" {
					if err != nil || reader.record.Kind != 2 {
						t.Fatal("fixture did not reach valid preceding record", err)
					}
					err = reader.next()
				}
			}
			if err == nil || err == io.EOF {
				t.Fatal("changed intermediate run was accepted")
			}
			_, err = c.mergeGroup([]string{path})
			if err == nil {
				t.Fatal("merged changed run")
			}
			// A failed merge may leave a temporary file for build cleanup but
			// must never install proof metadata for its output.
			if proof := c.runProofs.lookup(filepath.Join(c.scratch, fmt.Sprintf("run-%08d.bin", c.serial))); proof != nil {
				t.Fatal("failed merge retained its output proof")
			}
		})
	}
}

func TestOwnedMergeRequiresEveryInputProofIncludingDuplicates(t *testing.T) {
	c := proofMergeCompiler(t)
	r := sparseRunParityRows()[0]
	f, err := c.newCanonicalRunFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	a, b := proofMergeOne(t, c, f), proofMergeOne(t, c, f)
	c.runProofs.remove(b)
	merged, err := c.mergeGroup([]string{a, b})
	if err != nil || c.runProofs.lookup(merged) != nil {
		t.Fatal("mixed merge produced a proof", err)
	}
	reader, err := c.openIntermediateRun(merged)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.file.Close()
	if reader.owner != nil {
		t.Fatal("unproved merge entered metadata-only reader")
	}
	if err = reader.next(); err != nil || reader.row.key != f.row.key || !equalEncoded(reader.row, f.row) {
		t.Fatal("mixed merge changed output", err)
	}
	if err = reader.next(); err != io.EOF {
		t.Fatal("duplicate identity survived or EOF changed", err)
	}
}

func TestOwnedMergeRetainsStrictBytesAcrossFanInBoundaries(t *testing.T) {
	for _, n := range []int{17, 257} {
		c := proofMergeCompiler(t)
		var paths []string
		for i := 0; i < n; i++ {
			// Reverse the public identities to require interleaving across
			// multiple heap passes. Every initial one-row run is independently sealed.
			k := n - i
			r := via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{8, byte(k >> 8), byte(k), 0}), 24), Geo: &via3.GeoData{Country: "US"}}
			frame, err := c.newCanonicalRunFrame(r)
			if err != nil {
				t.Fatal(err)
			}
			paths = append(paths, proofMergeOne(t, c, frame))
		}
		path, err := c.merge(paths)
		if err != nil || c.runProofs.lookup(path) == nil {
			t.Fatal("multi-pass proof lost", err)
		}
		proved, err := c.openIntermediateRun(path)
		if err != nil {
			t.Fatal(err)
		}
		strict, err := openRun(path, c.options.Limits.RecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		previous := ""
		for i := 0; i < n; i++ {
			e1, e2 := proved.next(), strict.next()
			if e1 != nil || e2 != nil || proved.row.key <= previous || proved.row.key != strict.row.key || proved.row.logicalBytes != strict.row.logicalBytes || !equalEncoded(proved.row, strict.row) || strict.record.Geo == nil || proved.record.Geo != nil {
				t.Fatal("metadata path changed strict order, bytes, key or charge", i, e1, e2)
			}
			previous = proved.row.key
		}
		if proved.next() != io.EOF || strict.next() != io.EOF {
			t.Fatal("incomplete final merge")
		}
		proved.file.Close()
		strict.file.Close()
	}
}

func TestOwnedIntermediatePinsEvenBeforeReading(t *testing.T) {
	for _, empty := range []bool{false, true} {
		c := proofMergeCompiler(t)
		path := c.next()
		w, err := c.newOwnedRunWriter(path)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		if !empty {
			f, err := c.newCanonicalRunFrame(sparseRunParityRows()[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := w.AppendCanonical(f); err != nil {
				t.Fatal(err)
			}
		}
		if err = w.Finish(); err != nil {
			t.Fatal(err)
		}
		r, err := c.openIntermediateRun(path)
		if err != nil {
			t.Fatal(err)
		}
		charge := c.runProofs.used
		c.runProofs.remove(path)
		if charge <= 0 || charge != c.runProofs.used {
			t.Fatal("open reader lost its proof reservation before reading")
		}
		if !empty {
			if err = r.next(); err != nil {
				t.Fatal(err)
			}
		}
		if err = r.next(); err != io.EOF {
			t.Fatal(err)
		}
		if err = r.file.Close(); err != nil || c.runProofs.used != 0 {
			t.Fatal("closed retired reader retained metadata", err)
		}
	}
}
