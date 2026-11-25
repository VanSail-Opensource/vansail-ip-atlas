package pipeline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

// Two clusters require both direct binary and lookahead splits. The root
// record must preserve its complete payload as an overlay in every leaf.
func ownedPartitionFixture(t *testing.T, c *compiler) classifiedRun {
	t.Helper()
	path := c.next()
	w, err := c.newOwnedRunWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	write := func(p netip.Prefix, city string, exact bool) {
		f, err := c.newCanonicalRunFrame(via3.PublicRecord{Version: 3, Kind: 2, Prefix: p, Exact: exact, Geo: &via3.GeoData{Country: "US", City: city}})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.AppendCanonical(f); err != nil {
			t.Fatal(err)
		}
	}
	write(netip.MustParsePrefix("0.0.0.0/0"), "Root City", false)
	for i := 0; i < 96; i++ {
		a := netip.AddrFrom4([4]byte{11 + byte(i%2)*128, 0, byte(i), 0})
		write(netip.PrefixFrom(a, 24), "Local City", false)
		write(netip.PrefixFrom(a.Next(), 32), "Observed City", true)
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	runs, err := c.classify([]string{path})
	if err != nil || len(runs) != 1 {
		t.Fatal("classify", err)
	}
	return runs[0]
}

func TestOwnedPartitionRoutingAndOverlayParity(t *testing.T) {
	var wantObjects map[string]via3.ObjectInfo
	var wantRoutes []route
	for _, fast := range []bool{false, true} {
		c := proofMergeCompiler(t)
		c.output = t.TempDir()
		c.options.Limits.PartitionRecords = 10
		c.objects = map[string]via3.ObjectInfo{}
		var charged int
		if !fast {
			charged = ownedProofLimit - 8*ownedProofBuckets - 64
			if !c.runProofs.charge(charged) {
				t.Fatal("failed to force proof exhaustion")
			}
		}
		run := ownedPartitionFixture(t, c)
		if (c.runProofs.lookup(run.path) != nil) != fast {
			t.Fatal("classified input ownership did not propagate")
		}
		reader, err := c.openCompiledRun(run.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.next(); err != nil || reader.owner != nil || reader.record.Geo == nil || reader.record.Geo.City != "Root City" {
			t.Fatal("public leaf scan did not strictly reconstruct its payload", err)
		}
		if err := reader.file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := c.partition(run.path, run.scope); err != nil {
			t.Fatal(err)
		}
		if err := c.router(); err != nil {
			t.Fatal(err)
		}
		if err := c.encoder.Close(); err != nil {
			t.Fatal(err)
		}
		if c.runProofs.used != charged || len(c.routes) < 16 {
			t.Fatal("partition failed to split or retained proof charges")
		}
		if !fast {
			wantObjects, wantRoutes = c.objects, c.routes
		} else if !reflect.DeepEqual(c.objects, wantObjects) || !reflect.DeepEqual(c.routes, wantRoutes) {
			t.Fatal("proved partition changed public objects or routing")
		}
	}
}

func TestOwnedPartitionPlanningRequiresCaptureAndVerifiedEOF(t *testing.T) {
	c := proofMergeCompiler(t)
	run := ownedPartitionFixture(t, c)
	data, err := os.ReadFile(run.path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(run.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{false, true} {
		cap := &compiledPartitionCapture{inputPath: run.path, inputBytes: int64(len(data)), inputHash: sha256.Sum256(data), inputInfo: info}
		if !valid {
			cap.inputHash[0] ^= 1
		}
		c.compiledCaptures = []*compiledPartitionCapture{cap}
		r, err := c.openIntermediateRun(run.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.next(); err != nil || r.owner != c || r.record.Geo != nil {
			t.Fatal("classified metadata reader was not used", err)
		}
		if cap.inputVerified || !errors.Is(c.remove(run.path), errSpatialCache) {
			t.Fatal("read-ahead authorized an unconsumed capture")
		}
		for err == nil {
			err = r.next()
		}
		if valid && err != io.EOF || !valid && !errors.Is(err, errSpatialCache) || cap.inputVerified != valid {
			t.Fatal("segment verification bypassed the capture digest or logical EOF", err)
		}
		if err := r.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnedScatterFailureRetiresFinishedChildren(t *testing.T) {
	c := proofMergeCompiler(t)
	c.options.Limits.PartitionRecords = 4
	run := ownedPartitionFixture(t, c)
	scratch, proofCharge := c.used, c.runProofs.used
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	c.ctx = ctx
	firstChild := filepath.Join(c.scratch, fmt.Sprintf("run-%08d.bin", c.serial+1))
	c.options.scratchUsage = func(uint64) {
		if c.runProofs.lookup(firstChild) != nil {
			cancel()
		}
	}
	_, applied, err := c.scatterPartition(run.path, run.scope)
	if applied || !errors.Is(err, context.Canceled) {
		t.Fatal("fixture did not fail after its first child finished", err)
	}
	files, err := os.ReadDir(c.scratch)
	if err != nil || len(files) != 1 || files[0].Name() != filepath.Base(run.path) || c.used != scratch || c.runProofs.used != proofCharge || c.runProofs.lookup(run.path) == nil {
		t.Fatal("partial scatter changed its input or retained child files or proofs", err)
	}
}

func TestOwnedPartitionLeafVerifiesOriginalSegments(t *testing.T) {
	c := proofMergeCompiler(t)
	var paths []string
	for _, country := range []string{"US", "FR"} {
		f, err := c.newCanonicalRunFrame(via3.PublicRecord{Version: 3, Kind: 2, Prefix: netip.MustParsePrefix("8.0.0.0/8"), Geo: &via3.GeoData{Country: country}})
		if err != nil {
			t.Fatal(err)
		}
		runs, err := c.classify([]string{proofMergeOne(t, c, f)})
		if err != nil || len(runs) != 1 {
			t.Fatal("classify", err)
		}
		paths = append(paths, runs[0].path)
	}
	original, err := os.Stat(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	substitute, err := os.ReadFile(paths[1])
	if err != nil || original.Size() != int64(len(substitute)) {
		t.Fatal("fixture requires equally sized valid segments", err)
	}
	if err := os.WriteFile(paths[0], substitute, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := c.openCompiledRun(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer r.file.Close()
	if err := r.next(); !errors.Is(err, errOwnedRunProof) {
		t.Fatal("final leaf accepted a different valid segment", err)
	}
}

func TestOwnedScatterMustUseOriginalProofOnWritingPass(t *testing.T) {
	c := proofMergeCompiler(t)
	c.options.Limits.PartitionRecords = 10
	group := ownedPartitionFixture(t, c)
	before := c.used
	swapped := false
	c.options.externalScratch = func() uint64 {
		if !swapped {
			swapped = true
			c.runProofs.remove(group.path)
		}
		return 0
	}
	_, applied, err := c.scatterPartition(group.path, group.scope)
	if !swapped || applied || !errors.Is(err, errOwnedRunProof) || before != c.used {
		t.Fatal("scatter accepted a replacement input proof", swapped, applied, err)
	}
	if _, err := os.Stat(group.path); err != nil {
		t.Fatal(err)
	}
}
