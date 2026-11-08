package via3

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestSyntheticGraph24PreservesGoldenAnswersAndObservedAdjacency(t *testing.T) {
	baseline := golden(t)
	var expected goldenCorpus
	bytes, err := os.ReadFile("../../fixtures/bin/synthetic-graph24-via3.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes, &expected); err != nil {
		t.Fatal(err)
	}
	release, err := SyntheticGraph24(context.Background(), expected.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(release.Pointer, expected.Pointer) || !reflect.DeepEqual(release.Manifest, expected.Manifest) {
		t.Fatal("graph corpus is not deterministic")
	}
	reader := memoryRelease(t, expected, func() int64 { return expected.Clock })
	for _, vector := range baseline.Vectors {
		got, err := reader.Lookup(context.Background(), vector.Q)
		want := vector.Answer
		want.ReleaseID = release.Pointer.ReleaseID
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("graph fixture changed existing query %s: %v", vector.Q, err)
		}
	}
	answer, err := reader.Lookup(context.Background(), "AS424240")
	if err != nil || !answer.Synthetic || len(answer.BGP.Paths) != 12 {
		t.Fatalf("missing synthetic path population: %+v %v", answer, err)
	}
	nodes := map[uint32]bool{}
	edges := map[[2]uint32]bool{}
	for _, path := range answer.BGP.Paths {
		if path.Origin != 424240 || !path.GraphEligible || len(path.Segments) != 1 || path.Segments[0].Type != "sequence" || !reflect.DeepEqual(path.ASNs, path.Segments[0].ASNs) {
			t.Fatalf("fabricated route shape: %+v", path)
		}
		for i, asn := range path.ASNs {
			nodes[asn] = true
			if i > 0 {
				edges[[2]uint32{path.ASNs[i-1], asn}] = true
			}
		}
	}
	if len(nodes) != 24 || len(edges) != 23 {
		t.Fatalf("wrong 24-node tree population: nodes=%d edges=%d", len(nodes), len(edges))
	}
}
