// Verify the measured engineering mutation against its original rows after the timer stops.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"vansail-ip-atlas/internal/intelligence"
)

var mismatch = errors.New("warm row comparison failed")

// These closed stages are safe in the hosted diagnostic logs. The responsible
// source, object, path and underlying errors stay private.
var (
	readState      = errors.New("state-read")
	stateIdentity  = errors.New("state-identity")
	sourceIdentity = errors.New("source-identity")
	rowPopulation  = errors.New("row-population")
	originalObject = errors.New("original-object")
	mutatedObject  = errors.New("mutated-object")
	rowDifference  = errors.New("row-difference")
	changedCount   = errors.New("changed-count")
)

func state(path string) (intelligence.BuildState, error) {
	var s intelligence.BuildState
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return s, mismatch
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

type counts struct {
	Records  uint64 `json:"records"`
	Changed  uint64 `json:"changed"`
	Compared uint64 `json:"compared"`
}

func differing(ctx context.Context, root, out string, a, b intelligence.StoredSource, c *counts) error {
	x, y := a.RecordPartitions, b.RecordPartitions
	for len(x) > 0 && len(y) > 0 && x[0] == y[0] {
		x, y = x[1:], y[1:]
	}
	for len(x) > 0 && len(y) > 0 && x[len(x)-1] == y[len(y)-1] {
		x, y = x[:len(x)-1], y[:len(y)-1]
	}
	if len(x) == 0 && len(y) == 0 {
		return nil
	}
	a.RecordPartitions, b.RecordPartitions = x, y
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	rows := make(chan intelligence.NormalizedRecord, 32)
	done := make(chan error, 1)
	go func() {
		err := intelligence.WalkStoredSource(ctx, root, a, func(r intelligence.NormalizedRecord) error {
			select {
			case rows <- r:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		close(rows)
		done <- err
	}()
	err := intelligence.WalkStoredSource(ctx, out, b, func(r intelligence.NormalizedRecord) error {
		original, ok := <-rows
		if !ok {
			return mismatch
		}
		c.Compared++
		if original.Geo != nil && r.Geo != nil && original.Geo.City != r.Geo.City {
			want := "Benchmark mutation A"
			if original.Geo.City == want {
				want = "Benchmark mutation B"
			}
			if r.Geo.City != want {
				return mismatch
			}
			geo := *r.Geo
			geo.City = original.Geo.City
			r.Geo = &geo
			c.Changed++
		}
		if !reflect.DeepEqual(original, r) {
			return mismatch
		}
		return nil
	})
	if err != nil {
		cancel()
		<-done
		return err
	}
	if _, extra := <-rows; extra {
		cancel()
		<-done
		return mismatch
	}
	return <-done
}

func verifyPartitionedSourceMetadata(a, b intelligence.StoredSource) error {
	if len(a.Records) != 0 || len(b.Records) != 0 {
		return rowPopulation
	}
	// Streamed intake writes an empty inline slice. The isolated mutation
	// may serialize that empty slice as null after replacing its partitions.
	// Neither representation contains a row; compare the real metadata.
	a.Records, b.Records = nil, nil
	a.RecordPartitions, b.RecordPartitions = nil, nil
	if !reflect.DeepEqual(a, b) {
		return sourceIdentity
	}
	return nil
}

func inspect(root, out string) (counts, error) {
	var c counts
	ctx := context.Background()
	a, e := state(filepath.Join(root, ".atlas-private/state-v1.json"))
	if e != nil {
		return c, readState
	}
	b, e := state(filepath.Join(out, "benchmark-state.json"))
	if e != nil {
		return c, readState
	}
	if len(a.Sources) != 23 || len(a.Sources) != len(b.Sources) || a.Version != b.Version || a.PolicyHash != b.PolicyHash || !a.EvaluatedAt.Equal(b.EvaluatedAt) {
		return c, stateIdentity
	}
	for i, x := range a.Sources {
		y := b.Sources[i]
		p, q := x.RecordPartitions, y.RecordPartitions
		if e = verifyPartitionedSourceMetadata(x, y); e != nil {
			return c, e
		}
		var before, after uint64
		for _, v := range p {
			before += v.Records
		}
		for _, v := range q {
			after += v.Records
		}
		if before != after {
			return c, rowPopulation
		}
		c.Records += before
		if e = intelligence.VerifyStoredSourceObjects(ctx, root, x); e != nil {
			return c, originalObject
		}
		if e = intelligence.VerifyStoredSourceObjects(ctx, out, y); e != nil {
			return c, mutatedObject
		}
		if !slices.Equal(p, q) {
			if e = differing(ctx, root, out, x, y, &c); e != nil {
				return c, rowDifference
			}
		}
	}
	if c.Records == 0 || c.Changed != (c.Records+99)/100 {
		return c, changedCount
	}
	return c, nil
}
func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	c, e := inspect(os.Args[1], os.Args[2])
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(c) != nil {
		os.Exit(1)
	}
}
