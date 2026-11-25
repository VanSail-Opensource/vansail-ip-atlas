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
func inspect(root, out string) (counts, error) {
	var c counts
	ctx := context.Background()
	a, e := state(filepath.Join(root, ".atlas-private/state-v1.json"))
	if e != nil {
		return c, e
	}
	b, e := state(filepath.Join(out, "benchmark-state.json"))
	if e != nil {
		return c, e
	}
	if len(a.Sources) != 23 || len(a.Sources) != len(b.Sources) || a.Version != b.Version || a.PolicyHash != b.PolicyHash || !a.EvaluatedAt.Equal(b.EvaluatedAt) {
		return c, mismatch
	}
	for i, x := range a.Sources {
		y := b.Sources[i]
		p, q := x.RecordPartitions, y.RecordPartitions
		if len(x.Records) != 0 || len(y.Records) != 0 {
			return c, mismatch
		}
		x.RecordPartitions, y.RecordPartitions = nil, nil
		if !reflect.DeepEqual(x, y) {
			return c, mismatch
		}
		x.RecordPartitions, y.RecordPartitions = p, q
		var before, after uint64
		for _, v := range p {
			before += v.Records
		}
		for _, v := range q {
			after += v.Records
		}
		if before != after {
			return c, mismatch
		}
		c.Records += before
		if e = intelligence.VerifyStoredSourceObjects(ctx, root, x); e != nil {
			return c, e
		}
		if e = intelligence.VerifyStoredSourceObjects(ctx, out, y); e != nil {
			return c, e
		}
		if !slices.Equal(p, q) {
			if e = differing(ctx, root, out, x, y, &c); e != nil {
				return c, e
			}
		}
	}
	if c.Records == 0 || c.Changed != (c.Records+99)/100 {
		return c, mismatch
	}
	return c, nil
}
func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	c, e := inspect(os.Args[1], os.Args[2])
	if e != nil {
		fmt.Fprintln(os.Stderr, "Engineering row comparison failed")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(c) != nil {
		os.Exit(1)
	}
}
