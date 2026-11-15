package main

import (
	"context"
	"flag"
	"time"

	"vansail-ip-atlas/internal/via3"
)

func memoryProfile(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("memory-profile", flag.ContinueOnError)
	out := flags.String("out", "build-private/worker-profile", "standalone synthetic reader workload tree")
	report := flags.String("profile", ".atlas-private/worker-memory-profile.json", "private workload profile")
	clock := flags.Int64("clock", time.Now().UTC().Unix(), "evaluation clock, UTC Unix seconds")
	if err := flags.Parse(args); err != nil {
		return err
	}
	release, profile, err := via3.BuildMemoryProfile(ctx, *clock)
	if err != nil {
		return err
	}
	if err = release.Write(*out); err != nil {
		return err
	}
	return writeJSON(*report, profile)
}
