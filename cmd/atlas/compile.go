package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"vansail-ip-atlas/internal/pipeline"
	"vansail-ip-atlas/internal/via3"
)

// compile-facts exercises the bounded planner with already fused engineering
// facts. It cannot certify source evidence or create a production release.
func compileFacts(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("compile-facts", flag.ContinueOnError)
	workspace := fs.String("workspace", ".", "workspace containing private output")
	input := fs.String("input", "", "typed PublicRecord NDJSON file, at most 3 GiB")
	out := fs.String("out", "build-private/compiled-facts", "new private atlas destination")
	mode := fs.String("mode", "synthetic", "synthetic engineering facts only")
	clock := fs.Int64("clock", time.Now().UTC().Unix(), "UTC evaluation clock")
	until := fs.Int64("valid-until", 0, "synthetic validity bound, defaults to clock plus 720 hours")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode != "synthetic" {
		return errors.New("production_blocked: source-certified materialization and release gates are required")
	}
	if *input == "" || len(fs.Args()) != 0 {
		return errors.New("one explicit typed facts input is required")
	}
	file, err := openRegularInput(*input, 3<<30)
	if err != nil {
		return errors.New("facts input unavailable")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 3<<30 {
		return errors.New("facts input must be a regular file at most 3 GiB")
	}
	if *until == 0 {
		*until = *clock + 720*3600
	}
	destination := *out
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(*workspace, destination)
	}
	candidate, err := pipeline.Build(ctx, pipeline.Options{
		Workspace: *workspace, Output: destination, Mode: "synthetic", Clock: *clock, ValidUntil: *until,
		Limits: pipeline.DefaultLimits(),
	}, func(ctx context.Context, emit func(via3.PublicRecord) error) error {
		bounded := &io.LimitedReader{R: file, N: (3 << 30) + 1}
		scanner := bufio.NewScanner(bounded)
		scanner.Buffer(make([]byte, 64<<10), (8<<20)+1)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				return err
			}
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			if len(line) > 8<<20 || !utf8.Valid(line) || checkFactJSON(line) != nil {
				return errors.New("invalid bounded facts record")
			}
			decoder := json.NewDecoder(bytes.NewReader(line))
			decoder.DisallowUnknownFields()
			var record via3.PublicRecord
			if err := decoder.Decode(&record); err != nil {
				return errors.New("invalid typed facts record")
			}
			if err := emit(record); err != nil {
				return err
			}
		}
		if scanner.Err() != nil || bounded.N == 0 {
			return errors.New("facts input read or resource limit")
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("synthetic compiled facts %s: %d objects; %d records; production blocked\n", candidate.Pointer.ReleaseID, len(candidate.Manifest.Objects), candidate.Stats.UniqueRecords)
	return nil
}

// JSON decoding otherwise accepts duplicate and case-insensitively duplicated
// struct fields. Validate tokens before typed decoding; no generic record map
// survives parsing, and input contents never appear in error messages.
func checkFactJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 200000 {
			return errors.New("JSON resource limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make([]string, 0, 32)
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok || len(key) > 128 || len(keys) >= 64 {
					return errors.New("JSON object limit")
				}
				for _, previous := range keys {
					if strings.EqualFold(previous, key) {
						return errors.New("duplicate JSON key")
					}
				}
				keys = append(keys, key)
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for count := 0; decoder.More(); count++ {
				if count >= 65536 {
					return errors.New("JSON array limit")
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON token")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
