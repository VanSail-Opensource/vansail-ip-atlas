package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"time"

	"vansail-ip-atlas/internal/via3"
)

func main() {
	// These are the reviewed runner ceilings, not a whole-process RSS proof.
	debug.SetMemoryLimit(5120 << 20)
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signals, 35*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func writeJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".atlas-json-*.partial")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(b)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary, path)
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: atlas synthetic|compile-facts|compile-state|intake|lookup|inspect")
	}
	switch args[0] {
	case "compile-facts":
		return compileFacts(ctx, args[1:])
	case "compile-state":
		return compileState(ctx, args[1:])
	case "intake":
		return intakeSources(ctx, args[1:])
	case "synthetic":
		fs := flag.NewFlagSet("synthetic", flag.ContinueOnError)
		out := fs.String("out", "build-private/synthetic-atlas", "atlas tree destination")
		descriptor := fs.String("descriptor", "build-private/synthetic-descriptor.json", "private descriptor path")
		clock := fs.Int64("clock", time.Now().UTC().Unix(), "explicit evaluation clock, UTC Unix seconds")
		golden := fs.String("golden", "", "optional shared synthetic golden corpus JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		release, err := via3.Synthetic(ctx, *clock)
		if err != nil {
			return err
		}
		if err = release.Write(*out); err != nil {
			return err
		}
		if err = writeJSON(*descriptor, release.Descriptor); err != nil {
			return err
		}
		if *golden != "" {
			type object struct {
				Info   via3.ObjectInfo `json:"info"`
				Base64 string          `json:"base64"`
			}
			type vector struct {
				Q      string             `json:"q"`
				Answer via3.LookupAnswer  `json:"answer"`
				ClassC *via3.ClassCAnswer `json:"classC"`
			}
			type corpus struct {
				Clock    int64         `json:"clock"`
				Pointer  via3.Pointer  `json:"pointer"`
				Manifest via3.Manifest `json:"manifest"`
				Objects  []object      `json:"objects"`
				Vectors  []vector      `json:"vectors"`
			}
			c := corpus{Clock: *clock, Pointer: release.Pointer, Manifest: release.Manifest, Objects: []object{}, Vectors: []vector{}}
			for _, o := range release.Objects {
				c.Objects = append(c.Objects, object{Info: o.Info, Base64: base64.StdEncoding.EncodeToString(o.Bytes)})
			}
			reader, err := via3.OpenRelease(*out, func() int64 { return *clock })
			if err != nil {
				return err
			}
			for _, q := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.200", "203.0.114.1", "2001:db8::1", "::ffff:203.0.113.1", "AS13335", "AS15169", "8.8.8.8"} {
				answer, err := reader.Lookup(ctx, q)
				if err != nil {
					return err
				}
				cells, err := reader.ClassC(ctx, q)
				if err != nil {
					return err
				}
				c.Vectors = append(c.Vectors, vector{Q: q, Answer: answer, ClassC: cells})
			}
			if err = writeJSON(*golden, c); err != nil {
				return err
			}
		}
		fmt.Printf("synthetic release %s: %d objects; expires %d\n", release.Pointer.ReleaseID, len(release.Objects), release.Manifest.ValidUntil)
		return nil
	case "lookup":
		fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
		root := fs.String("root", "build-private/synthetic-atlas", "atlas tree")
		q := fs.String("q", "203.0.113.1", "literal IP or public ASN")
		clock := fs.Int64("clock", time.Now().UTC().Unix(), "UTC Unix seconds")
		classC := fs.Bool("class-c", false, "return bounded class C profile")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		reader, err := via3.OpenRelease(*root, func() int64 { return *clock })
		if err != nil {
			return err
		}
		if *classC {
			answer, err := reader.ClassC(ctx, *q)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(answer)
		}
		answer, err := reader.Lookup(ctx, *q)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(answer)
	case "inspect":
		fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
		file := fs.String("file", "", "one VIA3 file")
		dir := fs.String("dir", "", "directory, streamed NDJSON output")
		public := fs.Bool("public", false, "enforce deployed browser profile before decompression")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		paths := []string{}
		if *file != "" {
			paths = append(paths, *file)
		}
		if *dir != "" {
			entries, err := os.ReadDir(*dir)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".via3" {
					paths = append(paths, filepath.Join(*dir, entry.Name()))
				}
			}
		}
		sort.Strings(paths)
		if len(paths) == 0 {
			return fmt.Errorf("no VIA3 files")
		}
		for _, path := range paths {
			data, err := readInspectFile(ctx, path)
			if err != nil {
				return err
			}
			if *public && len(data) >= 64 && binary.LittleEndian.Uint64(data[36:44]) > via3.PublicObjectDecoded {
				return fmt.Errorf("resource_limit")
			}
			shard, err := via3.Read(ctx, data)
			if err != nil {
				return fmt.Errorf("invalid VIA3: %s", via3.ErrorCode(err))
			}
			if *public {
				if err := via3.ValidatePublicProfile(shard); err != nil {
					return err
				}
			}
			labels := []string{}
			if shard.Kind == 14 {
				offsets, _ := shard.Rows(5)
				text, _ := shard.Rows(6)
				for p := 0; p < len(offsets)-4; p += 4 {
					a, b := binary.LittleEndian.Uint32(offsets[p:p+4]), binary.LittleEndian.Uint32(offsets[p+4:p+8])
					labels = append(labels, string(text[a:b]))
				}
			}
			if err = json.NewEncoder(os.Stdout).Encode(struct {
				Kind    uint16   `json:"kind"`
				Strings []string `json:"strings"`
				Decoded uint64   `json:"decoded_bytes"`
			}{shard.Kind, labels, binary.LittleEndian.Uint64(data[36:44])}); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown command")
	}
}

// Check before opening: opening a FIFO can block before an fstat is possible.
// Recheck the opened identity as well; input trees are controlled build files,
// and symlink/device/directory inputs are never acceptable scanner payloads.
func openRegularInput(path string, maximum int64) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maximum {
		return nil, fmt.Errorf("bounded regular input required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("input unavailable")
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() > maximum || !os.SameFile(before, after) {
		file.Close()
		return nil, fmt.Errorf("input identity or resource limit")
	}
	return file, nil
}

type inputContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r inputContextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func readInspectFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openRegularInput(path, via3.MaxFile-1)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("input unavailable")
	}
	return readInspectBytes(ctx, file, info.Size())
}

func readInspectBytes(ctx context.Context, reader io.Reader, expectedSize int64) ([]byte, error) {
	if expectedSize < 0 || expectedSize >= via3.MaxFile {
		return nil, fmt.Errorf("length")
	}
	data, err := io.ReadAll(io.LimitReader(inputContextReader{ctx, reader}, via3.MaxFile))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != expectedSize || len(data) >= via3.MaxFile {
		return nil, fmt.Errorf("input changed or exceeds resource limit")
	}
	return data, nil
}
