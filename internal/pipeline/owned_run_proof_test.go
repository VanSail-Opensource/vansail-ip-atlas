package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type ownedRunShortWriter struct{}

func (ownedRunShortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func testOwnedRun(t *testing.T) (*compiler, string, *ownedRunWriter, ownedRunFrame) {
	t.Helper()
	c := &compiler{ctx: context.Background(), options: testOptions(t)}
	path := filepath.Join(c.options.Workspace, "run")
	w, err := c.newOwnedRunWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	f, err := c.newCanonicalRunFrame(sparseRunParityRows()[0])
	if err != nil {
		t.Fatal(err)
	}
	return c, path, w, f
}

func TestOwnedRunProofPublicationRequiresFinishedCanonicalWriter(t *testing.T) {
	for _, reason := range []string{"abort", "aborted-codec", "foreign", "oversize", "unproved", "short-write", "closed-file", "replaced-file", "cancel"} {
		t.Run(reason, func(t *testing.T) {
			c, path, w, frame := testOwnedRun(t)
			if err := w.AppendCanonical(frame); err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "abort":
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			case "aborted-codec":
				if err := w.codec.Close(); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				frame.owner = &compiler{}
				if err := w.AppendCanonical(frame); err == nil {
					t.Fatal("accepted a frame from another build")
				}
			case "oversize":
				c.options.Limits.RecordBytes = frame.row.logicalBytes - 1
				if err := w.AppendCanonical(frame); err == nil {
					t.Fatal("ignored the build record bound")
				}
			case "unproved":
				if err := w.AppendUnproved(frame.row); err != nil {
					t.Fatal(err)
				}
				if err := w.AppendCanonical(frame); err != nil {
					t.Fatal(err)
				}
			case "short-write":
				w.codec.output = ownedRunShortWriter{}
			case "closed-file":
				if err := w.file.Close(); err != nil {
					t.Fatal(err)
				}
			case "replaced-file":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				ctx, cancel := context.WithCancel(c.ctx)
				cancel()
				c.ctx = ctx
			}
			err := w.Finish()
			if (err == nil) != (reason == "unproved") {
				t.Fatal("unexpected finish result", err)
			}
			if w.Finish() == nil || c.runProofs.lookup(path) != nil || c.runProofs.used != 0 {
				t.Fatal("failed or unproved writer retained a proof")
			}
		})
	}
}

func TestOwnedRunProofRejectsSubstitutionTruncationAndReordering(t *testing.T) {
	c, path, w, frame := testOwnedRun(t)
	var frames bytes.Buffer
	// Force distinct, independently valid compressed segments on both sides
	// of a proof-block boundary. The ordinary writer also accepts partial
	// blocks. Production produces full blocks except for the final segment.
	for i := range ownedProofBlockLength + 2 {
		for range i + 1 {
			if err := w.AppendCanonical(frame); err != nil {
				t.Fatal(err)
			}
			if err := writeRunFrame(&frames, frame.row); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.codec.segment(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	p := c.runProofs.lookup(path)
	info, err := os.Stat(path)
	if p == nil || err != nil || p.checkFile(info) != nil {
		t.Fatal("finished run has no matching proof", err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(c.options.Workspace, "copy")
	if err := os.WriteFile(other, file, 0600); err != nil {
		t.Fatal(err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil || p.checkFile(otherInfo) == nil {
		t.Fatal("substituted inode accepted")
	}
	raw := file[len(privateRunMagic):]
	locate := func(start int) int {
		return start + privateRunSegmentHeader + int(binary.LittleEndian.Uint32(raw[start:]))
	}
	firstEnd := locate(0)
	secondEnd := locate(firstEnd)
	term := len(raw) - privateRunSegmentHeader
	data := bytes.Clone(raw)
	data[privateRunSegmentHeader] ^= 1
	inputs := map[string][]byte{
		"original":           raw,
		"valid-reordered":    bytes.Join([][]byte{raw[firstEnd:secondEnd], raw[:firstEnd], raw[secondEnd:]}, nil),
		"valid-duplicated":   bytes.Join([][]byte{raw[:term], raw[:firstEnd], raw[term:]}, nil),
		"valid-early-eof":    bytes.Join([][]byte{raw[:firstEnd], raw[term:]}, nil),
		"missing-terminator": raw[:term],
		"damaged-payload":    data,
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			r, err := newPrivateRunReader(bytes.NewReader(input))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err := r.attachProof(p); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if name == "original" {
				if err != nil || !bytes.Equal(got, frames.Bytes()) {
					t.Fatal("matching original run rejected or changed", err)
				}
			} else if name == "missing-terminator" {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("missing strict terminator accepted", err)
				}
			} else if !errors.Is(err, errOwnedRunProof) {
				t.Fatal("original segment proof did not reject altered run", err)
			}
			if (name == "valid-reordered" || name == "damaged-payload") && len(got) != 0 {
				t.Fatal("unverified first segment exposed")
			}
		})
	}
	r, err := newPrivateRunReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.attachProof(p); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	charged := c.runProofs.used
	c.runProofs.remove(path)
	if c.runProofs.lookup(path) != nil || c.runProofs.used != charged || charged <= 0 {
		t.Fatal("open reader lost its charged reference")
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal("pinned reader lost its original segment inventory", err)
	}
	r.Close()
	if c.runProofs.used != 0 {
		t.Fatal("closed reader retained proof storage")
	}
}

func TestOwnedRunProofCapacityFallsBackBeforeAllocation(t *testing.T) {
	c, path, w, frame := testOwnedRun(t)
	base := c.runProofs.used
	// An existing generation owns all remaining space. The writer must drop
	// its optional proof on the first segment and finish a normal strict run.
	c.runProofs.used = ownedProofLimit - 8*ownedProofBuckets - 64
	full := c.runProofs.used
	if err := w.AppendCanonical(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	if c.runProofs.lookup(path) != nil || c.runProofs.used != full-base {
		t.Fatal("an exhausted registry retained proof or corrupted the other owner's reservation")
	}
	reader, err := openRun(path, c.options.Limits.RecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.file.Close()
	if err := reader.next(); err != nil || !equalEncoded(frame.row, reader.row) {
		t.Fatal("strict reader could not read exhausted-registry output", err)
	}
	if err := reader.next(); !errors.Is(err, io.EOF) {
		t.Fatal("strict output has extra records", err)
	}
}
