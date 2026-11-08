package main

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func TestSniffDeclaredTextStaysText(t *testing.T) {
	if got := sniffTextKind([]byte("perso,1574\ndsl,3689\n"), "text"); got != "text-lines" {
		t.Fatalf("sniffTextKind(text) = %q, want text-lines", got)
	}
}

func TestTarEntrySampleSkipsMetadataAndEmptyFiles(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := map[string]string{
		"as/0/readme.txt":          "https://example.invalid/metadata-only\n",
		"as/1/aggregated.json":     `{"asn":1,"prefixes":{"ipv4":[]}}`,
		"as/2/ipv4-aggregated.txt": "# AS2\n#\n",
		"as/3/ipv4-aggregated.txt": "# AS3\n202.62.246.0/24\n",
	}
	for _, name := range []string{"as/0/readme.txt", "as/1/aggregated.json", "as/2/ipv4-aggregated.txt", "as/3/ipv4-aggregated.txt"} {
		content := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	got, entry, _, err := tarEntrySample(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if entry != "as/3/ipv4-aggregated.txt" || !strings.Contains(string(got), "202.62.246.0/24") {
		t.Fatalf("tarEntrySample() entry=%q content=%q", entry, got)
	}
}
