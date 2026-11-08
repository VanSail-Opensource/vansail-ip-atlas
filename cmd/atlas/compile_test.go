package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vansail-ip-atlas/internal/via3"
)

func TestCompileFactsCommandRoundTrip(t *testing.T) {
	workspace := t.TempDir()
	input := filepath.Join(workspace, "facts.ndjson")
	if err := os.WriteFile(input, []byte(`{"Version":3,"Kind":5,"Prefix":"203.0.113.0/24","Usage":{"Type":1,"Assignment":1}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"compile-facts", "-workspace", workspace, "-input", input, "-clock", "1794096000"}); err != nil {
		t.Fatal(err)
	}
	reader, err := via3.OpenRelease(filepath.Join(workspace, "build-private/compiled-facts"), func() int64 { return 1794096000 })
	if err != nil {
		t.Fatal(err)
	}
	answer, err := reader.Lookup(context.Background(), "203.0.113.42")
	if err != nil || !answer.Synthetic || answer.Usage == nil || answer.Usage.Type != "residential" || answer.Quality != nil {
		t.Fatalf("typed synthetic facts changed: %v %+v", err, answer)
	}
}

func TestCompileFactsRejectsProductionAndAmbiguousJSON(t *testing.T) {
	for _, payload := range []string{
		`{"Version":3,"Kind":5,"kind":2,"Prefix":"203.0.113.0/24","Usage":{"Type":1}}`,
		`{"Version":3,"Kind":5,"Prefix":"203.0.113.0/24","Usage":{"Type":1,"type":4}}`,
		`{"Version":3,"Kind":5,"Prefix":"203.0.113.0/24","Usage":{"Type":1},"source_id":"must-never-survive"}`,
		`{"Version":3,"Kind":5,"Prefix":"203.0.113.0/24","Usage":{"Type":1}} {}`,
	} {
		workspace := t.TempDir()
		input := filepath.Join(workspace, "facts.ndjson")
		if err := os.WriteFile(input, []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		if err := run(context.Background(), []string{"compile-facts", "-workspace", workspace, "-input", input}); err == nil {
			t.Fatal("ambiguous or private input accepted")
		}
		if _, err := os.Stat(filepath.Join(workspace, "build-private/compiled-facts")); !os.IsNotExist(err) {
			t.Fatal("failed input left a candidate")
		}
	}
	if err := run(context.Background(), []string{"compile-facts", "-mode", "production", "-input", "absent"}); err == nil {
		t.Fatal("uncertified facts promoted to production")
	}
}
