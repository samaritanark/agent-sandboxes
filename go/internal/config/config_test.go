package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestUpsertYAMLScalar(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "c.yaml")
	if err := UpsertYAMLScalar(p, "k", "v"); err != nil {
		t.Fatal(err)
	}
	UpsertYAMLScalar(p, "other", "o")
	UpsertYAMLScalar(p, "k", `a\nb`)
	b, _ := os.ReadFile(p)
	if string(b) != "k: a\\nb\nother: o\n" {
		t.Fatalf("got %q", b)
	}
}

func TestExtractYAMLListQuirks(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(f, []byte("masked_paths:\n- a.txt # c\n-n\n  -n\n- \"b c/\"\nnext:\n  - z\n"), 0o644)
	got := ExtractYAMLList(f, "masked_paths")
	if fmt.Sprint(got) != "[a.txt n b c/]" {
		t.Fatalf("got %q", got)
	}
	if ExtractYAMLList(filepath.Join(t.TempDir(), "nope"), "masked_paths") != nil {
		t.Fatal("missing file must yield no items")
	}
}
