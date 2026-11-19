package config

import (
	"os"
	"path/filepath"
	"testing"

	"git.theark.cloud/acs/agent-sandboxes/go/internal/deviation"
)

func TestFixEchoOptionItems(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(f, []byte("masked_paths:\n-n\n- -e\n  - -nE\n  - ok\n"), 0o644)
	legacy := ExtractYAMLList(f, "masked_paths")
	if len(legacy) != 1 || legacy[0] != "ok" { // all three echo-option entries vanish
		t.Fatalf("legacy: got %q", legacy)
	}
	defer deviation.Force(deviation.EchoOptionItems)()
	got := ExtractYAMLList(f, "masked_paths")
	want := []string{"n", "-e", "-nE", "ok"}
	if len(got) != len(want) {
		t.Fatalf("fixed: got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fixed: got %q, want %q", got, want)
		}
	}
}
