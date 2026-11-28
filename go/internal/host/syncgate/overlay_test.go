package syncgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOverlayExecVectors: the overlay's exec_vectors: come from the overlay SANDBOX_OVERLAY names,
// else the one the user config's overlay: names (with ~ expanded, an inline comment and quotes
// removed); no overlay or no overlay config is an empty list, and an unreadable one is an error.
func TestOverlayExecVectors(t *testing.T) {
	home := t.TempDir()
	ov := filepath.Join(home, "team-overlay")
	os.MkdirAll(ov, 0o755)
	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("min_sandbox_version: 3.0.0\nexec_vectors:\n  - .taskfile/\n  - tools/run.sh\n  - Justfile\n"), 0o644)
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	want := "[.taskfile tools/run.sh Justfile]"

	if got, err := OverlayExecVectors(home, getenv); err != nil || len(got) != 0 {
		t.Errorf("no overlay: %q %v", got, err)
	}
	os.MkdirAll(filepath.Join(home, ".sandbox"), 0o755)
	os.WriteFile(filepath.Join(home, ".sandbox", "config.yaml"), []byte("overlay: \"~/team-overlay\" # the team's\n"), 0o644)
	if got, err := OverlayExecVectors(home, getenv); err != nil || fmtList(got) != want {
		t.Errorf("config overlay: %q %v", got, err)
	}
	env["SANDBOX_OVERLAY"] = filepath.Join(home, "elsewhere")
	if got, err := OverlayExecVectors(home, getenv); err != nil || len(got) != 0 {
		t.Errorf("SANDBOX_OVERLAY without a config: %q %v", got, err)
	}
	env["SANDBOX_OVERLAY"] = ov
	if got, err := OverlayExecVectors(home, getenv); err != nil || fmtList(got) != want {
		t.Errorf("SANDBOX_OVERLAY: %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		os.Chmod(filepath.Join(ov, "config.yaml"), 0)
		if os.Getuid() != 0 {
			if _, err := OverlayExecVectors(home, getenv); err == nil {
				t.Error("an unreadable overlay config was taken as empty")
			}
		}
		os.Chmod(filepath.Join(ov, "config.yaml"), 0o644)
	}
	env["USER_SANDBOX_CONFIG"] = filepath.Join(home, "missing.yaml")
	delete(env, "SANDBOX_OVERLAY")
	if got, err := OverlayExecVectors(home, getenv); err != nil || len(got) != 0 {
		t.Errorf("USER_SANDBOX_CONFIG: %q %v", got, err)
	}
}

func fmtList(l []string) string { return "[" + strings.Join(l, " ") + "]" }

// TestClassifyOverlayExecVectors: an overlay's entries are held like the built-in exec vectors: a
// bare name at any depth, a path from the repository root and what is under it, matched the way
// the host's file system matches names; other paths are unaffected.
func TestClassifyOverlayExecVectors(t *testing.T) {
	r := Repo{ExecVectors: []string{".taskfile", "tools/run.sh", "Justfile"}}
	mac := Host{CaseInsensitive: true, NormInsensitive: true}
	for p, want := range map[string]Class{
		".taskfile/build.yml": Quarantine,
		"sub/.taskfile/x.yml": Quarantine,
		"Justfile":            Quarantine,
		"pkg/Justfile":        Quarantine,
		"tools/run.sh":        Quarantine,
		"tools/run.sh/inner":  Quarantine,
		"other/tools/run.sh":  Apply,
		"tools/run.sh.bak":    Apply,
		"src/main.go":         Apply,
		"tools":               Apply, // shorter than the entry
		"justfile":            Apply, // case-sensitive host
	} {
		if got, err := Classify(p, Host{}, r); err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", p, got, err, want)
		}
	}
	if got, _ := Classify("JUSTFILE", mac, r); got != Quarantine {
		t.Errorf("a case-insensitive host's alias was applied: %v", got)
	}
	if got, _ := Classify("Justfile", Host{}, Repo{}); got != Apply {
		t.Errorf("held with no overlay: %v", got)
	}
}
