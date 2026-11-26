package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func bindingsHome(t *testing.T) Env {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".sandbox", "profiles"), 0o755)
	os.WriteFile(filepath.Join(home, ".sandbox", "profiles", "p.yaml"),
		[]byte("tier: 1\nsecrets:\n  - GH_TOKEN\n  - NPM_TOKEN\n  - GH_TOKEN\n"), 0o644)
	e := fixtureEnv("full", home, "", nil)
	e.RunHandoff = nil
	return e
}

// TestRunBindings: the pre-pass names a profile's secrets once each, though none is in the store
// yet, and prints nothing.
func TestRunBindings(t *testing.T) {
	e := bindingsHome(t)
	var out bytes.Buffer
	e.Stdin = &out
	names, _, ok, rc := RunBindings([]string{"--profile", "p"}, e)
	if !ok || rc != 0 || strings.Join(names, " ") != "GH_TOKEN NPM_TOKEN" {
		t.Fatalf("%q %v %d", names, ok, rc)
	}
	// a dependency's secrets follow the profile's, a name in both once
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "config", "catalogue"), 0o755)
	os.WriteFile(filepath.Join(root, "config", "catalogue", "pg.yaml"), []byte("kind: service\nimage: docker.io/library/postgres@sha256:"+
		strings.Repeat("a", 64)+"\nport: 5432\nsecrets:\n  - PG_PASSWORD\n  - GH_TOKEN\n"), 0o644)
	os.WriteFile(filepath.Join(e.Home, ".sandbox", "profiles", "d.yaml"), []byte("tier: 1\nsecrets:\n  - GH_TOKEN\nservices:\n  - pg\n"), 0o644)
	e.SandboxRoot = root
	if names, _, ok, _ := RunBindings([]string{"--profile", "d"}, e); !ok || strings.Join(names, " ") != "GH_TOKEN PG_PASSWORD" {
		t.Errorf("dependency: %q %v", names, ok)
	}
	os.WriteFile(filepath.Join(e.Home, ".sandbox", "profiles", "x.yaml"), []byte("tier: 1\nsecrets:\n  - GH_TOKEN\nservices:\n  - nope\n"), 0o644)
	if names, _, ok, rc := RunBindings([]string{"--profile", "x"}, e); ok || rc != 1 || names != nil {
		t.Errorf("an unknown dependency: %q %v %d", names, ok, rc)
	}
	if names, _, ok, _ := RunBindings(nil, e); !ok || len(names) != 0 {
		t.Errorf("no profile: %q %v", names, ok)
	}
	if _, _, ok, rc := RunBindings([]string{"--bogus"}, e); ok || rc != 1 {
		t.Errorf("a refused launch: %v %d", ok, rc)
	}
	if _, _, ok, rc := RunBindings([]string{"--help"}, e); ok || rc != 0 {
		t.Errorf("help: %v %d", ok, rc)
	}
	// the repositories, as run sees them, before they exist in the VM
	if _, repos, ok, rc := RunBindings([]string{"--repo", "/not/synced/yet"}, e); !ok || strings.Join(repos, " ") != "/not/synced/yet" {
		t.Errorf("unsynced repo: %q %v %d", repos, ok, rc)
	}
	other := t.TempDir()
	for _, r := range []string{filepath.Join(e.Home, "code/app"), filepath.Join(e.Home, "b"), other} {
		os.MkdirAll(r, 0o755)
		if out, err := exec.Command("git", "init", "-q", r).CombinedOutput(); err != nil {
			t.Fatalf("%s %v", out, err)
		}
	}
	os.WriteFile(filepath.Join(e.Home, ".sandbox", "profiles", "r.yaml"), []byte("tier: 1\ndefault_repo: ~/code/app\n"), 0o644)
	if _, repos, ok, rc := RunBindings([]string{"--profile", "r"}, e); !ok || strings.Join(repos, " ") != e.Home+"/code/app" {
		t.Errorf("default repo: %q %v %d", repos, ok, rc)
	}
	if _, repos, ok, rc := RunBindings([]string{"--repo", other, "--repo=~/b"}, e); !ok || strings.Join(repos, " ") != other+" "+e.Home+"/b" {
		t.Errorf("repos: %q %v %d", repos, ok, rc)
	}
	if _, err := os.Stat(e.LogsDir); err == nil {
		t.Error("the pre-pass wrote the logs directory")
	}
}

// TestRunSecretPresent: run asks the hook, not the VM's secrets directory, whether the host pushed
// a secret, and stops with v2's message when it did not.
func TestRunSecretPresent(t *testing.T) {
	e := bindingsHome(t)
	var asked []string
	e.SecretPresent = func(n string) bool { asked = append(asked, n); return n != "NPM_TOKEN" }
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"run", "--profile", "p"}, e, &stdout, &stderr)
	if rc != 1 || !strings.Contains(stderr.String(), "Profile 'p' requires secret 'NPM_TOKEN' but it's not in the host-side store.") {
		t.Fatalf("%d %s", rc, stderr.String())
	}
	if strings.Join(asked, " ") != "GH_TOKEN NPM_TOKEN" {
		t.Errorf("asked %q", asked)
	}
}
