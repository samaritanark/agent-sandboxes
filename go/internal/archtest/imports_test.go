// Package archtest holds the import-graph rules of design section 5.1.1: which packages may
// import which, and the rule that the host binary (cmd/sandbox) depends, directly or not, only on
// host-safe packages: no policy, vetting, secret-gate, or repo-parsing package.
package archtest

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const mod = "github.com/samaritanark/agent-sandboxes/go/internal/"

// allowed lists, per package, the internal packages its production code may import.
var allowed = map[string][]string{
	"archtest":   {},
	"deviation":  {},
	"bashcompat": {"deviation"},
	"config":     {"bashcompat", "deviation"},
	"gate":       {"bashcompat", "config", "deviation"},
	"vetting":    {"bashcompat", "config", "deviation"}, // the gate is injected, never imported
	"checks":     {"config", "deviation"},
	"tier":       {},
	"catalogue":  {"bashcompat", "checks", "config", "deviation"},
	"jqjson":     {},
	"audit":      {"bashcompat", "deviation", "jqjson", "tier"},
	"link":       {"bashcompat", "config", "deviation"},
	"onboard":    {"bashcompat", "config", "deviation"},
	"agents":     {"deviation", "jqjson"},
	"workspace":  {"bashcompat", "config", "deviation"},
	// the host-side secret store: files only, no policy
	"secrets": {},
	// the session allowlist: built-in and extra domains through the block lists
	"allowlist": {"checks"},
	// the workspace mount rules (masks, read-only exec vectors) and their tables
	"mounts": {"bashcompat", "config", "gate"},
	// the in-VM CLI is the policy layer's front end, so it may use every policy package
	"cli": {"agents", "audit", "bashcompat", "catalogue", "checks", "config", "deviation", "gate", "jqjson",
		"link", "mounts", "onboard", "secrets", "tier", "vetting", "workspace"},

	// The host binary's packages (design 5.1). They import only each other.
	"host/driver":  {},
	"host/release": {},
	"host/app":     {"host/driver", "host/release"},
	"host/lima":    {"host/driver"},
}

// hostSafe is every internal package the host binary may depend on, directly or not (5.1.1).
// Adding a policy package here is a design change, not a code change.
func hostSafe(name string) bool { return strings.HasPrefix(name, "host/") }

// TestHostBinaryClosure checks the host binary's whole dependency closure, so a host package
// cannot reach a policy package through another package either.
func TestHostBinaryClosure(t *testing.T) {
	if _, err := os.Stat("../../cmd/sandbox"); err != nil {
		t.Skip("no host binary yet")
	}
	out, err := exec.Command("go", "list", "-deps", "../../cmd/sandbox").Output()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range strings.Fields(string(out)) {
		if !strings.HasPrefix(p, mod) {
			continue
		}
		n++
		if name := strings.TrimPrefix(p, mod); !hostSafe(name) {
			t.Errorf("the host binary depends on %s, which is not host-safe (design 5.1.1)", name)
		}
	}
	if n == 0 {
		t.Error("the host binary depends on no host package; is the closure test looking at the right binary?")
	}
}

func TestImportGraph(t *testing.T) {
	out, err := exec.Command("go", "list", "-json", "../...").Output()
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	seen := map[string]bool{}
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(p.ImportPath, mod)
		rule, ok := allowed[name]
		if !ok {
			// Every package needs a rule, so a new one cannot import past the graph unnoticed.
			// The corpus generators (*/internal/gen*) are test tooling and are exempt.
			if strings.Contains(name, "/internal/gen") || !strings.HasPrefix(p.ImportPath, mod) {
				continue
			}
			t.Errorf("package %s has no import-graph rule: add one to allowed", name)
			continue
		}
		seen[name] = true
		for _, imp := range p.Imports {
			if !strings.HasPrefix(imp, mod) {
				continue
			}
			dep := strings.TrimPrefix(imp, mod)
			okDep := false
			for _, a := range rule {
				if a == dep {
					okDep = true
				}
			}
			if !okDep {
				t.Errorf("package %s imports %s, which the import-graph rules do not allow", name, dep)
			}
		}
	}
	for name := range allowed {
		if !seen[name] {
			t.Errorf("rule for %s matches no package", name)
		}
	}
}

// TestPlantedBugsApply checks that every planted bug in tools/mutants.py still finds its text,
// exactly once, in its file. A refactor that moves the text would otherwise leave the bug
// planting nothing, and `tools/mutate.py` reports that only when someone runs it.
func TestPlantedBugsApply(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("python3 is required in CI")
		}
		t.Skip("python3 not found")
	}
	cmd := exec.Command(py, "tools/mutate.py", "--check")
	cmd.Dir = "../.." // the module root, where tools/ lives
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("stale planted bugs (fix their text in tools/mutants.py):\n%s", out)
	}
}
