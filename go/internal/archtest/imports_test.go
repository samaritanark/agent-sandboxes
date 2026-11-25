// Package archtest holds the import-graph rules of design section 5.1.1: which packages may
// import which. Today it covers the policy packages; the host-safe set and the host binary are
// added with them, and the rule "the host binary imports no policy, vetting, secret-gate, or
// repo-parsing package" becomes one more row here.
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
	// the in-VM CLI is the policy layer's front end, so it may use every policy package
	"cli": {"agents", "audit", "bashcompat", "catalogue", "checks", "config", "deviation", "gate", "jqjson",
		"link", "onboard", "secrets", "tier", "vetting", "workspace"},
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
