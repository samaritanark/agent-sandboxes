// Package archtest holds the import-graph rules of design section 5.1.1: which packages may
// import which. Today it covers the policy packages; the host-safe set and the host binary are
// added with them, and the rule "the host binary imports no policy, vetting, secret-gate, or
// repo-parsing package" becomes one more row here.
package archtest

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const mod = "git.theark.cloud/acs/agent-sandboxes/go/internal/"

// allowed lists, per package, the internal packages its production code may import.
var allowed = map[string][]string{
	"bashcompat": {},
	"config":     {"bashcompat"},
	"gate":       {"bashcompat", "config"},
	"vetting":    {"bashcompat", "config"}, // the gate is injected, never imported
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
