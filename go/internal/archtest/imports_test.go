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
	"config":     {"bashcompat", "deviation", "yamllist"},
	"gate":       {"bashcompat", "config", "deviation", "tables"},
	// rule tables shared by the policy layer and the host's sync gate: data only
	"tables": {},
	// the operator-state push (5.1.4): the host builds it, the in-VM binary receives it
	"opstate": {},
	// the flat YAML list reader shared by config and the host sync gate (masked_paths:)
	"yamllist": {},
	// whether a file is a terminal, for both binaries
	"tty": {},
	// the session spec the policy CLI hands sandboxd (design 5.4.2): data and its structural checks
	"sessionspec": {"egressmatch"},
	// sandboxd (design 5.4.3): the in-VM supervisor's packages
	"sandboxd/journal":  {"sessionspec"},
	"sandboxd/limits":   {"sessionspec"},
	"sandboxd/runtime":  {},
	"sandboxd/netns":    {},
	"sandboxd/netsetup": {},
	"sandboxd/daemon":   {"sandboxd/journal", "sandboxd/limits", "sandboxd/netsetup", "sandboxd/runtime", "sessionspec"},
	// the sync protocol (host engine and in-VM agent) and the in-VM agent itself
	"syncproto": {},
	"syncagent": {"syncproto"},
	"vetting":   {"bashcompat", "config", "deviation"}, // the gate is injected, never imported
	"checks":    {"config", "deviation", "egressmatch"},
	// domain matching shared by the policy layer and the gateway and resolver: pure functions
	"egressmatch": {},
	// the gateway (design 5.8): each session's resolver, gateway controller, and broker
	"gateway/resolver":  {"egressmatch"},
	"gateway/authz":     {"egressmatch"},
	"gateway/envoyconf": {"egressmatch"},
	"tier":              {},
	"catalogue":         {"bashcompat", "checks", "config", "deviation"},
	"jqjson":            {},
	"audit":             {"bashcompat", "deviation", "jqjson", "tier"},
	"link":              {"bashcompat", "config", "deviation"},
	"onboard":           {"bashcompat", "config", "deviation"},
	"agents":            {"deviation", "jqjson"},
	"workspace":         {"bashcompat", "config", "deviation"},
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
	"host/driver":     {},
	"host/release":    {},
	"host/app":        {"host/driver", "host/release", "host/sizing", "host/syncengine", "host/syncgate", "opstate"},
	"host/sizing":     {},
	"host/syncgate":   {"tables", "yamllist"},
	"host/gitobj":     {},
	"host/syncengine": {"host/gitobj", "host/gitref", "host/syncgate", "syncproto"},
	"host/lima":       {"host/driver", "host/hostbin", "host/sizing"},
	"host/hostbin":    {},
	"host/netd":       {},
	"host/seedimg":    {},
	"host/netdvm":     {"host/driver", "host/hostbin", "host/netd", "host/seedimg", "host/sizing"},
	"host/sshx":       {"host/driver"},
	"host/gitref":     {},
	"host/proxycert":  {},
}

// hostSafe is every internal package the host binary may depend on, directly or not (5.1.1).
// Adding a policy package here is a design change, not a code change.
func hostSafe(name string) bool {
	return strings.HasPrefix(name, "host/") || name == "tables" || name == "opstate" || name == "yamllist" || name == "syncproto" || name == "tty"
}

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

// thirdParty lists, per package, the only modules outside the standard library its production
// code may import. Third-party code is confined to the packages the owner allowed (2026-11-25):
// netd's network stack and sandboxd's containerd client; everything else stays on the standard
// library.
var thirdParty = map[string][]string{
	"host/netd": {"github.com/containers/gvisor-tap-vsock/", "gvisor.dev/gvisor/"},
	// containerd's Go client for sandboxd (owner decision, 2026-11-25, design 5.4.3)
	"sandboxd/runtime": {"github.com/containerd/", "github.com/opencontainers/runtime-spec/"},
	// miekg/dns for the filtering resolver (owner decision, 2026-11-25)
	"gateway/resolver": {"github.com/miekg/dns"},
	// Envoy's API types and gRPC for the gateway and broker (owner decision, 2026-11-25)
	"gateway/authz": {"github.com/envoyproxy/go-control-plane/", "google.golang.org/grpc", "google.golang.org/genproto/"},
}

func TestThirdPartyImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-json", "../...").Output()
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(p.ImportPath, mod)
		for _, imp := range p.Imports {
			first, _, _ := strings.Cut(imp, "/")
			if strings.HasPrefix(imp, mod) || !strings.Contains(first, ".") {
				continue // ours, or the standard library
			}
			ok := false
			for _, pre := range thirdParty[name] {
				ok = ok || strings.HasPrefix(imp, pre)
			}
			if !ok {
				t.Errorf("package %s imports %s, a third-party package the rules do not allow", name, imp)
			}
		}
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
