// gencli writes the corpus for the in-VM CLI: testdata/cases.tsv, one case per line,
// "id version args tree stdin env" (see oracle.sh).
//
// Usage: go run ./internal/cli/internal/gencli -base internal/cli/testdata
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

type tree []string

func (t tree) f(p, body string) tree { return append(t, enc("f")+" "+enc(p)+" "+enc(body)) }
func (t tree) d(p string) tree       { return append(t, enc("d")+" "+enc(p)) }
func (t tree) l(p, to string) tree   { return append(t, enc("l")+" "+enc(p)+" "+enc(to)) }

type cs struct {
	ver   string
	args  []string
	tree  tree
	stdin string
	env   []string
}

func main() {
	base := flag.String("base", "internal/cli/testdata", "testdata directory")
	flag.Parse()
	var cases []cs
	add := func(c cs) {
		if c.ver == "" {
			c.ver = "none"
		}
		cases = append(cases, c)
	}
	// dispatch, usage, version
	for _, ver := range []string{"none", "full"} {
		for _, a := range [][]string{{}, {"--help"}, {"-h"}, {"help"}, {"bogus"}, {"RUN"}, {"--bogus"}, {""},
			{"version"}, {"version", "--short"}, {"version", "--json"}, {"version", "-h"}, {"version", "--help"},
			{"version", "--bogus"}, {"version", "--short", "--json"}, {"version", "--json", "--short"}, {"version", "--short", "extra"}} {
			add(cs{ver: ver, args: a})
		}
	}
	for _, c := range []string{"run", "rebuild", "upgrade", "onboard", "allow", "mask", "exceptions", "secret", "vet", "link", "profile"} {
		add(cs{args: []string{c, "--help"}})
		add(cs{args: []string{c, "-h"}})
	}
	// profile
	repo := tree{}.d("repos/app").d("repos/my app")
	ov := []string{"SANDBOX_OVERLAY=<HOME>/ov"}
	profs := repo.f(".sandbox/profiles/dev.yaml", "tier: 2\nagent: codex\ndefault_repo: ~/repos/app\n").
		f(".sandbox/profiles/min.yaml", "tier: 1\n").f(".sandbox/profiles/shadow.yaml", "tier: 3\n").
		f("ov/profiles/shadow.yaml", "tier: 1\n").f("ov/profiles/team.yaml", "tier: 2\nagent: claude\n").
		f("ov/profiles/sub/x.yaml", "tier: 1\n").f("ov/profiles/.hidden.yaml", "tier: 1\n").
		f(".sandbox/profiles/long-name-that-is-more-than-24-chars.yaml", "tier: 2\nagent: verylongagent\ndefault_repo: /x\n")
	for _, a := range [][]string{
		{"profile"}, {"profile", "bogus"}, {"profile", "help"},
		{"profile", "save"}, {"profile", "save", "--tier", "4"}, {"profile", "save", "--tier"}, {"profile", "save", "--tier", ""},
		{"profile", "save", "--tier=2"}, {"profile", "save", "--tier", "1"}, {"profile", "save", "--tier", "1", "--agent", "bogus"},
		{"profile", "save", "--tier", "2", "--agent", "codex", "--repo", "~/repos/app"},
		{"profile", "save", "--tier", "2", "--repo", "~/repos/app", "--repo", "~/repos/x"},
		{"profile", "save", "--tier", "2", "--repo", "~/repos/nope", "--dry-run"},
		{"profile", "save", "--tier", "2", "--repo", "~/repos/my app"},
		{"profile", "save", "--tier", "2", "--repo", "~/repos/app/", "--name", "x"},
		{"profile", "save", "--tier", "1", "--allow-domain", "smtp.example.com"},
		{"profile", "save", "--tier", "1", "--allow-domain", "ok.example.com", "--allow-domain=b.example.com", "--dry-run"},
		{"profile", "save", "--tier", "1", "--name", "dev"}, {"profile", "save", "--tier", "1", "--name", "dev", "--force"},
		{"profile", "save", "--tier", "1", "--name", "2"}, {"profile", "save", "--tier", "1", "--name", "../x"},
		{"profile", "save", "--tier", "1", "--bogus"}, {"profile", "save", "--tier", "1", "stray"},
		{"profile", "save", "--tier", "1", "--agent"}, {"profile", "save", "--help"},
		{"profile", "list"}, {"profile", "ls", "extra"}, {"profile", "list", "-h"},
		{"profile", "show"}, {"profile", "show", "dev"}, {"profile", "cat", "team"}, {"profile", "show", "shadow"},
		{"profile", "show", "nope"}, {"profile", "show", "sub/x"}, {"profile", "show", "-h"},
		{"profile", "delete"}, {"profile", "delete", "dev", "--yes"}, {"profile", "rm", "team", "-y"},
		{"profile", "remove", "nope", "-y"}, {"profile", "delete", "a", "b"}, {"profile", "delete", "--bogus"},
	} {
		add(cs{args: a, tree: profs, env: ov})
	}
	add(cs{args: []string{"profile", "list"}})
	add(cs{args: []string{"profile", "list"}, env: ov})
	add(cs{args: []string{"profile", "list"}, tree: tree{}.f(".sandbox/config.yaml", "overlay: ~/ov\n").f("ov/profiles/t.yaml", "tier: 2\n")})
	for _, in := range []string{"y\n", "Y\n", "yes\n", "n\n", "", "y", "YES\n", "nope\n"} {
		add(cs{args: []string{"profile", "delete", "dev"}, tree: profs, env: ov, stdin: in})
	}
	add(cs{args: []string{"profile", "save", "--tier", "2", "--agent", "claude", "--repo", "~/repos/app", "--allow-domain", "x.example.com"}, tree: repo})
	// Not covered: a filesystem refusal (e.g. a file where ~/.sandbox should be a directory), where
	// the bash dies with coreutils' own error text; the port prints its own ERROR line.
	add(cs{args: []string{"profile", "save", "--tier", "1", "--allow-domain", "x.slack.com"}, env: []string{"BLOCKED_DESTINATIONS_CONFIG=<HOME>/none.yaml"}})

	var rows []string
	for i, c := range cases {
		args := ""
		for _, a := range c.args {
			args += a + "\x00"
		}
		rows = append(rows, fmt.Sprintf("c%04d\t%s\t%s\t%s\t%s\t%s", i, c.ver, enc(args), enc(strings.Join(c.tree, "\n")), enc(c.stdin), enc(strings.Join(c.env, "\n"))))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
