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

// clone copies t, so that every builder step returns a new slice: appending to a shared base
// with spare capacity would let sibling cases overwrite one another's last steps.
func (t tree) clone() tree { return append(tree(nil), t...) }

func (t tree) f(p, body string) tree { return append(t.clone(), enc("f")+" "+enc(p)+" "+enc(body)) }
func (t tree) d(p string) tree       { return append(t.clone(), enc("d")+" "+enc(p)) }
func (t tree) l(p, to string) tree   { return append(t.clone(), enc("l")+" "+enc(p)+" "+enc(to)) }
func (t tree) g(p string) tree       { return append(t.clone(), enc("g")+" "+enc(p)) }
func (t tree) c(p string) tree       { return append(t.clone(), enc("c")+" "+enc(p)) }
func (t tree) r(p string) tree       { return append(t.clone(), enc("r")+" "+enc(p)) }
func (t tree) p(p string) tree       { return append(t.clone(), enc("p")+" "+enc(p)) }
func (t tree) v(p string) tree       { return append(t.clone(), enc("v")+" "+enc(p)) }
func (t tree) t(p string, days int) tree {
	return append(t.clone(), enc("t")+" "+enc(p)+" "+enc(fmt.Sprint(days)))
}
func (t tree) L(name, origin string) tree {
	return append(t.clone(), enc("L")+" "+enc(name)+" "+enc(origin))
}

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

	// check
	finding := func(file, rule string, line int) string {
		return fmt.Sprintf(`{"EndColumn":5,"File":"@REPO@/%s","Match":"R","RuleID":"%s","StartColumn":1,"StartLine":%d}`, file, rule, line)
	}
	ws := tree{}.g("repos/app")
	stub := []string{"STUB=1"}
	for _, cc := range []cs{
		{args: []string{"check"}}, {args: []string{"check", ""}}, {args: []string{"check", "--help"}},
		{args: []string{"check", "~/nope"}}, {args: []string{"check", "~/plain"}, tree: tree{}.d("plain")},
		{args: []string{"check", "~/repos/app"}, tree: ws},
		{args: []string{"check", "~/repos/app", "extra"}, tree: ws},
		{args: []string{"check", "~"}, tree: tree{}.g(".")},
		{args: []string{"check", "~/.ssh"}, tree: tree{}.g(".ssh")},
		{args: []string{"check", "~/.ssh/keys"}, tree: tree{}.g(".ssh/keys")},
		{args: []string{"check", "~/.SSH"}, tree: tree{}.g(".SSH")},
		{args: []string{"check", "~/.config/gcloud"}, tree: tree{}.g(".config/gcloud")},
		{args: []string{"check", "~/.sandbox/overlays/x"}, tree: tree{}.g(".sandbox/overlays/x")},
		{args: []string{"check", "~/work"}, tree: tree{}.g("work").d("work/.sandbox")},
		{args: []string{"check", "~/work"}, tree: tree{}.g("work").d("work/ov"), env: []string{"SANDBOX_OVERLAY=<HOME>/work/ov"}},
		{args: []string{"check", "~/ov"}, tree: tree{}.g("ov"), env: []string{"SANDBOX_OVERLAY=<HOME>/ov/inner"}},
		{args: []string{"check", "~/link"}, tree: tree{}.g(".kube").l("link", ".kube")},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("repos/app/.env", "A=1").f("repos/app/sub/clouds.yaml", "x").
			f("repos/app/a/b/c/deep.pem", "x").f("repos/app/a/b/x.key", "k").f("repos/app/.git/x.pem", "x")},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("repos/app/prod.env", "x").f("repos/app/x-openrc.sh", "x").f("repos/app/id_rsa", "x")},
		{args: []string{"check", "~/repos/app/"}, tree: ws.f("repos/app/.npmrc", "x")},
		{args: []string{"check", "~/repos/app"}, tree: ws, env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("scen/ws.json", "[]"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("repos/app/a.txt", "s").f("repos/app/b c.txt", "s").
			f("scen/ws.json", "["+finding("a.txt", "rule-a", 3)+","+finding("b c.txt", "generic-api-key", 7)+","+finding("a.txt", "other", 9)+"]"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("repos/app/.env", "A=1").f("scen/ws.json", "["+finding(".env", "r", 1)+"]"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("scen/ws.json", "[]").f("scen/gc.json", "["+finding(".git/config", "url-cred", 8)+"]"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("scen/ws.json", "{}").f("scen/ws.rc", "1"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("scen/ws.rc", "2"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("repos/app/.sandbox/config.yaml", "accepted_secrets:\n  - a.txt:r:1:h\n").f("scen/ws.json", "[]"), env: stub},
		{args: []string{"check", "~/repos/app"}, tree: ws.f("repos/app/sealed.yaml", "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:\n    k: AgB\n").
			f("scen/ws.json", `[{"EndColumn":0,"File":"@REPO@/sealed.yaml","Match":"REDACTED","RuleID":"generic-api-key","StartColumn":0,"StartLine":5}]`), env: stub},
	} {
		add(cc)
	}

	// mask
	mr := tree{}.g("r").f("r/file.txt", "x").d("r/dir").f("r/dir/k", "k").f("r/tracked.txt", "t").f("r/gone.txt", "g").c("r").r("r/gone.txt").
		f("r/new.txt", "n").p("r/fifo")
	mrel := [][]string{{"file.txt"}, {"dir"}, {"dir/"}, {"file.txt/"}, {"nope"}, {"nope/"}, {"/abs"}, {"../up"}, {"a/../b"}, {".."},
		{"."}, {""}, {"a/.."}, {"./x"}, {"tracked.txt"}, {"gone.txt"}, {"new.txt"}, {"fifo"}, {"we\"ird"}, {"a #b"},
		{"file.txt", "dir", "file.txt"}, {"x/./y"}, {"a//b"}}
	for _, r := range mrel {
		add(cs{args: append([]string{"mask", "add", "--repo", "~/r"}, r...), tree: mr})
	}
	for _, a := range [][]string{
		{"mask"}, {"mask", "-h"}, {"mask", "help"}, {"mask", "bogus"}, {"mask", "add"}, {"mask", "add", "x"},
		{"mask", "add", "--repo", "~/r"}, {"mask", "add", "--repo"}, {"mask", "add", "--repo=~/r", "file.txt"},
		{"mask", "add", "--repo", "~/nope", "x"}, {"mask", "add", "--repo", "~/plain", "x"}, {"mask", "add", "--repo", "~/r", "--bogus"},
		{"mask", "add", "--repo", "~/r", "x", "--help"}, {"mask", "list"}, {"mask", "list", "--repo", "~/r"},
		{"mask", "list", "--repo", "~/r", "extra"}, {"mask", "list", "--repo", "~/r", "--x"}, {"mask", "list", "-h"},
		{"mask", "list", "--repo", "~/nope"},
	} {
		add(cs{args: a, tree: mr.d("plain")})
	}
	add(cs{args: []string{"mask", "list", "--repo", "~/r"}, tree: mr.f("r/.sandbox/config.yaml",
		"masked_paths:\n  - \"file.txt\"\n  - dir/\n  - gone/\n  - absent.txt\n  - fifo\n  - -n\n  -\n")})
	add(cs{args: []string{"mask", "add", "--repo", "~/r", "new.txt"}, tree: mr.f("r/.sandbox/config.yaml", "overlay: x")})
	add(cs{args: []string{"mask", "add", "--repo", "~/r", "dir/"}, tree: mr.f("r/.sandbox/config.yaml", "masked_paths:\n  - \"file.txt\"\n")})

	// exceptions
	evil := "n\nsecret.txt:rule-a:3\nz"
	jsonName := strings.ReplaceAll(evil, "\n", "\\n")
	ex := tree{}.g("ex").f("ex/a.txt", "s").f("ex/b c.txt", "s").f("ex/x:y.txt", "s").f("ex/secret.txt", "s").f("ex/"+evil, "s").
		f("scen/ws.json", "["+finding("a.txt", "rule-a", 3)+","+finding("b c.txt", "generic-api-key", 7)+","+
			finding("x:y.txt", "r", 2)+","+finding("secret.txt", "rule-a", 3)+","+finding(jsonName, "r", 1)+"]")
	for _, a := range [][]string{
		{"exceptions"}, {"exceptions", "-h"}, {"exceptions", "bogus"},
		{"exceptions", "add"}, {"exceptions", "add", "--repo", "~/ex"}, {"exceptions", "add", "--repo", "~/ex", "--bogus"},
		{"exceptions", "add", "--repo", "~/ex", "a"}, {"exceptions", "add", "--repo", "~/ex", "a:b"}, {"exceptions", "add", "--repo", "~/ex", "a:b:x"},
		{"exceptions", "add", "--repo", "~/ex", ":r:1"}, {"exceptions", "add", "--repo", "~/ex", "a::1"}, {"exceptions", "add", "--repo", "~/ex", "a:r:"},
		{"exceptions", "add", "--repo", "~/ex", "/a:r:1"}, {"exceptions", "add", "--repo", "~/ex", "../a:r:1"},
		{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:4"}, {"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3", "--reason", "test fixture"},
		{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3", "a.txt:rule-a:3"}, {"exceptions", "add", "--repo", "~/ex", "x:y.txt:r:2"},
		{"exceptions", "add", "--repo", "~/ex", "b c.txt:generic-api-key:7", "--reason=#hash"}, {"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:003"},
		{"exceptions", "add", "--repo", "~/ex", evil + ":r:1"}, {"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3", "--reason", "two\nlines"},
		{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3", "--reason"}, {"exceptions", "add", "--repo=~/nope", "a:r:1"},
	} {
		add(cs{args: a, tree: ex, env: stub})
	}
	add(cs{args: []string{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3"}, tree: ex})
	add(cs{args: []string{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3"}, tree: ex.f("scen/ws.rc", "2"), env: stub})
	add(cs{args: []string{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3"}, tree: ex.f("ex/.gitleaksignore", "old:r:1"), env: stub})
	add(cs{args: []string{"exceptions", "add", "--repo", "~/ex", "a.txt:rule-a:3"}, tree: ex.f("ex/.betterleaksignore", "a.txt:rule-a:3\n"), env: stub})
	legacy := "masked_paths:\n  - m\naccepted_secrets:\n  - a.txt:rule-a:3:abc123  # reviewed: test key\n  - b.txt:r:9:def  #  spaced\n- c.txt:r:1\n  - d.txt:r:2:h\nother: 1\n"
	for _, a := range [][]string{{"exceptions", "list", "--repo", "~/ex"}, {"exceptions", "list", "--repo", "~/ex", "x"}, {"exceptions", "list"},
		{"exceptions", "migrate", "--repo", "~/ex"}, {"exceptions", "migrate", "--repo", "~/ex", "--x"}, {"exceptions", "migrate"}} {
		add(cs{args: a, tree: ex})
		add(cs{args: a, tree: ex.f("ex/.betterleaksignore", "# c\na.txt:rule-a:3\n\n b.txt:r:2 \n").f("ex/.sandbox/config.yaml", legacy)})
	}

	// vet
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDibY918+MT8DF7TUm/hnkyDxbO69tvcJYhrdgRygK30wAAAIhs26KabNui\nmgAAAAtzc2gtZWQyNTUxOQAAACDibY918+MT8DF7TUm/hnkyDxbO69tvcJYhrdgRygK30w\nAAAEC43XLViLHpSHRdQGkJYBOCGVnuXYE0UagmHMOQTTAVBOJtj3Xz4xPwMXtNSb+GeTIP\nFs7r229wliGt2BHKArfTAAAAA3RAeAEC\n-----END OPENSSH PRIVATE KEY-----\n"
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOJtj3Xz4xPwMXtNSb+GeTIPFs7r229wliGt2BHKArfT t@x"
	signer := tree{}.f(".testkey/k", key).f(".testkey/k.pub", pub+"\n").
		f(".sandbox/vetting/allowed_signers", "t@x namespaces=\"git\" "+pub+"\n")
	vr := append(append(tree{}, signer...), tree{}.g("vr").f("vr/a.txt", "a").c("vr")...)
	vetted := append(append(tree{}, vr...), tree{}.v("vr")...)
	for _, cc := range []cs{
		{args: []string{"vet"}}, {args: []string{"vet", "-h"}}, {args: []string{"vet", "help"}}, {args: []string{"vet", "--bogus"}},
		{args: []string{"vet", "stray"}}, {args: []string{"vet", "--status"}}, {args: []string{"vet", "--repo", "~/nope", "--status"}},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vr},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: tree{}.g("vr")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted},
		{args: []string{"vet", "--status", "--repo=~/vr"}, tree: vetted.f(".sandbox/config.yaml", "vetting_max_age_days: 30\n")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f(".sandbox/config.yaml", "vetting_max_age_days: 5000\n")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f(".sandbox/config.yaml", "vetting_max_age_days: 08\n")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f("vr/b.txt", "b").c("vr")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f("vr/b.txt", "b").c("vr").f(".sandbox/config.yaml", "vetting_max_commits_behind: 0\n")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f("vr/untracked", "u").f(".sandbox/config.yaml", "vetting_require_clean_worktree: true\n")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.r(".sandbox/vetting/allowed_signers")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f(".sandbox/vetting/allowed_signers", "other@x namespaces=\"git\" "+pub+"\n")},
		{args: []string{"vet", "--status", "--repo", "~/vr"}, tree: vetted.f(".sandbox/config.yaml", "vetting: off\n")},
		// Not covered here: attesting with no signing key configured, where the failure text is
		// git's own and differs between git versions (the vetting package's corpus, run against
		// Linux git only, covers it).
		{args: []string{"vet", "--repo", "~/vr", "--yes"}, tree: vr.f(".sandbox/config.yaml", "vetting_signing_key: ~/.testkey/k\n").f("scen/ws.json", "[]"), env: stub},
		{args: []string{"vet", "--repo", "~/vr", "--message", "release 1"}, tree: vr.f(".sandbox/config.yaml", "vetting_signing_key: ~/.testkey/k\n").f("scen/ws.json", "[]"), env: stub},
		{args: []string{"vet", "--repo", "~/vr"}, tree: vetted.f(".sandbox/config.yaml", "vetting_signing_key: ~/.testkey/k\n").f("scen/ws.json", "[]"), env: stub},
		{args: []string{"vet", "--repo", "~/vr", "--message"}, tree: vr},
	} {
		add(cc)
	}

	// link
	og := tree{}.g("origin").f("origin/profiles/dev.yaml", "tier: 2\n").c("origin")
	linked := og.L("origin", "origin")
	ahead := linked.f("origin/profiles/ops.yaml", "tier: 3\nextra_allowed_domains:\n  - ops.example.com\n").c("origin")
	for _, cc := range []cs{
		{args: []string{"link"}}, {args: []string{"link", "-h"}}, {args: []string{"link", "status"}}, {args: []string{"link", "sync"}},
		{args: []string{"link", "unlink"}}, {args: []string{"link", "status", "x"}}, {args: []string{"link", "--bogus"}},
		{args: []string{"link", "<HOME>/origin"}, tree: og},
		{args: []string{"link", "<HOME>/origin", "--name", "team", "--ref", "main"}, tree: og},
		{args: []string{"link", "<HOME>/origin", "--ref=nope"}, tree: og},
		{args: []string{"link", "<HOME>/origin", "--name", "a b"}, tree: og},
		{args: []string{"link", "<HOME>/origin", "extra"}, tree: og},
		{args: []string{"link", "<HOME>/origin/"}, tree: og},
		{args: []string{"link", "<HOME>/origin"}, tree: og.f(".sandbox/config.yaml", "overlay: /old/team\n")},
		{args: []string{"link", "<HOME>/origin"}, tree: og.d(".sandbox/overlays/origin")},
		{args: []string{"link", "<HOME>/origin"}, tree: linked},
		{args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/profiles/bad.yaml", "tier: 9\n").c("origin")},
		{args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/config.yaml", "min_sandbox_version: 99.0\n").c("origin")},
		{ver: "full", args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/config.yaml", "min_sandbox_version: 99.0\n").c("origin")},
		{ver: "full", args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/config.yaml", "min_sandbox_version: 1.0\n").c("origin")},
		{args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/config.yaml", "leakscan_config_url: file:///nonexistent/x.toml\n").c("origin"), env: stub},
		{args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/config.yaml", "leakscan_config_url: file://<HOME>/cfg.toml\n").c("origin").f("cfg.toml", "x"), env: stub},
		{args: []string{"link", "<HOME>/origin"}, tree: og.f("origin/config.yaml", "leakscan_config_url: -x\n").c("origin")},
		{args: []string{"link", "status"}, tree: linked},
		{args: []string{"link", "status"}, tree: ahead},
		{args: []string{"link", "status"}, tree: linked.r(".sandbox/overlays/origin/.git")},
		{args: []string{"link", "status"}, tree: linked.r("origin")},
		{args: []string{"link", "sync"}, tree: linked},
		{args: []string{"link", "sync"}, tree: ahead},
		{args: []string{"link", "sync", "--ref", "nope"}, tree: ahead},
		{args: []string{"link", "sync", "x"}, tree: ahead},
		{args: []string{"link", "sync"}, tree: ahead.f(".sandbox/overlays/origin/profiles/dev.yaml", "tier: 1\n")},
		{args: []string{"link", "sync"}, tree: linked.f("origin/profiles/bad.yaml", "tier: 0\n").c("origin")},
		{args: []string{"link", "sync"}, tree: linked.f("origin/config.yaml", "min_sandbox_version: 99\n").c("origin")},
		{args: []string{"link", "sync"}, tree: linked.r("origin")},
		{args: []string{"link", "sync"}, tree: linked.r(".sandbox/overlays/origin/.git")},
		{args: []string{"link", "unlink", "--yes"}, tree: linked},
		{args: []string{"link", "unlink", "--keep-clone", "-y"}, tree: linked},
		{args: []string{"link", "unlink", "--bogus"}, tree: linked},
		{args: []string{"link", "unlink"}, tree: linked, stdin: "y\n"},
		{args: []string{"link", "unlink", "--keep-clone"}, tree: linked, stdin: "n\n"},
		{args: []string{"link", "unlink"}, tree: linked, stdin: ""},
		{args: []string{"link", "unlink", "--yes"}, tree: linked.r(".sandbox/overlays/origin/.git")},
	} {
		add(cc)
	}

	// list, logs, cleanup
	L := "logs/"
	sj := func(sid, body string) tree { return tree{}.f(L+sid+"/session.json", body) }
	sessions := tree{}.d("logs").clone()
	for _, s := range []tree{
		sj("ses-1", `{"agent":"claude","tier":2,"name":"dev","start_time":"2026-01-01T00:00:00Z","end_time":null}`),
		sj("ses-2", `{"agent":"codex","tier":3,"name":"","start_time":"s","end_time":"e"}`),
		sj("ses-3", `{"agent":false,"tier":null}`),
		sj("ses-4", `{"agent":{"a":[1,2]},"tier":1.50,"name":"ünïcode name that is long enough","end_time":true}`),
		sj("ses-5", ``), sj("ses-6", `not json`), sj("ses-7", `null`), sj("ses-8", `[1]`),
		sj("ses-9", "{\"agent\":\"a\"}\n{\"agent\":\"b\"}\n"),
		tree{}.d(L + "ses-10"), tree{}.d(L + "other"), tree{}.f(L+"ses-file", "x"),
		tree{}.d(L + "ses-a-very-long-session-identifier-over-36-characters"),
		tree{}.d("elsewhere").l(L+"ses-link", "../elsewhere"),
	} {
		sessions = append(sessions, s...)
	}
	for _, cc := range []cs{
		{args: []string{"list"}}, {args: []string{"list"}, tree: tree{}.d("logs")}, {args: []string{"list"}, tree: sessions},
		{args: []string{"list", "--anything"}, tree: sessions},
		{args: []string{"logs"}}, {args: []string{"logs", ""}}, {args: []string{"logs", "ses-nope"}, tree: sessions},
		{args: []string{"logs", "ses-1"}, tree: sessions.f(L+"ses-1/transcript/b.jsonl", "b").f(L+"ses-1/transcript/a/x.jsonl", "a").
			f(L+"ses-1/files.log", "M src/a.go\nA new.txt\n")},
		{args: []string{"logs", "ses-4"}, tree: sessions}, {args: []string{"logs", "ses-5"}, tree: sessions},
		{args: []string{"logs", "ses-9"}, tree: sessions}, {args: []string{"logs", "ses-10"}, tree: sessions},
		{args: []string{"logs", "ses-link"}, tree: sessions},
		{args: []string{"cleanup"}}, {args: []string{"cleanup"}, tree: tree{}.d("logs")},
		{args: []string{"cleanup"}, tree: tree{}.d(L+"ses-old").t(L+"ses-old", 200).d(L+"ses-new").t(L+"ses-new", 10).
			d("elsewhere").t("elsewhere", 300).l(L+"ses-link", "../elsewhere").d(L+"keep").t(L+"keep", 400)},
		{args: []string{"cleanup", "--older-than", "5"}, tree: tree{}.d(L+"ses-new").t(L+"ses-new", 10).d(L + "ses-now")},
		{args: []string{"cleanup", "--older-than=005"}, tree: tree{}.d(L+"ses-new").t(L+"ses-new", 10)},
		{args: []string{"cleanup", "--older-than", "abc"}, tree: tree{}.d(L+"ses-old").t(L+"ses-old", 200)},
		{args: []string{"cleanup", "--older-than"}, tree: tree{}.d("logs")},
		{args: []string{"cleanup", "--older-than="}, tree: tree{}.d(L+"ses-old").t(L+"ses-old", 200)},
		{args: []string{"cleanup", "30"}, tree: tree{}.d("logs")},
		{args: []string{"cleanup", "--older-than", "-5"}, tree: tree{}.d(L+"ses-new").t(L+"ses-new", 10)},
	} {
		add(cc)
	}

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
