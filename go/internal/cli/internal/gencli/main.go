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

// F is f with <HOME> in the content replaced by the case's home (never for a committed file:
// the path would differ between machines and so would the commit).
func (t tree) F(p, body string) tree { return append(t.clone(), enc("F")+" "+enc(p)+" "+enc(body)) }
func (t tree) d(p string) tree       { return append(t.clone(), enc("d")+" "+enc(p)) }
func (t tree) l(p, to string) tree   { return append(t.clone(), enc("l")+" "+enc(p)+" "+enc(to)) }
func (t tree) g(p string) tree       { return append(t.clone(), enc("g")+" "+enc(p)) }
func (t tree) a(p string) tree       { return append(t.clone(), enc("a")+" "+enc(p)) }
func (t tree) c(p string) tree       { return append(t.clone(), enc("c")+" "+enc(p)) }
func (t tree) r(p string) tree       { return append(t.clone(), enc("r")+" "+enc(p)) }
func (t tree) p(p string) tree       { return append(t.clone(), enc("p")+" "+enc(p)) }
func (t tree) v(p string) tree       { return append(t.clone(), enc("v")+" "+enc(p)) }
func (t tree) t(p string, days int) tree {
	return append(t.clone(), enc("t")+" "+enc(p)+" "+enc(fmt.Sprint(days)))
}
func (t tree) T(p string, epoch int64) tree {
	return append(t.clone(), enc("T")+" "+enc(p)+" "+enc(fmt.Sprint(epoch)))
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
		{"profile", "save", "--agent", "codex", "--name", "notier", "--dry-run"},
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
		sj("ses-11", "null\n{\"agent\":\"b\",\"tier\":2}\n"), sj("ses-12", "{\"agent\":\"a\"}\n[1]\n"),
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

	// addRun gives a run case the stub scanner (clean reports unless the case writes its own) and
	// pins a case that passes --infra-kubeconfig to the launch decisions (STOP_AT=b1): v2's Step 1b
	// becomes the broker's (design 5.9.5). NOSTUB=1 leaves the scanner off PATH.
	addRun := func(cc cs) {
		var env []string
		stubbed := true
		for _, kv := range cc.env {
			if kv == "NOSTUB=1" {
				stubbed = false
				continue
			}
			env = append(env, kv)
		}
		if stubbed {
			env = append(env, "STUB=1")
			cc.tree = append(tree{}.f("scen/ws.json", "[]").f("scen/gc.json", "[]"), cc.tree...)
		}
		for _, a := range cc.args {
			if strings.HasPrefix(a, "--infra-kubeconfig") {
				env = append(env, "STOP_AT=b1")
				break
			}
		}
		cc.env = env
		add(cc)
	}
	// run: the launch decisions (bin/sandbox cmd_run up to ensure_cluster_ready, which the oracle
	// stubs to print them; k3s_image_present answers STUB_IMAGE_RC, default 2 "cannot tell").
	R := func(a ...string) []string { return append([]string{"run"}, a...) }
	rg := tree{}.g("r").f("r/a.txt", "a").c("r")
	two := rg.g("a/r").f("a/r/x", "x").c("a/r").g("b/r").f("b/r/y", "y").c("b/r")
	sp := rg.g("a/my r").f("a/my r/x", "x").c("a/my r").g("b/my r").f("b/my r/y", "y").c("b/my r").
		g("c/my").f("c/my/z", "z").c("c/my")
	tok := rg.f("tok", "t\n").f("tok2", "u\n").f("kc", "apiVersion: v1\n").f("kc2", "apiVersion: v1\n")
	prof := func(name, body string) tree { return rg.f(".sandbox/profiles/"+name+".yaml", body) }
	sec := func(names ...string) tree {
		t := tree{}
		for _, n := range names {
			t = t.f(".sandbox/secrets/"+n, "v")
		}
		return t
	}
	withSecrets := func(list string, names ...string) tree {
		return append(prof("s", "tier: 1\nsecrets:\n"+list), sec(names...)...)
	}
	repoDom := "extra_allowed_domains:\n  - api.vr.example.org\n  - smtp.vr.example.org\n"
	vrDom := append(append(tree{}, signer...), tree{}.g("vr").f("vr/.sandbox/config.yaml", repoDom).c("vr")...)
	vrDomVetted := vrDom.v("vr")
	honorOv := tree{}.f("ov/config.yaml", "honor_repo_allowed_domains: true\n")
	for _, cc := range []cs{
		// parsing
		{args: R("--help")}, {args: R("-h")}, {args: R("--bogus")}, {args: R("stray")}, {args: R("--agent")},
		{args: R("--tier")}, {args: R("--repo")}, {args: R("--name")}, {args: R("--agent=")},
		{args: R()}, {args: R("--dry-run")},
		{args: R("--agent", "codex", "--tier=1", "--name", "a b", "--dry-run", "--keep-alive", "--allow-exec-plugin",
			"--i-accept-unmasked-secrets", "--i-accept-unvetted-repo", "--i-accept-vetting-drift")},
		{args: R("--agent", "bogus")}, {args: R("--agent", "CLAUDE")}, {args: R("--tier", "0")}, {args: R("--tier", "4")},
		{args: R("--tier", "abc")}, {args: R("--tier", "01")}, {args: R("--tier", " 1")},
		{args: R("--homedir", "~/ah")}, {args: R("--homedir=")}, {args: R(), env: []string{"SANDBOX_AGENT_HOME_OVERRIDE=<HOME>/ah2"}},
		// opencode
		{args: R("--agent", "opencode")},
		{args: R("--agent", "opencode"), env: []string{"OPENCODE_API_KEY=k"}},
		{args: R("--agent", "opencode"), env: []string{"OPENCODE_API_KEY=k", "OPENCODE_BASE_URL=ftp://x.example.org"}},
		{args: R("--agent", "opencode"), env: []string{"OPENCODE_API_KEY=k", "OPENCODE_BASE_URL=https://"}},
		{args: R("--agent", "opencode", "--base-url", "https://llm.example.org/v1"), env: []string{"OPENCODE_API_KEY=k", "OPENCODE_BASE_URL=bad"}},
		{args: R("--agent", "opencode", "--base-url=http://10.1.2.3:8000/v1"), env: []string{"OPENCODE_API_KEY=k"}},
		{args: R("--agent", "opencode", "--base-url", "https://smtp.example.org/v1"), env: []string{"OPENCODE_API_KEY=k"}},
		{args: R("--agent", "codex", "--base-url", "https://llm.example.org/v1")},
		// tiers and repos
		{args: R("--tier", "2")}, {args: R("--tier", "2", "--repo", "~/r"), tree: rg},
		{args: R("--tier", "2", "--repo", "~/nope")}, {args: R("--tier", "2", "--repo", "~"), tree: rg},
		{args: R("--tier", "2", "--repo", "~/.ssh"), tree: tree{}.d(".ssh")},
		{args: R("--tier", "2", "--repo", "~/r/"), tree: rg},
		{args: R("--tier", "1", "--repo", "~/r"), tree: rg},
		{args: R("--tier", "2", "--repo", "~/a/r", "--repo", "~/b/r"), tree: two},
		{args: R("--tier", "2", "--repo", "~/a/r", "--repo", "~/r"), tree: two},
		{args: R("--tier", "2", "--repo", "~/a/my r", "--repo", "~/b/my r"), tree: sp},
		{args: R("--tier", "2", "--repo", "~/a/my r", "--repo", "~/c/my"), tree: sp},
		{args: R("--tier", "2", "--repo", "~/r"), tree: rg, env: []string{"STUB_IMAGE_RC=1"}},
		{args: R("--tier", "2", "--repo", "~/r"), tree: rg, env: []string{"STUB_IMAGE_RC=0"}},
		{args: R("--agent", "codex"), env: []string{"STUB_IMAGE_RC=1"}},
		// tier 3
		{args: R("--tier", "3", "--repo", "~/r"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "GH=~/tok", "--infra-token", "~/tok2"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--infra-token", "INFRA_TOKEN=~/tok2"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "A=~/tok", "--infra-token", "A=~/tok2"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/missing"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-kubeconfig", "~/kc"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-kubeconfig", "~/nokc"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-kubeconfig", "~/kc", "--infra-kube-context", "prod"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-kubeconfig", "~/kc", "--infra-kubeconfig", "~/kc2", "--infra-kube-context", "prod"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--infra-kube-context", "prod"), tree: tok},
		{args: R("--tier", "2", "--repo", "~/r", "--infra-kubeconfig", "~/kc"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--infra-endpoint", "https://api.infra.example.org:6443/x"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--infra-endpoint", "https://smtp.example.org"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--infra-endpoint", "http://10.9.8.7:8080"),
			tree: tok.f(".sandbox/config.yaml", "blocked_cidrs:\n  - 10.0.0.0/8\n")},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--allow-exec-plugin"), tree: tok},
		// egress
		{args: R("--allow-domain", "api.example.org", "--allow-domain=*.cdn.example.org")},
		{args: R("--allow-domain", "smtp.example.org")}, {args: R("--allow-domain", "discord.com")},
		{args: R("--allow-domain", "*.com")}, {args: R("--allow-domain", "*.co.uk")}, {args: R("--allow-domain", "a b")},
		{args: R("--allow-domain", "EXAMPLE.org.")}, {args: R("--allow-domain", "")}, {args: R("--allow-domain", "10.1.2.3")},
		{args: R("--allow-domain", "x.example.org"), tree: tree{}.f(".sandbox/config.yaml", "blocked_domains:\n  - \"*.example.org\"\n")},
		{args: R(), tree: tree{}.f(".sandbox/config.yaml", "blocked_cidrs:\n  - 10.0.0.0/33\n")},
		{args: R(), tree: tree{}.f(".sandbox/config.yaml", "extra_allowed_domains:\n  - u.example.org\n  - \"*.u2.example.org\"\n")},
		{args: R("--allow-domain", "c.example.org"), env: []string{"SANDBOX_EXTRA_ALLOWED_DOMAINS=e1.example.org e2.example.org"}},
		{args: R(), env: []string{"SANDBOX_EXTRA_ALLOWED_DOMAINS=smtp.example.org"}},
		{args: R(), env: []string{"SANDBOX_EXTRA_ALLOWED_DOMAINS=*"}, tree: tree{}.f("a1", "").f("b1", "")},
		{args: R(), env: []string{"BLOCKED_DESTINATIONS_CONFIG=<HOME>/nope.yaml"}},
		{args: R("--allow-domain", "x.example.org"), env: []string{"BLOCKED_DESTINATIONS_CONFIG=<HOME>/bl.yaml"},
			tree: tree{}.f("bl.yaml", "blocked_domains:\n  - x.example.org\n")},
		// per-repo egress: ungranted (no overlay), honored (vetted), honored overlay but unvetted repo
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vrDomVetted},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: append(append(tree{}, vrDomVetted...), honorOv...), env: ov},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: append(append(tree{}, vrDom...), honorOv...), env: ov},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: append(append(tree{}, vrDomVetted.f("vr/.sandbox/config.yaml", repoDom+"  - new.example.org\n")...), honorOv...), env: ov},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: append(append(tree{}, vrDomVetted...), tree{}.f(".sandbox/config.yaml", "overlay: ~/ov\n").f("ov/config.yaml", "honor_repo_allowed_domains: true\n")...)},
		// profiles
		{args: R("--profile", "2", "--repo", "~/r"), tree: rg}, {args: R("--profile", "2", "--tier", "3"), tree: rg},
		{args: R("--profile", "1", "--tier", "1")}, {args: R("--profile", "nope")}, {args: R("--profile", "../x")},
		{args: R("--profile", "dev"), tree: prof("dev", "tier: 2\nagent: codex\ndefault_repo: ~/r\nextra_allowed_domains:\n  - p.example.org\nmcps:\n  - m1\n  - m2\nservices:\n  - postgres\n")},
		{args: R("--profile", "dev", "--repo", "~/r"), tree: prof("dev", "tier: 2\ndefault_repo: ~/nope\n")},
		{args: R("--profile", "dev"), tree: prof("dev", "agent: codex\n")},
		{args: R("--profile", "dev", "--tier", "3"), tree: prof("dev", "tier: 2\n")},
		{args: R("--profile", "dev", "--tier", "1"), tree: prof("dev", "tier: 1\n")},
		{args: R("--profile", "dev", "--agent", "claude"), tree: prof("dev", "tier: 1\nagent: codex\n")},
		{args: R("--profile", "dev", "--agent", "codex"), tree: prof("dev", "tier: 1\nagent: codex\n")},
		{args: R("--profile", "dev"), tree: prof("dev", "tier: 7\n")},
		{args: R("--profile", "dev"), tree: prof("dev", "tier: 1\nextra_allowed_domains:\n  - smtp.example.org\n")},
		{args: R("--profile", "team"), tree: rg.f("ov/profiles/team.yaml", "tier: 1\n"), env: ov},
		{args: R("--profile", "team"), tree: rg.f("ov/profiles/team.yaml", "tier: 1\n").f(".sandbox/config.yaml", "overlay: ~/ov\n")},
		{args: R("--profile", "2", "--repo", "~/r"), tree: rg.d("ov"), env: ov},
		// profile secrets
		{args: R("--profile", "s"), tree: withSecrets("  - GH_TOKEN\n  - NPM_TOKEN\n", "GH_TOKEN", "NPM_TOKEN")},
		{args: R("--profile", "s"), tree: withSecrets("  - GH_TOKEN\n  - NPM_TOKEN\n", "GH_TOKEN")},
		{args: R("--profile", "s"), tree: withSecrets("  - gh_token\n", "gh_token")},
		{args: R("--profile", "s"), tree: withSecrets("  - "+strings.Repeat("A", 65)+"\n", strings.Repeat("A", 65))},
		{args: R("--profile", "s"), tree: withSecrets("  - "+strings.Repeat("A", 64)+"\n", strings.Repeat("A", 64))},
		{args: R("--profile", "s"), tree: withSecrets("  - A B\n", "A", "B", "AB")},
		{args: R("--profile", "s"), tree: withSecrets("  - \"A*\"\n", "A1", "A*").f("A2", "")},
		{args: R("--profile", "s"), tree: withSecrets("  - -n\n  - GH\n", "GH")},
		{args: R("--profile", "s"), tree: withSecrets("  - GH\n  - GH\n", "GH")},
		{args: R("--profile", "s"), tree: withSecrets("  - \"\"\n", "X")},
		{args: R("--profile", "s"), tree: withSecrets("  - 1X\n", "1X")},
		// overlay minimum version
		{args: R(), tree: tree{}.f("ov/config.yaml", "min_sandbox_version: 99.0\n"), env: ov},
		{ver: "full", args: R(), tree: tree{}.f("ov/config.yaml", "min_sandbox_version: 99.0\n"), env: ov},
		{ver: "full", args: R(), tree: tree{}.f("ov/config.yaml", "min_sandbox_version: 1.0\n"), env: ov},
		{ver: "full", args: R(), tree: tree{}.f("ov/config.yaml", "min_sandbox_version: banana\n"), env: ov},
		{args: R(), env: []string{"SANDBOX_OVERLAY=<HOME>/missing"}},
		// a linked overlay is synced first (SANDBOX_NO_LINK_CHECK skips it)
		{args: R("--profile", "dev", "--repo", "~/r"), tree: append(append(tree{}, rg...), ahead...)},
		{args: R("--profile", "ops", "--repo", "~/r"), tree: append(append(tree{}, rg...), ahead...)},
		{args: R("--profile", "ops", "--repo", "~/r"), tree: append(append(tree{}, rg...), ahead...), env: []string{"SANDBOX_NO_LINK_CHECK=1"}},
	} {
		addRun(cc)
	}

	// run, B3: the gates, the session ID and name, dependencies, and session.json (the stub stops
	// after audit_flush_overrides).
	vrep := append(append(tree{}, signer...), tree{}.g("vr").f("vr/a.txt", "a").c("vr")...)
	vvet := vrep.v("vr")
	req := ".sandbox/config.yaml"
	entry := func(name, kind, extra string) string {
		return "name: " + name + "\nkind: " + kind + "\nimage: docker.io/mcp/everything@sha256:330885a0c4b2eed6f0cd3aae0f0b37152ccdf2852e2f6af6d616a5d5c1e9817d\nport: 3001\n" + extra
	}
	deps := func(body string) tree { return prof("d", "tier: 1\n"+body) }
	for _, cc := range []cs{
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vrep},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vrep.f(req, "vetting: required\n")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unvetted-repo"), tree: vrep.f(req, "vetting: required\n")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet.f(req, "vetting: required\n")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet.f(req, "vetting: off\n")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-vetting-drift"), tree: vvet.f("vr/b.txt", "b").c("vr").f(req, "vetting: required\nvetting_max_commits_behind: 0\n")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unvetted-repo"), tree: vrep.f(req, "vetting: required\noverlay: ~/ov\n").f("ov/config.yaml", "vetting_forbid_unvetted_override: true\n")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vrep.r(".sandbox/vetting/allowed_signers").f(req, "vetting: required\n")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet.f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unmasked-secrets"), tree: vvet.f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unmasked-secrets", "--i-accept-unvetted-repo"),
			tree: vrep.f(req, "vetting: required\n").f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet.f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]").
			f(req, "overlay: ~/ov\n").f("ov/config.yaml", "trusted_inference_endpoints:\n  - api.anthropic.com\n")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet.f("vr/.env", "A=1").f("vr/k.pem", "k")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: vvet, env: []string{"NOSTUB=1"}},
		{args: R("--tier", "2", "--repo", "~/vr", "--repo", "~/r"), tree: append(append(tree{}, vvet...), rg...)},
		{args: R("--tier", "3", "--repo", "~/vr", "--infra-token", "~/tok"), tree: vvet.f("tok", "t")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-vetting-drift"), tree: vvet.f("vr/b.txt", "b").c("vr").f(req, "vetting: required\n")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unvetted-repo"), tree: vvet.f("vr/b.txt", "b").c("vr").f(req, "vetting: required\n")},
		// an accepted unvetted repo's exceptions are honored, unless the overlay forbids the override
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unvetted-repo"),
			tree: vrep.f("vr/.betterleaksignore", "a.txt:rule-a:1\n").c("vr").f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]")},
		{args: R("--tier", "2", "--repo", "~/vr", "--i-accept-unvetted-repo"),
			tree: vrep.f("vr/.betterleaksignore", "a.txt:rule-a:1\n").c("vr").f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]").
				f(req, "overlay: ~/ov\n").f("ov/config.yaml", "vetting_forbid_unvetted_override: true\n")},
		{args: R("--allow-domain", "api.anthropic.com", "--allow-domain", "x.example.org", "--allow-domain", "x.example.org")},
		{args: R(), env: []string{"FAKE_NOW=1800003723"}},
		// names and the pod name
		{args: R("--name", "My Repo!! (x)")}, {args: R("--name", "-n")}, {args: R("--name", "---")}, {args: R("--name", "ÄÖ ü")}, {args: R("--name", "a\nb\tc")}, {args: R("--name", "a--b")}, {args: R("--name", " Lead")},
		{args: R("--agent", "codex")}, {args: R("--agent", "codex", "--name", "UPPER_case.1")},
		// dependencies
		{args: R("--profile", "d"), tree: deps("mcps:\n  - everything-mcp\n")},
		{args: R("--profile", "d", "--agent", "codex"), tree: deps("mcps:\n  - everything-mcp\n")},
		{args: R("--profile", "d"), tree: deps("services:\n  - everything-mcp\n")},
		{args: R("--profile", "d"), tree: deps("services:\n  - nope\n")},
		{args: R("--profile", "d"), tree: deps("services:\n  - ../x\n")},
		{args: R("--profile", "d"), tree: deps("mcps:\n  - everything-mcp\n"), env: []string{"SANDBOX_MAX_DEPS_PER_SESSION=0"}},
		{args: R("--profile", "d"), tree: deps("services:\n  - db\n").f("ov/catalogue/db.yaml", entry("db", "service", "secrets:\n  - DB_PASS\n")), env: ov},
		{args: R("--profile", "d"), tree: deps("services:\n  - db\n").f("ov/catalogue/db.yaml", entry("db", "service", "secrets:\n  - DB_PASS\n")).f(".sandbox/secrets/DB_PASS", "p"), env: ov},
		{args: R("--profile", "d"), tree: deps("services:\n  - web\n  - db\n").f("ov/catalogue/web.yaml", entry("web", "service", "class: browser\n")).
			f("ov/catalogue/db.yaml", entry("db", "service", "")), env: ov},
		{args: R("--profile", "d"), tree: deps("services:\n  - Big_DB\n").f("ov/catalogue/Big_DB.yaml", entry("Big_DB", "service", "")), env: ov},
		{args: R("--profile", "d"), tree: deps("services:\n  - bad\n").f("ov/catalogue/bad.yaml", entry("bad", "service", "port: x\n")), env: ov},
		{args: R("--profile", "d"), tree: deps("services:\n  - \"*\"\n").f("ov/catalogue/db.yaml", entry("db", "service", "")).f("db", ""), env: ov},
	} {
		addRun(cc)
	}

	// allow: the checks, the liveness test (STUB_POD), the merge, and the session record.
	A := func(a ...string) []string { return append([]string{"allow"}, a...) }
	sess := func(body string) tree { return tree{}.f("logs/ses-1/session.json", body) }
	sbase := `{"id":"ses-1","agent":"claude","tier":2,"pod_name":"sandbox-r-claude-beef","allowed_domains":["claude.ai","x.example.org"],"events":[]}`
	live := []string{"STUB_POD=Running"}
	for _, cc := range []cs{
		{args: A()}, {args: A("--help")}, {args: A("-h")}, {args: A("--bogus")}, {args: A("ses-1")},
		{args: A("--add-domain", "a.example.org")}, {args: A("ses-1", "ses-2", "--add-domain", "a.example.org")},
		{args: A("ses-1", "--add-domain")}, {args: A("ses-1", "--add-domain=")}, {args: A("ses-1", "--add-domain", "a.example.org", "-x")},
		{args: A("ses-nope", "--add-domain", "a.example.org")},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(sbase)},
		{args: A("ses-1", "--add-domain", "smtp.example.org"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "*.com"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "a b"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "10.1.2.3"), tree: sess(sbase).f(".sandbox/config.yaml", "blocked_cidrs:\n  - 10.0.0.0/8\n"), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(sbase).f(".sandbox/config.yaml", "blocked_cidrs:\n  - nope\n"), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(sbase).f(".sandbox/config.yaml", "blocked_domains:\n  - \"*.example.org\"\n"), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain=b.example.org", "--add-domain", "a.example.org", "--add-domain", "b.example.org"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "x.example.org"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "x.example.org", "--add-domain", "api.anthropic.com"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "api.anthropic.com"), tree: sess(sbase), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"codex","tier":1,"allowed_domains":["b.example.org","a.example.org","b.example.org"]}`), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"claude","tier":3}`), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"claude","tier":3,"kube_api_cidr":"10.9.0.1/32","kube_api_port":"6443","kube_host_entity":"true","allowed_domains":[],` +
			`"dependencies":[{"name":"db","resource_name":"dep-db-ses-1","port":5432},{"name":"m","resource_name":"dep-m-ses-1","port":"3001"}],"events":[{"time":"t","type":"x","message":"m"}]}`), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"opencode","tier":1,"allowed_domains":[]}`), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"opencode","tier":1,"allowed_domains":[]}`),
			env: []string{"STUB_POD=Running", "OPENCODE_BASE_URL=https://llm.example.org/v1"}},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"claude","tier":1,"pod_name":"","allowed_domains":[]}`)},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"claude","tier":1,"pod_name":null}`), env: live},
		{args: A("ses-1", "--add-domain", "a.example.org"), tree: sess(`{"id":"ses-1","agent":"claude","tier":1,"allowed_domains":[]}`),
			env: []string{"STUB_POD=Running", "BLOCKED_DESTINATIONS_CONFIG=<HOME>/missing.yaml"}},
	} {
		add(cc)
	}

	// resume: liveness and phase (STUB_POD), the recreate blockers and the guide command, the
	// re-run gates, and the policy, workload, and agent command handed on.
	RS := func(a ...string) []string { return append([]string{"resume"}, a...) }
	scen := tree{}.f("scen/ws.json", "[]").f("scen/gc.json", "[]")
	withSess := func(t tree, body string) tree {
		return append(append(tree{}, scen...), t.F("logs/ses-1/session.json", body)...)
	}
	rec := func(fields string) string {
		return `{"id":"ses-1","agent":"claude","tier":1,"user":"t","name":"claude","pod_name":"sandbox-claude-beef",` + fields + `"allowed_domains":["claude.ai","api.anthropic.com","x.example.org"]}`
	}
	sess1 := rec(`"agent_session_id":"01234567-89ab-4def-bedc-ba9876543210",`)
	vrRec := func(extra string) string {
		return `{"id":"ses-1","agent":"claude","tier":2,"user":"t","name":"vr/claude","pod_name":"sandbox-vr-claude-beef","repos":["<HOME>/vr"],` + extra + `"allowed_domains":["claude.ai"]}`
	}
	stubEnv := func(kv ...string) []string { return append([]string{"STUB=1"}, kv...) }
	for _, cc := range []cs{
		{args: RS()}, {args: RS("--help")}, {args: RS("-h")}, {args: RS("--bogus")}, {args: RS("ses-1", "ses-2")},
		{args: RS("ses-1", "--help")}, {args: RS("ses-nope")}, {args: RS("")},
		// live
		{args: RS("ses-1"), tree: withSess(tree{}, sess1), env: []string{"STUB_POD=Running"}},
		{args: RS("ses-1", "--keep-alive"), tree: withSess(tree{}, sess1), env: []string{"STUB_POD=Running"}},
		{args: RS("ses-1"), tree: withSess(tree{}, sess1), env: []string{"STUB_POD=Pending"}},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"codex","agent_session_id":"abc"}`), env: []string{"STUB_POD=Running"}},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"copilot"}`), env: []string{"STUB_POD=Running"}},
		{args: RS("ses-1"), tree: withSess(tree{}, `{}`), env: []string{"STUB_POD=Running"}},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":null,"pod_name":null}`), env: []string{"STUB_POD=Running"}},
		// torn down: blockers and the guide command
		{args: RS("ses-1"), tree: withSess(tree{}, rec(`"tier":3,"repos":["<HOME>/r","<HOME>/b c"],`))},
		{args: RS("ses-1"), tree: withSess(tree{}, rec(`"profile":"dev","repos":["<HOME>/r"],`))},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"opencode","tier":1,"name":"it's","allowed_domains":["llm.example.org","z.example.org"]}`)},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"opencode","tier":1,"allowed_domains":["llm.example.org"]}`), env: []string{"OPENCODE_BASE_URL=https://llm.example.org/v1"}},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"codex","tier":"3","profile":"","repos":[]}`)},
		// torn down: recreated
		{args: RS("ses-1"), tree: withSess(tree{}, sess1)},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"id":"ses-1","tier":1,"kube_api_cidr":"10.0.0.1/32","kube_api_port":"6443","kube_host_entity":"true"}`)},
		{args: RS("ses-1"), tree: withSess(vvet, vrRec("")), env: stubEnv()},
		{args: RS("ses-1"), tree: withSess(vrep, vrRec("")), env: stubEnv()},
		{args: RS("ses-1"), tree: withSess(vrep.f(req, "vetting: required\n"), vrRec("")), env: stubEnv()},
		{args: RS("ses-1", "--i-accept-unvetted-repo"), tree: withSess(vrep.f(req, "vetting: required\n"), vrRec(`"events":[],`)), env: stubEnv()},
		{args: RS("ses-1"), tree: withSess(vvet.f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]"), vrRec("")), env: stubEnv()},
		{args: RS("ses-1", "--i-accept-unmasked-secrets"), tree: withSess(vvet.f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]"), vrRec("")), env: stubEnv()},
		{args: RS("ses-1", "--i-accept-vetting-drift"), tree: withSess(vvet.f("vr/b.txt", "b").c("vr").f(req, "vetting: required\n"), vrRec("")), env: stubEnv()},
		{args: RS("ses-1"), tree: withSess(vvet, vrRec("")), env: []string{}},
		{args: RS("ses-1"), tree: withSess(vvet, `{"agent":"claude","tier":2,"repos":[]}`)},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"codex","tier":1,"allowed_domains":["api.openai.com","x.example.org"]}`)},
		{args: RS("ses-1"), tree: withSess(tree{}, `{"agent":"claude","tier":3,"repos":[null,false,true,7,"<HOME>/r",""]}`)},
	} {
		add(cc)
	}

	// secret: the host-side store. TZ is fixed where file times are printed.
	SC := func(a ...string) []string { return append([]string{"secret"}, a...) }
	SD := ".sandbox/secrets/"
	utc := []string{"TZ=UTC"}
	listed := tree{}.f(SD+"B_TOKEN", "bee").T(SD+"B_TOKEN", 1700000000).f(SD+"A", "").T(SD+"A", 1700003600).
		f(SD+".hidden", "x").d(SD+"SUBDIR").f(SD+"lower", "abc").T(SD+"lower", 1600000000).
		f(SD+"ünï", "u").T(SD+"ünï", 1600000000)
	for _, cc := range []cs{
		{args: SC()}, {args: SC("--help")}, {args: SC("-h")}, {args: SC("help")}, {args: SC("bogus")},
		{args: SC("set")}, {args: SC("set", "")}, {args: SC("set", "lower")}, {args: SC("set", "1A")}, {args: SC("set", "A-B")},
		{args: SC("set", strings.Repeat("A", 65))}, {args: SC("set", strings.Repeat("A", 64)), stdin: "v"},
		{args: SC("set", "ÄB")},
		{args: SC("set", "HAS SPACE")}, {args: SC("set", "HAS.DOT")}, {args: SC("set", "Mixed_Case")},
		{args: SC("set", "_LEADING_UNDERSCORE"), stdin: "v"}, {args: SC("set", "B12"), stdin: "v"},
		{args: SC("set", "GH_TOKEN"), stdin: "ghp_value\n"}, {args: SC("set", "GH_TOKEN"), stdin: ""},
		{args: SC("set", "GH_TOKEN", "extra")}, {args: SC("set", "GH_TOKEN", "--bogus")}, {args: SC("set", "GH_TOKEN", "--help")},
		{args: SC("set", "GH_TOKEN", "--from-file", "~/src"), tree: tree{}.f("src", "file value\n")},
		{args: SC("set", "GH_TOKEN", "--from-file=<HOME>/src"), tree: tree{}.f("src", "file value")},
		{args: SC("set", "GH_TOKEN", "--from-file", "~/missing")},
		{args: SC("set", "GH_TOKEN", "--from-file", "~/dir"), tree: tree{}.d("dir")},
		{args: SC("set", "GH_TOKEN", "--from-file")}, {args: SC("set", "GH_TOKEN", "--from-file", "")},
		{args: SC("set", "GH_TOKEN", "--from-file="), stdin: "from stdin"},
		{args: SC("set", "GH_TOKEN", "--from-file", "~/src", "--from-env"), tree: tree{}.f("src", "x")},
		{args: SC("set", "lower", "--from-file", "~/src", "--from-env"), tree: tree{}.f("src", "x")},
		{args: SC("set", "GH_TOKEN", "--from-env"), env: []string{"GH_TOKEN=env value"}},
		{args: SC("set", "GH_TOKEN", "--from-env=MY_VAR"), env: []string{"MY_VAR=other value"}},
		{args: SC("set", "GH_TOKEN", "--from-env=MY_VAR")},
		{args: SC("set", "GH_TOKEN", "--from-env="), stdin: "from stdin"},
		{args: SC("set", "GH_TOKEN", "--from-env"), env: []string{"GH_TOKEN="}},
		{args: SC("set", "lower", "--from-env")},
		{args: SC("set", "GH_TOKEN", "--from-env=a-b")}, {args: SC("set", "GH_TOKEN", "--from-env=1X")},
		{args: SC("set", "GH_TOKEN", "--from-env=_USE_DEFAULT"), env: []string{"GH_TOKEN=via sentinel"}},
		{args: SC("set", "GH_TOKEN"), stdin: "new", tree: tree{}.f(SD+"GH_TOKEN", "a much longer old value").d(SD + "keep")},
		{args: SC("set", "GH_TOKEN"), stdin: "v", tree: tree{}.d(".sandbox")},
		{args: SC("set", "GH_TOKEN"), stdin: "through", tree: tree{}.f("target", "t").l(SD+"GH_TOKEN", "../../target")},
		{args: SC("set", "GH_TOKEN"), stdin: "v", env: []string{"SANDBOX_SECRETS_DIR=<HOME>/alt"}},
		{args: SC("list")}, {args: SC("list"), tree: tree{}.d(SD)}, {args: SC("list", "extra"), tree: tree{}.d(SD)},
		{args: SC("list"), tree: listed, env: utc}, {args: SC("list"), tree: listed, env: []string{"TZ=Asia/Kolkata"}},
		{args: SC("list"), tree: listed.f(SD+strings.Repeat("é", 20), "x").T(SD+strings.Repeat("é", 20), 1600000000), env: utc},
		{args: SC("list"), tree: listed.f("alt/X", "1").T("alt/X", 1700000000), env: []string{"TZ=UTC", "SANDBOX_SECRETS_DIR=<HOME>/alt"}},
		{args: SC("list"), env: []string{"SANDBOX_SECRETS_DIR=/nonexistent/secrets"}},
		{args: SC("delete")}, {args: SC("delete", "lower")}, {args: SC("delete", "GH_TOKEN")},
		{args: SC("delete", "GH_TOKEN"), tree: tree{}.f(SD+"GH_TOKEN", "v")},
		{args: SC("rm", "GH_TOKEN", "extra"), tree: tree{}.f(SD+"GH_TOKEN", "v")},
		{args: SC("remove", "GH_TOKEN"), tree: tree{}.f("target", "t").l(SD+"GH_TOKEN", "../../target")},
		{args: SC("delete", "GH_TOKEN"), tree: tree{}.l(SD+"GH_TOKEN", "../../nowhere")},
	} {
		add(cc)
	}

	// onboard: the command around the onboard package (whose own corpus covers the staging).
	OB := func(a ...string) []string { return append([]string{"onboard"}, a...) }
	for _, cc := range []cs{
		{args: OB("--help")}, {args: OB("-h")}, {args: OB("--bogus")}, {args: OB("stray")}, {args: OB("--agent")},
		{args: OB("--agent", "bogus")}, {args: OB("--agent=")}, {args: OB("--agent=all", "--dry-run")},
		{args: OB("--dry-run")}, {args: OB()}, {args: OB("--skip-config", "--agent", "opencode")},
		{args: OB("--agent", "claude"), tree: tree{}.f(".claude/.credentials.json", "{}").f(".claude/settings.json", "{}")},
		{args: OB("--agent", "claude", "--dry-run"), tree: tree{}.f(".claude/.credentials.json", "{}")},
		{args: OB("--agent", "codex", "--force"), tree: tree{}.f(".codex/auth.json", "{}").f(".sandbox/config.yaml", "x: 1\n")},
		{args: OB("--agent", "grok"), env: []string{"ANTHROPIC_API_KEY=k", "GH_TOKEN=t"}},
		{args: OB("--agent", "copilot", "--skip-config"), env: []string{"OPENAI_API_KEY=k"}},
	} {
		add(cc)
	}

	// Cases added when the corrected mutation runner (which copies the whole repository) showed
	// what the CLI corpus could not see.
	hist := tree{}.g("h").f("h/old.txt", "o").f("h/keep.txt", "k").c("h").r("h/old.txt").c("h").f("h/staged.txt", "s").a("h")
	vrX := vr.f("vr/.betterleaksignore", "a.txt:rule-a:1\n").c("vr").f(".sandbox/config.yaml", "vetting_signing_key: ~/.testkey/k\n").
		f("scen/ws.json", "["+finding("a.txt", "rule-a", 1)+"]")
	honorDel := append(append(tree{}, vrDomVetted.r("vr/.sandbox/config.yaml")...), honorOv...)
	for _, cc := range []cs{
		{args: []string{"profile", "save", "--name", "p", "--tierx", "1"}}, {args: R("--tierx", "1")},
		{args: []string{"profile", "save", "--name", "p", "--tier", "2", "--repo", "~/file"}, tree: tree{}.f("file", "x")},
		{args: []string{"profile", "save", "--name", "p", "--tier", "1"}, tree: tree{}.d(".sandbox/profiles/p.yaml")},
		{args: []string{"check", "~/.sshkeys"}, tree: tree{}.d(".ssh").g(".sshkeys").f(".sshkeys/a", "a").c(".sshkeys")},
		{args: []string{"check", "~/r"}, tree: rg.f("scen/ws.json", "["+finding("", "rule-x", 2)+"]"), env: stub},
		{args: []string{"mask", "add", "--repo", "~/h", "old.txt"}, tree: hist},
		{args: []string{"mask", "add", "--repo", "~/h", "staged.txt"}, tree: hist},
		{args: []string{"exceptions", "migrate", "--repo", "~/ex"}, tree: ex.f("ex/.sandbox/config.yaml", "accepted_secrets:\n  - e.txt:r:3:h  # first # second\n")},
		{args: []string{"vet", "--repo", "~/vr", "--yes"}, tree: vrX, env: stub},
		{args: []string{"vet", "--repo", "~/vr"}, tree: vrX, env: stub},
		{args: []string{"cleanup", "--older-than", "30"}, tree: tree{}.d(L+"ses-b").t(L+"ses-b", 30).d(L+"ses-c").t(L+"ses-c", 31)},
		{args: []string{"cleanup", "--older-than", "-5"}, tree: tree{}.d(L+"ses-new").t(L+"ses-new", 2)},
		{args: []string{"cleanup", "--older-than", "5"}, tree: tree{}.f(L+"ses-file", "x").t(L+"ses-file", 40).d(L+"ses-d").t(L+"ses-d", 40)},
		{args: R("--tier", "3", "--infra-token", "~/tok"), tree: tok},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "<HOME>/to=k"), tree: tok.f("to=k", "t")},
		{args: R("--tier", "3", "--repo", "~/r", "--infra-token", "~/tok", "--infra-endpoint", "https://smtp.example.org/x:1"), tree: tok},
		{args: R(), tree: tree{}.f(".sandbox/config.yaml", "blocked_cidrs:\n  - nope\n")},
		{args: R("--tier", "2", "--repo", "~/r"), tree: rg.f("r/node_modules/m.js", "m").f("r/build/o", "o").f("r/keep.txt", "k")},
		{args: R("--tier", "2", "--repo", "~/vr"), tree: honorDel, env: ov},
	} {
		addRun(cc)
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
