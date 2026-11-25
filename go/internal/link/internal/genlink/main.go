// genlink writes the corpus for lib/link.sh: testdata/cases.tsv, one case per line,
// "id op arg1 arg2 arg3", each arg "=" + base64 (see oracle.sh for the ops).
//
// Usage: go run ./internal/link/internal/genlink -base internal/link/testdata -seed 1 -n 120
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

// tree builds an overlay spec: "f path content" / "d path" / "l path target" lines.
type tree []string

// clone copies t, so that every builder step returns a new slice (appending to a shared base with
// spare capacity would let sibling cases overwrite one another's last steps).
func (t tree) clone() tree { return append(tree(nil), t...) }

func (t tree) f(p, body string) tree { return append(t.clone(), enc("f")+" "+enc(p)+" "+enc(body)) }
func (t tree) d(p string) tree       { return append(t.clone(), enc("d")+" "+enc(p)) }
func (t tree) l(p, to string) tree   { return append(t.clone(), enc("l")+" "+enc(p)+" "+enc(to)) }
func (t tree) spec() string          { return strings.Join(t, "\n") }

const home = "/home/u"

func main() {
	base := flag.String("base", "internal/link/testdata", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 120, "random overlay trees")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	var rows []string
	add := func(op string, args ...string) {
		for len(args) < 3 {
			args = append(args, "")
		}
		rows = append(rows, fmt.Sprintf("l%04d\t%s\t%s\t%s\t%s", len(rows), op, enc(args[0]), enc(args[1]), enc(args[2])))
	}
	for _, nm := range []string{"team", "", "a/b", "..x", "a..b", ".h", "x.y_z-1", "café", "a b", "-n"} {
		add("name", nm)
	}
	for _, u := range []string{"git@host:org/team-overlay.git", "https://h/org/repo.git/", "https://h/org/repo", "git@host:repo.git",
		"file:///srv/x.git", "repo", "", "https://h/org/.git", "https://h/org/a..b.git", "ssh://h:22/r.git", "h:", "https://h/org/x.git.git"} {
		add("fromurl", u)
	}
	paths := []string{"~", "~/", "~/.", "~//", "~/.ssh", "~/repos/x", "/", "/.", "//", "/home", "/home/", "/home/u", "/home/u/",
		"/home/u/.", "/home/u//x", "/home/u/./x", "/home/u/../root", "rel", "rel/./x", "./", "", ".", "..", "/etc", "/etc/x", "/etcx",
		"/root", "/proc/1", "/sys", "/boot/efi", "/var/run/docker.sock", "/run", "/dev/sda", "/private/etc", "/ETC", "/Users", "/HOME/U",
		"~user", "/home/u/repos/.hidden/x", "/opt/.x", "/a/.", "/a/..b"}
	for _, h := range []string{home, home + "/", "/Users/U", ""} {
		for _, p := range paths {
			add("sens", h, p)
		}
	}
	for _, p := range paths {
		add("norm", home, p)
	}
	good := tree{}.f("profiles/dev.yaml", "tier: 2\n")
	trees := map[string]tree{
		"empty":          {},
		"good":           good,
		"full":           good.f("profiles/ops.yaml", "tier: 3\ndefault_repo: ~/repos/ops\nextra_allowed_domains:\n  - a.example.com\n  - b.example.com\n").f("catalogue/mcp.yaml", "kind: mcp\n").f("blocked-destinations.yaml", "blocked_domains: []\n").f("config.yaml", "vetting: required\nvetting_trust_root: signers.txt\nmin_sandbox_version: 1.2\nvetting_max_commits_behind: 5\nvetting_max_age_days: 30\nvetting_exceptions_require_head: true\nvetting_exceptions_from_commit: true\n").f("signers.txt", "a ssh-ed25519 AAAA\n# c\n\nb ssh-ed25519 BBBB\n").f("README.md", "x"),
		"one-cat":        good.f("catalogue/x.yaml", "kind: service\n"),
		"badtier":        good.f("profiles/t.yaml", "tier: 4\n"),
		"notier":         good.f("profiles/t.yaml", "name: x\n"),
		"badname":        good.f("profiles/a b.yaml", "tier: 1\n").f("catalogue/c d.yaml", "x\n"),
		"hiddenprof":     good.f("profiles/.hidden.yaml", "tier: 9\n"),
		"dirprof":        good.d("profiles/d.yaml"),
		"dangling":       good.l("profiles/gone.yaml", "nowhere.yaml"),
		"sens-ssh":       good.f("profiles/s.yaml", "tier: 1\ndefault_repo: ~/.ssh\n"),
		"sens-home":      good.f("profiles/s.yaml", "tier: 1\ndefault_repo: /home\n"),
		"sens-dock":      good.f("profiles/s.yaml", "tier: 1\ndefault_repo: /var/run/docker.sock\n"),
		"sens-root":      good.f("profiles/s.yaml", "tier: 1\ndefault_repo: '/'\n"),
		"link-abs":       good.l("profiles/x.yaml", "/etc/passwd"),
		"link-up":        good.l("data", "../outside"),
		"link-ok":        good.f("docs/a.md", "a").l("docs/b.md", "a.md"),
		"link-nl":        good.l("evil\nname", "/etc/passwd"),
		"link-nl-frag":   good.l("profiles/dev.yaml\nx", "/etc"),
		"link-git":       good.l(".git/hooks/h", "/bin/sh"),
		"unknown":        good.f("profile/x.yaml", "tier: 1\n").f("NOTES", "x").f(".hidden", "x"),
		"vet-typo":       good.f("config.yaml", "vetting: requird\n"),
		"troot-missing":  good.f("config.yaml", "vetting_trust_root: nope.txt\n"),
		"troot-zero":     good.f("config.yaml", "vetting_trust_root: s.txt\n").f("s.txt", "# only\n\n"),
		"troot-abs":      good.f("config.yaml", "vetting_trust_root: /nonexistent/x\n"),
		"troot-tilde":    good.f("config.yaml", "vetting_trust_root: ~/x\n"),
		"troot-home":     good.f("config.yaml", "vetting_trust_root: ~/s.txt\n").f("../home/s.txt", "a k\n"),
		"troot-nonl":     good.f("config.yaml", "vetting_trust_root: s.txt\n").f("s.txt", "a k\r\nb k"),
		"knobs-bad":      good.f("config.yaml", "vetting_max_commits_behind: 5x\nvetting_max_age_days: -1\nvetting_exceptions_require_head: yes\nvetting_exceptions_from_commit: 1\n"),
		"knobs-false":    good.f("config.yaml", "vetting_exceptions_require_head: false\nvetting_exceptions_from_commit: false\n"),
		"cfg-dir":        good.d("config.yaml"),
		"minver":         good.f("config.yaml", "min_sandbox_version: 9.9\n"),
		"problems+warn":  good.f("profiles/t.yaml", "tier: 0\nextra_allowed_domains:\n  - x.com\n").f("config.yaml", "vetting: x\n"),
		"domains-only":   good.f("profiles/o.yaml", "tier: 1\nextra_allowed_domains:\n  - x.com\n  - -n\n"),
		"profiles-file":  tree{}.f("profiles", "x"),
		"catalogue-file": good.f("catalogue", "x"),
	}
	var keys []string
	for k := range trees {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		add("validate", trees[k].spec(), k)
	}
	parts := []func(t tree, i int) tree{
		func(t tree, i int) tree {
			return t.f(fmt.Sprintf("profiles/p%d.yaml", i), fmt.Sprintf("tier: %d\n", rng.Intn(5)))
		},
		func(t tree, i int) tree {
			return t.f(fmt.Sprintf("profiles/r%d.yaml", i), "tier: 1\ndefault_repo: "+paths[rng.Intn(len(paths))]+"\n")
		},
		func(t tree, i int) tree { return t.f(fmt.Sprintf("catalogue/c%d.yaml", i), "kind: mcp\n") },
		func(t tree, i int) tree { return t.f(fmt.Sprintf("x%d", i), "") },
		func(t tree, i int) tree {
			return t.f("config.yaml", []string{"vetting: off\n", "vetting: bogus\n", "vetting_max_age_days: 7\n", "min_sandbox_version: 2\n"}[rng.Intn(4)])
		},
		func(t tree, i int) tree {
			return t.f(fmt.Sprintf("profiles/d%d.yaml", i), "tier: 2\nextra_allowed_domains:\n  - d"+fmt.Sprint(i)+".com\n")
		},
	}
	for i := 0; i < *n; i++ {
		t := tree{}
		for j, k := 0, 1+rng.Intn(5); j < k; j++ {
			t = parts[rng.Intn(len(parts))](t, j)
		}
		add("validate", t.spec(), fmt.Sprintf("r%d", i))
	}
	none := "\x01"
	for _, uc := range []string{none, "", "overlay: /old\nlink_url: x\n", "# overlay: c\nlink_ref: a\nlink_ref: b\n"} {
		for i, d := range []string{"/m/team", "~/x", "a\\nb"} {
			add("wcfg", uc, d, fmt.Sprint(i))
		}
	}
	for _, uc := range []string{none, "overlay: /m/team\nlink_url: u\nlink_ref: r\nlink_commit: c\nother: 1\n", "overlay: ~/m/team\nlink_url: u\n",
		"overlay: /elsewhere\nlink_url: u\nlink_ref: r\n", "link_url: u\n"} {
		for _, m := range []string{"/m/team", "<HOME>/m/team"} {
			add("ccfg", uc, m)
		}
	}
	for _, a := range [][2]string{{none, ""}, {"link_url: u\noverlay: ~/ov\n", "ov/.git"}, {"link_url: u\noverlay: ~/ov\n", "ov"},
		{"overlay: ~/ov\n", "ov/.git"}, {"link_url: u\n", ""}, {"link_url: u\noverlay: ~/ov\nlink_ref: main\nlink_commit: abc\n", "ov/.git"},
		{"link_url: ''\noverlay: ~/ov\n", "ov/.git"}, {"link_url: u\noverlay: ~/ov\n", "file:ov/.git"}} {
		add("active", a[0], a[1])
	}
	for _, s := range []string{"same", "advance", "advance-tag", "invalid", "sensitive", "minver", "minver-ok", "minver-bad", "dirty",
		"untracked", "offline", "missing-ref", "sha-ref", "no-check", "inactive", "not-git", "tilde"} {
		add("sync", s, "")
		if strings.HasPrefix(s, "minver") {
			add("sync", s, "50.0")
			add("sync", s, "dev")
		}
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
