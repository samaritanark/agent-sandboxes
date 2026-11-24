// genwrite writes the corpus for the config writers and the remaining lib/config.sh readers:
// fixture files (testdata/write/fx/*) and cases.tsv, one case per line:
//
//	id  op  fixture  mode  arg1  arg2
//
// op is rmscalar, rmlist, addmask, addfp, ignfile, honor or envdom (see oracle.sh). fixture is a
// file under fx/ or "-" (none). mode is the fixture's permission bits. Each arg is "=" followed by
// its base64, so that newlines, tabs and quotes survive the TSV.
//
// Usage: go run ./internal/config/internal/genwrite -base internal/config/testdata/write -seed 1 -n 40
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// hand-written YAML fixtures, each aimed at one edge of a writer.
var yamls = map[string]string{
	"empty":       "",
	"basic":       "overlay: /o\nlink_url: u\nmasked_paths:\n  - a.txt\n  - dir/\nextra_allowed_domains:\n  - git.example.com\n",
	"nonl":        "masked_paths:\n  - a.txt",
	"nomask":      "overlay: x\n",
	"nomask-nonl": "overlay: x",
	"crlf":        "masked_paths:\r\n  - a.txt\r\noverlay: y\r\naccepted_secrets:\r\n  - a:r:1:h\r\n",
	"col0":        "masked_paths:\n  - keep\naccepted_secrets:\n- a.txt:r:1:h\n- b.txt:r:2:h\nother: 1\n",
	"col0-first":  "accepted_secrets:\n- a.txt:r:1:h\n  - b.txt:r:2:h\nmasked_paths:\n- m\n",
	"blanks":      "accepted_secrets:\n  - x\n\n  - y\n\n\nfoo: 1\n",
	"comments":    "# top\naccepted_secrets:\n  # why\n  - x\n# about foo\nfoo: 1\n",
	"col0-cmt":    "accepted_secrets:\n- a\n# note\n- b\n\n# about next\nnext: 1\n",
	"twice":       "accepted_secrets:\n  - a\nmasked_paths:\n  - m\naccepted_secrets:\n  - b\n",
	"tail":        "foo: 1\naccepted_secrets:\n  - a\n",
	"tailblank":   "accepted_secrets:\n  - a\n\n",
	"nested":      "accepted_secrets:\n  nested: x\n  - a\nz: 1\n",
	"inline":      "accepted_secrets: [a, b]\nmasked_paths: []\nk: v\n",
	"commented":   "# overlay: old\noverlay: new\n#masked_paths:\n# accepted_secrets:\n",
	"prefix":      "overlay_extra: 1\noverlayx: 2\noverlay: 3\n  overlay: 4\nmasked_paths_x:\n  - no\n",
	"dupes":       "overlay: a\noverlay: b\nlink_ref: r\nlink_url: u\nlink_ref: s\n",
	"quoted":      "masked_paths:\n  - \"a.txt\"\n  - 'b.txt'\n  - \"-n\"\n  - \"a #b\"\n",
	"echoopt":     "masked_paths:\n  -n\n  - \"we\"ird\"\n",
	"tabs":        "masked_paths:\n\t- t.txt\naccepted_secrets:\n\t- a\n \t\n\tz: 1\n",
	"nul":         "overlay: a\x00b\nmasked_paths:\n  - n\x00ul\n",
	"unicode":     "masked_paths:\n  - café\n# ü\naccepted_secrets:\n  - 日本:r:1:h\n",
	"keyonly":     "masked_paths:",
	"ws-end":      "masked_paths:\n  - a \t\n",
	"nul-end":     "overlay: x\nk: a\x00",
}

// ignore-file fixtures (betterleaks fingerprints).
var ignores = map[string]string{
	"ign-basic":  "a.txt:r:1\n# c\n  b.txt:r:2  \n",
	"ign-nonl":   "x:y:1",
	"ign-empty":  "",
	"ign-cmt":    "# only\n",
	"ign-crlf":   "a.txt:r:1\r\n",
	"ign-blanks": "\n\n a.txt:r:1\n\n",
	"ign-hash":   "#a.txt:r:1\na.txt:r:1 # note\n",
	"ign-nul":    "a.txt:r:1\x00",
}

// overlay configs for honor_repo_allowed_domains.
var overlays = map[string]string{
	"ov-true":     "honor_repo_allowed_domains: true\n",
	"ov-dquote":   "honor_repo_allowed_domains: \"true\"\n",
	"ov-squote":   "honor_repo_allowed_domains: 'true'\n",
	"ov-cap":      "honor_repo_allowed_domains: True\n",
	"ov-comment":  "honor_repo_allowed_domains: true # yes\n",
	"ov-glued":    "honor_repo_allowed_domains:true\n",
	"ov-yes":      "honor_repo_allowed_domains: yes\n",
	"ov-first":    "honor_repo_allowed_domains: false\nhonor_repo_allowed_domains: true\n",
	"ov-indent":   "  honor_repo_allowed_domains: true\n",
	"ov-crlf":     "honor_repo_allowed_domains: true\r\n",
	"ov-absent":   "overlay: x\n",
	"ov-trailing": "honor_repo_allowed_domains: true   \n",
}

// user configs for load_user_extra_allowed_domains.
var users = map[string]string{
	"uc-list":  "extra_allowed_domains:\n  - a.example.com\n  - '*.b.com'\n  - -n\n",
	"uc-other": "masked_paths:\n  - x\n",
}

var (
	scalarKeys = []string{"overlay", "link_url", "link_ref", "masked_paths", "absent_key"}
	listKeys   = []string{"accepted_secrets", "masked_paths", "extra_allowed_domains", "absent_key"}
	// No backslash escape awk handles differently in gawk and mawk (\q, a trailing \).
	relpaths = []string{
		"a.txt", "new.txt", "dir/", "with space.txt", `we"ird`, "it's", "a #b", "a#b",
		`x\ny`, `t\tx`, `back\\slash`, `q\"q`, `oct\101`, "-n", "-e", "#lead", " lead", "trail ",
		"日本/", "real\nnewline", "x\nextra_allowed_domains:\n  - evil.com", "cr\rx", "",
	}
	fps = []string{
		"a.txt:r:1", "new.txt:r:9", " a.txt:r:1", "b.txt:r:2", "x:y:1", "#c:r:1",
		"two\nlines:r:1", "a.txt:r:1 # note", "",
	}
	reasons  = []string{"", "why", "#hashed", "#  two", " lead", "multi\nline", "cr\rx", "-n", "#"}
	layouts  = []string{"", "B", "G", "BG", "bG", "gB", "b", "g", "bg"}
	honorHow = []string{"env", "user", "user-tilde", "none", "env-empty"}
	envVals  = []string{
		"", "a.com", "a.com,b.com", " a.com , b.com ", "a b.com", ",,a.com,", "*.example.com",
		"?1", "[ab]1", "[!a]1", ".h*", "*", "*.nomatch", "-n,-e,ok.com", " -n", "x,", "a.com\tb.com",
		"\\*.example.com", "a.com,*,b.com",
	}
)

var frags = []string{
	"masked_paths:\n", "accepted_secrets:\n", "overlay: /x\n", "link_url: u\n", "  - a.txt\n",
	"- col0\n", "  # c\n", "# c\n", "\n", "  \n", "other: 1\n", "  - \"q #x\"\n", "masked_paths_x:\n",
	"\t- tab\n", "  nested: 1\n", "link_ref: r", "extra_allowed_domains:\n", "  - d.com\n",
}

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func main() {
	base := flag.String("base", "internal/config/testdata/write", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 40, "random YAML fixtures")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	fx := filepath.Join(*base, "fx")
	os.RemoveAll(fx)
	os.MkdirAll(fx, 0o755)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(fx, name), []byte(body), 0o644); err != nil {
			panic(err)
		}
	}
	sorted := func(m map[string]string) []string {
		var k []string
		for x := range m {
			k = append(k, x)
		}
		sort.Strings(k)
		return k
	}
	var hand, random []string
	for _, k := range sorted(yamls) {
		write("y-"+k, yamls[k])
		hand = append(hand, "y-"+k)
	}
	for i := 0; i < *n; i++ {
		var sb strings.Builder
		for j, m := 0, 2+rng.Intn(8); j < m; j++ {
			sb.WriteString(frags[rng.Intn(len(frags))])
		}
		name := fmt.Sprintf("r-%03d", i)
		write(name, sb.String())
		random = append(random, name)
	}
	for _, m := range []map[string]string{ignores, overlays, users} {
		for _, k := range sorted(m) {
			write(k, m[k])
		}
	}

	var rows []string
	id := 0
	add := func(op, fixture, mode, a1, a2 string) {
		rows = append(rows, fmt.Sprintf("c%04d\t%s\t%s\t%s\t%s\t%s", id, op, fixture, mode, enc(a1), enc(a2)))
		id++
	}
	mode := func() string { return []string{"644", "600", "640"}[rng.Intn(3)] }
	pick := func(s []string) string { return s[rng.Intn(len(s))] }

	for _, f := range hand {
		for _, k := range scalarKeys {
			add("rmscalar", f, mode(), k, "")
		}
		for _, k := range listKeys {
			add("rmlist", f, mode(), k, "")
		}
		for _, p := range relpaths {
			add("addmask", f, mode(), p, "")
		}
	}
	for _, f := range random {
		for i := 0; i < 2; i++ {
			add("rmscalar", f, mode(), pick(scalarKeys), "")
			add("rmlist", f, mode(), pick(listKeys), "")
		}
		for i := 0; i < 3; i++ {
			add("addmask", f, mode(), pick(relpaths), "")
		}
	}
	add("rmscalar", "-", "-", "overlay", "")
	add("rmlist", "-", "-", "accepted_secrets", "")
	for _, p := range relpaths {
		add("addmask", "-", "-", p, "")
	}
	for _, f := range append([]string{"-"}, sorted(ignores)...) {
		for _, fp := range fps {
			add("addfp", f, mode(), fp, pick(reasons))
		}
	}
	for _, r := range reasons {
		add("addfp", "-", "-", "a.txt:r:1", r)
		add("addfp", "ign-basic", "644", "c.txt:r:3", r)
	}
	for _, l := range layouts {
		add("ignfile", "ign-basic", "644", l, "")
		add("ignfile", "ign-hash", "644", l, "")
	}
	for _, h := range honorHow {
		for _, f := range append([]string{"-"}, sorted(overlays)...) {
			add("honor", f, "644", h, "")
		}
	}
	for _, u := range []string{"-", "uc-list", "uc-other"} {
		for _, v := range envVals {
			add("envdom", u, "644", v, "")
		}
	}
	if err := os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%d hand + %d random YAML fixtures, %d cases\n", len(hand), len(random), len(rows))
}
