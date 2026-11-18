// genscan writes the scenarios and cases for the scan_repo_secrets differential:
// testdata/scan/scen/<name>/{ws,gc}.{json,rc} and testdata/scan/cases.tsv.
// Usage: go run ./internal/genscan -base internal/gate/testdata/scan -seed 1 -n 250
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var (
	files = []string{"a.txt", ".env", "sealed.yaml", "sops.yaml", "src/x.py", "u.txt", "ign.txt", "secret.txt", "privdir/x", "x-openrc.sh",
		".kube/config", ".git/HEAD", ".git/config", ".git/x/y", "vendor/v.js", "node_modules/p/i.js", "ünï/.venv/x", "missing.txt", "a b.txt", "dir/../a.txt", ".gitx/a"}
	rules   = []string{"generic-api-key", "rule-a", "aws-access-token", "a:b", "", "r\tt", "x y"}
	matches = []string{"REDACTED", "", "a\tb", "line1\nline2", "back\\slash", "é日本", "x\ry", "ghp_***", "null", "tab\t", "\tlead", "a  b", "\\t"}
	ints    = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 999}
)

type obj = map[string]any

func main() {
	base := flag.String("base", "", "testdata/scan directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 250, "random scenarios")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	scen := filepath.Join(*base, "scen")
	os.RemoveAll(scen)
	write := func(name, kind, content string, rc int) {
		d := filepath.Join(scen, name)
		os.MkdirAll(d, 0o755)
		if content != "\x00none" {
			os.WriteFile(filepath.Join(d, kind+".json"), []byte(content), 0o644)
		}
		if rc != 0 {
			os.WriteFile(filepath.Join(d, kind+".rc"), []byte(strconv.Itoa(rc)), 0o644)
		}
	}
	fixtureCols := func(name string, line int, tok string) (int, int) {
		b, err := os.ReadFile(filepath.Join(*base, "..", "encrypted", "fixtures", name))
		if err != nil {
			panic(err)
		}
		l := strings.Split(string(b), "\n")[line-1]
		i := strings.Index(l, tok)
		return i + 2, i + len(tok) + 1 // as colspan_of in the bash tests
	}
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	f := func(file, rule string, line, sc, ec int, match string) obj {
		return obj{"File": "@REPO@/" + file, "RuleID": rule, "StartLine": line, "StartColumn": sc, "EndColumn": ec, "Match": match}
	}
	sc, ec := fixtureCols("sops.yaml", 6, "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z")

	hand := map[string][2]string{} // name -> ws, gc ("" = no file)
	hand["clean-null"] = [2]string{"null", ""}
	hand["clean-empty-array"] = [2]string{"[]", "[]"}
	hand["one-of-each"] = [2]string{js([]obj{
		f("sealed.yaml", "generic-api-key", 8, 0, 0, "REDACTED"), f("sops.yaml", "generic-api-key", 6, sc, ec, "REDACTED"),
		f(".env", "generic-api-key", 1, 1, 9, "REDACTED"), f("a.txt", "rule-a", 3, 1, 5, "REDACTED"), f("src/x.py", "generic-api-key", 10, 1, 5, "R"),
		f("u.txt", "rule-a", 3, 1, 5, "R"), f("ign.txt", "rule-a", 3, 1, 5, "R"), f("secret.txt", "rule-a", 3, 1, 5, "R"), f("privdir/x", "r", 1, 1, 2, "R"),
		f(".git/HEAD", "r", 1, 1, 2, "R"), f("a.txt", "other", 9, 1, 5, "R"),
	}), js([]obj{{"File": "@REPO@/.git/config", "RuleID": "url-cred", "StartLine": 7, "Match": "https://***@host"}})}
	hand["err-rc2"] = [2]string{"null", ""}
	hand["bad-json"] = [2]string{"[{\"File\":", ""}
	hand["not-array"] = [2]string{"{\"File\":\"x\"}", ""}
	hand["stream"] = [2]string{"[]\n" + js([]obj{f("a.txt", "rule-a", 3, 1, 5, "R")}), ""}
	hand["stream-last-not-array"] = [2]string{js([]obj{f("a.txt", "rule-a", 3, 1, 5, "R")}) + "\nnull", ""}
	hand["gc-only"] = [2]string{"[]", js([]obj{{"File": "@REPO@/.git/config", "RuleID": "x", "StartLine": 1, "Match": "m"}, {"File": "", "RuleID": "skipped"}, {"File": "@REPO@/.git/config", "RuleID": "y", "StartLine": "2", "Match": ""}})}
	hand["empty-fields"] = [2]string{js([]obj{{"File": "@REPO@/a.txt", "RuleID": "", "StartLine": 3, "Match": ""}, {"File": "", "RuleID": "r", "StartLine": 1}, {"RuleID": "r"}, {}, nil}), ""}
	hand["bad-element"] = [2]string{js([]any{f("a.txt", "rule-a", 3, 1, 5, "R"), 5, f("a.txt", "rule-a", 4, 1, 5, "R")}), ""}
	hand["nested-match"] = [2]string{js([]any{f("a.txt", "rule-a", 3, 1, 5, "R"), obj{"File": "@REPO@/a.txt", "RuleID": "r", "StartLine": 1, "Match": []int{1}}, f("a.txt", "rule-a", 4, 1, 5, "R")}), ""}
	hand["object-top"] = [2]string{js(obj{"k1": f("a.txt", "rule-a", 3, 1, 5, "R"), "k0": f("u.txt", "rule-a", 3, 1, 5, "R")}), ""}
	hand["prefix-confusion"] = [2]string{js([]obj{{"File": "@REPO@-other/a.txt", "RuleID": "rule-a", "StartLine": 3, "Match": "R"}, {"File": "a.txt", "RuleID": "rule-a", "StartLine": 3, "Match": "R"}, {"File": "@REPO@", "RuleID": "r", "StartLine": 1, "Match": "R"}}), ""}
	hand["tsv-escapes"] = [2]string{js([]obj{f("a.txt", "r\tt", 3, 1, 5, "a\tb\nc\\d\re")}), ""}
	hand["numbers-as-strings"] = [2]string{js([]obj{{"File": "@REPO@/sops.yaml", "RuleID": "g", "StartLine": "6", "StartColumn": strconv.Itoa(sc), "EndColumn": strconv.Itoa(ec), "Match": "R"}}), ""}
	for name, v := range hand {
		ws, gc := v[0], v[1]
		if ws == "" {
			ws = "\x00none"
		}
		if gc == "" {
			gc = "\x00none"
		}
		rc := 0
		switch name {
		case "err-rc2":
			rc = 2
		}
		write(name, "ws", ws, rc)
		write(name, "gc", gc, 0)
	}
	write("rc1-valid", "ws", js([]obj{f("a.txt", "rule-a", 3, 1, 5, "R")}), 1)
	write("rc1-valid", "gc", js([]obj{{"File": "@REPO@/.git/config", "RuleID": "x", "StartLine": 1, "Match": "m"}}), 1)
	write("rc1-invalid", "ws", "garbage", 1)
	write("rc1-empty", "ws", "\x00none", 1)
	write("rc1-nonarray", "ws", "null", 1)
	write("rc127", "ws", "[]", 127)
	write("gc-fails", "ws", "[]", 0)
	write("gc-fails", "gc", "oops", 1)
	write("ws-ok-gc-rc3", "ws", js([]obj{f("a.txt", "rule-a", 3, 1, 5, "R")}), 0)
	write("ws-ok-gc-rc3", "gc", "[]", 3)

	randVal := func(pool []string) string { return pool[rng.Intn(len(pool))] }
	randObj := func() any {
		switch rng.Intn(40) {
		case 0:
			return 5
		case 1:
			return "str"
		case 2:
			return []int{1}
		case 3:
			return nil
		}
		o := obj{}
		file := randVal(files)
		switch rng.Intn(12) {
		case 0:
			file = "" // empty
		case 1:
			file = "../outside/" + file
		}
		o["File"] = "@REPO@/" + file
		if rng.Intn(15) == 0 {
			o["File"] = file
		}
		o["RuleID"] = randVal(rules)
		var line any = ints[rng.Intn(len(ints))]
		if rng.Intn(10) == 0 {
			line = strconv.Itoa(line.(int))
		}
		o["StartLine"] = line
		if file == "sops.yaml" && rng.Intn(2) == 0 {
			o["StartLine"], o["StartColumn"], o["EndColumn"] = 6, sc+rng.Intn(3)-1, ec+rng.Intn(3)-1
		} else {
			o["StartColumn"], o["EndColumn"] = rng.Intn(20), rng.Intn(40)
		}
		o["Match"] = randVal(matches)
		for _, k := range []string{"File", "RuleID", "StartLine", "StartColumn", "EndColumn", "Match"} {
			if rng.Intn(25) == 0 {
				delete(o, k)
			} else if rng.Intn(60) == 0 {
				o[k] = nil
			}
		}
		if rng.Intn(50) == 0 {
			o["Match"] = obj{"a": 1}
		}
		if rng.Intn(10) == 0 {
			o["Extra"] = "x"
		}
		return o
	}
	randReport := func(gc bool) (string, int) {
		shape := rng.Intn(30)
		var arr []any
		for i, k := 0, rng.Intn(7); i < k; i++ {
			o := randObj()
			if gc {
				if m, ok := o.(obj); ok {
					m["File"] = "@REPO@/.git/config"
				}
			}
			arr = append(arr, o)
		}
		rc := 1
		if rng.Intn(5) == 0 {
			rc = 0
		}
		switch {
		case shape == 0:
			return "\x00none", rc
		case shape == 1:
			return "null", rc
		case shape == 2:
			return "{}", rc
		case shape == 3:
			return "[{\"File\": \"@REPO@/a.txt\"", rc
		case shape == 4:
			return js(arr) + "\n" + js(arr), rc
		case shape == 5:
			return "", rc
		case shape == 6:
			return js(arr), []int{2, 3, 127}[rng.Intn(3)]
		}
		return js(arr), rc
	}
	var names []string
	for i := 0; i < *n; i++ {
		name := fmt.Sprintf("rnd-%04d", i)
		names = append(names, name)
		ws, rc := randReport(false)
		write(name, "ws", ws, rc)
		if rng.Intn(3) != 0 {
			gc, rc2 := randReport(true)
			write(name, "gc", gc, rc2)
		}
	}

	// ---- cases ----
	type env struct{ repo, ov, uc, acc string }
	var rows []string
	add := func(scn string, e env) {
		rows = append(rows, strings.Join([]string{fmt.Sprintf("c%05d", len(rows)), e.repo, e.ov, e.uc, e.acc, scn}, "\t"))
	}
	repos := []string{"r-base", "r-link", "r-exclusions-off", "r-ign-rel", "r-ign-abs", "r-ign-dotdot", "r-ign-mid", "r-gl-abs", "r-gl-rel", "r-both", "r-nocfg", "r-masked", "r-masked-link"}
	ovs := []string{"-", "plain", "noconfig", "extra", "inlineoff", "inlineon", "inlinefalse", "url", "url-toml", "toml", "dottoml", "ign", "ign-fallback"}
	ucs := []string{"-", "pin", "pin-wrong-src", "pin-wrong-hash", "excl-off", "overlay-extra", "overlay-tilde"}
	accs := []string{"-", "fp", "empty"}
	// every environment dimension against two scenarios
	for _, scn := range []string{"one-of-each", "rc1-valid"} {
		for _, r := range repos {
			add(scn, env{r, "-", "-", "fp"})
		}
		for _, o := range ovs {
			for _, u := range ucs {
				add(scn, env{"r-base", o, u, "-"})
			}
		}
		for _, a := range accs {
			add(scn, env{"r-masked", "plain", "-", a})
		}
	}
	// every scenario in the base environment, plus randomised environments
	all := make([]string, 0)
	ents, _ := os.ReadDir(scen)
	for _, e := range ents {
		all = append(all, e.Name())
	}
	sort.Strings(all)
	for _, scn := range all {
		add(scn, env{"r-base", "-", "-", "fp"})
		for k := 0; k < 2; k++ {
			add(scn, env{repos[rng.Intn(len(repos))], ovs[rng.Intn(len(ovs))], ucs[rng.Intn(len(ucs))], accs[rng.Intn(len(accs))]})
		}
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d scenarios, %d cases\n", len(all), len(rows))
}
