// gengate writes scenarios and cases for the secret_gate_repos differential:
// testdata/gate/scen/<name>/... and testdata/gate/cases.tsv.
// Usage: go run ./internal/gengate -base internal/gate/testdata/gate -seed 1 -n 60
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type obj = map[string]any

var weirdFiles = []string{"a b.txt", "it's.txt", "$x.txt", "~lead", "#hash", "a:b", "a=~b", "tab\tname", "new\nline", "é.txt", "back\\slash",
	"(paren)", "{brace}", "semi;colon", "star*", "x,y", "\u0001ctl", "\u007f", "日本 語", "zero​width", "q\"uote", "lt<gt>", "pipe|x", "amp&x", "bang!", "caret^", "bt`x", "[br]", "a?b", "plain.txt", "dir/sub dir/f.txt", ".hidden"}

func main() {
	base := flag.String("base", "", "testdata/gate directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 60, "random scenarios")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	scen := filepath.Join(*base, "scen")
	os.RemoveAll(scen)
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	put := func(name, file, content string) {
		d := filepath.Join(scen, name)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, file), []byte(content), 0o644)
	}
	f := func(file, rule string, line int, match string) obj {
		return obj{"File": "@REPO@/" + file, "RuleID": rule, "StartLine": line, "StartColumn": 1, "EndColumn": 9, "Match": match}
	}
	gcf := func(rule string, line int, match string) obj {
		return obj{"File": "@REPO@/.git/config", "RuleID": rule, "StartLine": line, "Match": match}
	}
	var names []string
	add := func(name, ws, gc string, wsrc, gcrc int) {
		names = append(names, name)
		put(name, "ws.json", ws)
		if gc != "" {
			put(name, "gc.json", gc)
		}
		if wsrc != 0 {
			put(name, "ws.rc", strconv.Itoa(wsrc))
		}
		if gcrc != 0 {
			put(name, "gc.rc", strconv.Itoa(gcrc))
		}
	}
	add("g-clean", "null", "[]", 0, 0)
	add("g-masked-only", js([]obj{f(".env", "k", 1, "R"), f("x-openrc.sh", "k", 1, "R"), f(".kube/config", "k", 1, "R"), f("privdir/x", "k", 1, "R"), f("secret.txt", "k", 1, "R")}), "", 0, 0)
	add("g-sealed-only", js([]obj{f("sealed.yaml", "k", 8, "R")}), "", 0, 0)
	add("g-unmasked-one", js([]obj{f("a.txt", "generic-api-key", 3, "REDACTED")}), "", 0, 0)
	add("g-accepted", js([]obj{f("a.txt", "rule-a", 3, "R"), f("src/x.py", "generic-api-key", 10, "R")}), "", 0, 0)
	var q []obj
	for i, w := range weirdFiles {
		q = append(q, f(w, []string{"r1", "", "rule x", "r\tt"}[i%4], i+1, []string{"REDACTED", "\"REDACTED\"", "REDACTED,", "", "plain text", "a\tb", "back\\slash", "é"}[i%8]))
	}
	add("g-quoting", js(q), "", 0, 0)
	add("g-gitconfig-only", "[]", js([]obj{gcf("url-cred", 7, "https://***@host"), gcf("", 8, ""), gcf("x y", 9, "REDACTED\"")}), 0, 0)
	add("g-mixed", js([]obj{f("a.txt", "r", 1, "R"), f(".env", "r", 1, "R"), f("sealed.yaml", "r", 8, "R"), f("u.txt", "r", 2, "R"), f("dir/it's here.txt", "r", 3, "")}), js([]obj{gcf("url-cred", 7, "R")}), 0, 0)
	add("g-empty-rule", js([]obj{f("a.txt", "", 3, "REDACTED"), f("u.txt", "", 4, "")}), "", 0, 0)
	add("g-err-ws", "null", "", 2, 0)
	add("g-err-gc", js([]obj{f("a.txt", "r", 1, "R")}), "garbage", 0, 3)
	add("g-dups", js([]obj{f("a.txt", "r", 1, "R"), f("a.txt", "r", 1, "R"), f("u.txt", "r", 1, "R"), f("u.txt", "r2", 1, "R")}), "", 0, 0)
	add("g-bad-ignore-error-text", "[]", "", 0, 0)
	// per-repo answers
	add("g-multi", "null", "", 0, 0)
	put("g-multi", "ws.r-base.json", js([]obj{f("a.txt", "r", 1, "R"), f("u.txt", "r", 2, "R")}))
	put("g-multi", "ws.r-masked.json", js([]obj{f("secret.txt", "r", 1, "R")}))
	put("g-multi", "gc.r-masked-link.json", js([]obj{gcf("url-cred", 7, "R")}))
	put("g-multi", "gc.json", "[]")
	add("g-multi-err", "[]", "[]", 0, 0)
	put("g-multi-err", "ws.r-masked.json", "null")
	put("g-multi-err", "ws.r-masked.rc", "2")
	put("g-multi-err", "ws.r-base.json", js([]obj{f("a.txt", "r", 1, "R")}))

	for i := 0; i < *n; i++ {
		var ws []obj
		for k, c := 0, rng.Intn(6); k < c; k++ {
			file := []string{"a.txt", ".env", "sealed.yaml", "u.txt", "ign.txt", "src/x.py", "secret.txt", ".git/HEAD", "privdir/x"}[rng.Intn(9)]
			if rng.Intn(3) == 0 {
				file = weirdFiles[rng.Intn(len(weirdFiles))]
			}
			line := rng.Intn(12)
			if file == "sealed.yaml" {
				line = 8
			}
			ws = append(ws, f(file, []string{"r", "rule-a", "", "x y", "generic-api-key"}[rng.Intn(5)], line,
				[]string{"R", "", "REDACTED", "\"REDACTED\"", "txt\tq"}[rng.Intn(5)]))
		}
		var gc []obj
		for k, c := 0, rng.Intn(3); k < c; k++ {
			gc = append(gc, gcf([]string{"u", "", "p q"}[rng.Intn(3)], rng.Intn(9), []string{"R", "", "REDACTED"}[rng.Intn(3)]))
		}
		wsrc, gcrc := 0, 0
		if rng.Intn(12) == 0 {
			wsrc = 2
		}
		if rng.Intn(12) == 0 {
			gcrc = 3
		}
		gcs := ""
		if rng.Intn(4) != 0 {
			gcs = js(gc)
			if gc == nil {
				gcs = "[]"
			}
		}
		wss := js(ws)
		if ws == nil {
			wss = "[]"
		}
		add(fmt.Sprintf("g-rnd-%03d", i), wss, gcs, wsrc, gcrc)
	}

	type c struct{ repos, accept, trusted, unvetted, vec, tty, legacy, accfix, scen, path string }
	var cases []c
	repoSets := []string{"r-base", "r-base,r-masked", "r-masked,r-masked-link,r-base", "r-base,r-base", "r-link,r-nocfg", "r-exclusions-off", "-"}
	b := []string{"false", "true"}
	odd := []string{"false", "true", "true", "false", "", "yes", "TRUE", "True"}
	// the full flag matrix on the scenarios that exercise every output branch
	for _, scn := range []string{"g-mixed", "g-quoting", "g-gitconfig-only", "g-multi", "g-clean", "g-masked-only", "g-err-ws"} {
		for _, rs := range repoSets[:4] {
			for _, acc := range b {
				for _, tr := range b {
					cases = append(cases, c{rs, acc, tr, "false", "false", "-", "-", "fp", scn, "stub"})
				}
			}
		}
	}
	// interactive prompt: replies x scenarios
	for _, scn := range []string{"g-mixed", "g-gitconfig-only", "g-unmasked-one", "g-clean", "g-quoting"} {
		for _, reply := range []string{"y", "Y", "yes please", "n", "", "EOF", "x", " y", "\\y"} {
			cases = append(cases, c{"r-base,r-masked", "false", "true", "false", "true", reply, "-", "-", scn, "stub"})
		}
		cases = append(cases, c{"r-base", "true", "true", "false", "false", "y", "-", "-", scn, "stub"}) // flag wins over prompt
	}
	for _, tr := range []string{"", "yes", "TRUE", "false"} {
		cases = append(cases, c{"r-base", "false", tr, "false", "false", "y", "-", "-", "g-unmasked-one", "stub"})
	}
	// the other switches
	for _, scn := range names {
		for _, vec := range b {
			cases = append(cases, c{repoSets[rng.Intn(len(repoSets)-1)], odd[rng.Intn(len(odd))], odd[rng.Intn(len(odd))], b[rng.Intn(2)], vec, "-", []string{"-", "yes", "nl"}[rng.Intn(3)], []string{"-", "fp", "empty"}[rng.Intn(3)], scn, "stub"})
		}
		cases = append(cases, c{"r-base", "false", "false", "false", "false", "-", "-", "fp", scn, "stub"})
	}
	for _, rs := range []string{"r-base", "-"} {
		cases = append(cases, c{rs, "false", "false", "false", "false", "-", "-", "-", "g-clean", "nostub"})
	}
	var rows []string
	for i, x := range cases {
		rows = append(rows, strings.Join([]string{fmt.Sprintf("g%04d", i), x.repos, x.accept, x.trusted, x.unvetted, x.vec, x.tty, x.legacy, x.accfix, x.scen, x.path}, "\t"))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d scenarios, %d cases\n", len(names), len(rows))
}
