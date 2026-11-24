// genaudit writes the corpus for the session-record half of lib/audit.sh: testdata/cases.tsv,
// one case per line, "id steps" (see oracle.sh for the step letters).
//
// Usage: go run ./internal/audit/internal/genaudit -base internal/audit/testdata -seed 1 -n 150
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

func step(fields ...string) string {
	var w []string
	for _, f := range fields {
		w = append(w, enc(f))
	}
	return strings.Join(w, " ")
}

var (
	write = [][]string{
		{"W", "ses-1", "claude", "2", "alice", "/home/a/repo", "dev", "pod-1", "2026-01-01T00:00:00Z", "github.com", "pypi.org"},
		{"W", "ses-2", "codex", "1", "bob", "", "", "", "2026-01-01T00:00:00Z"},
		{"W", "ses-3", "copilot", "3", "carol", `["/r/a","/r/b"]`, "n", "p", "t"},
		{"W", "ses-4", "claude", "2", "d\"q\\x", "/repo with space", "na\tme", "p\nod", "t", "a\"b", "c"},
		{"W", "ses-5", "claude", "2", "u", "/r", "", "", "t", `evil\x2ecom`},
		{"W", "ses-6", "claude", "2", "u", "/r", "", "", "t", `a.b.com`},
		{"W", "ses-7", "claude", "2", "u", "/r", "", "", "t", `x","injected.com`},
		{"W", "ses-8", "claude", "3", "ü", "[]", "é", "\x01\x7f", "t", "*.example.com", ""},
		{"W", "ses-9", "claude", "2", "u", "/r", "", "", "t", "tab\there"},
	}
	envs = [][]string{
		{"V", "SESSION_PROFILE", "dev"}, {"V", "SESSION_OVERLAY", "/ov"}, {"V", "SESSION_KUBE_API_CIDR", "10.0.0.1/32"},
		{"V", "SESSION_KUBE_API_PORT", "6443"}, {"V", "SESSION_KUBE_API_CONTEXTS", "a,b"}, {"V", "SESSION_KUBE_HOST_ENTITY", "true,false"},
		{"V", "SESSION_INFRA_TOKEN", "x"}, {"V", "SESSION_INFRA_KUBECONFIG", "/k"},
	}
	edits = [][]string{
		{"O", "flag:--i-accept-unvetted", "unvetted repo", "/a/r1", "/b/r2/", ""},
		{"O", "interactive-prompt", "drift \"x\"", "/"},
		{"O", "flag:--i-accept-unmasked-secrets", "secrets"},
		{"F"}, {"E", "2026-01-01T01:00:00Z"}, {"R", "evicted", "The node was low on memory."}, {"R", "", "ignored"},
		{"A", "conv-123"}, {"D", `[{"name":"db","version":"1.2","egress":["a.com"],"up_time":"t1"}]`}, {"D", `[]`},
		{"D", `{"not":"array"}`}, {"D", `[1, null]`}, {"D", `not json`}, {"D", `[{"down_time":"old","x":1.50}]`},
		{"d", "2026-01-01T02:00:00Z"}, {"G", "info", "hello"}, {"G", "warn", "multi\nline \"q\" \\ \x02"},
		{"E", "second-end"},
	}
	raws = []string{
		"", "{}", "null", "[]", "\"s\"", "{\"events\":\"str\"}", "{\"events\":null}", "{\"events\":[1]}", "{\"a\":1}{\"b\":2}",
		"{\"a\":1,\"a\":2}", "{\"dependencies\":[{\"n\":1},null]}", "{\"dependencies\":[1]}", "{\"truncated\":", "{\"n\":1.50,\"z\":-0}",
		" \n{\"x\" : [ 1 , 2 ] }\n", "{\"s\":\"\\u00e9\\n\"}",
	}
)

func main() {
	base := flag.String("base", "internal/audit/testdata", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 150, "random step sequences")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	var rows []string
	add := func(steps ...string) {
		rows = append(rows, fmt.Sprintf("a%04d\t%s", len(rows), enc(strings.Join(steps, "\n"))))
	}
	for _, w := range write {
		add(step(w...))
		var s []string
		for _, e := range envs {
			s = append(s, step(e...))
		}
		add(append(s, step(w...))...)
	}
	for _, e := range edits { // each edit on a fresh record, and with no record at all
		add(step(write[0]...), step(e...))
		add(step(e...))
	}
	for _, e := range edits { // overrides flushed, dependencies stamped down
		switch e[0] {
		case "O":
			add(step(write[0]...), step(e...), step("F"))
		case "D":
			add(step(write[0]...), step(e...), step("d", "down"))
		}
	}
	add(step(write[0]...), step("G", "t\tab", "a\tb"))
	for _, r := range raws {
		for _, e := range [][]string{{"E", "t"}, {"G", "x", "y"}, {"O", "m", "w"}, {"F"}, {"d", "t"}, {"R", "r", "d"}} {
			if e[0] == "F" {
				add(step("O", "m", "w"), step("X", r), step("F"))
				continue
			}
			add(step("X", r), step(e...))
		}
	}
	add(step("K", "ses-b", "dir"), step("K", "ses-a", "dir"), step("K", "ses-f", "file"), step("K", "ses-l", "link"),
		step("K", "ses-d", "dangling"), step("K", "other", "dir"), step("K", "ses-", "dir"), step("K", "sesx", "dir"), step("S"))
	add(step("S"))
	add(step("N"))
	for i := 0; i < *n; i++ {
		s := []string{}
		if rng.Intn(4) > 0 {
			for _, e := range envs {
				if rng.Intn(3) == 0 {
					s = append(s, step(e...))
				}
			}
			s = append(s, step(write[rng.Intn(len(write))]...))
		} else {
			s = append(s, step("X", raws[rng.Intn(len(raws))]))
		}
		for j, k := 0, 1+rng.Intn(6); j < k; j++ {
			s = append(s, step(edits[rng.Intn(len(edits))]...))
		}
		add(s...)
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
