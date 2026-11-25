// genallowlist writes testdata/cases.tsv for the allowlist corpus: one case per line,
// "id agent tier layout extras" (extras: "=" + base64 of the NUL-joined list; layout as in the
// checks corpus, naming fixtures from go/internal/checks/testdata/fx).
//
// Usage: go run ./internal/allowlist/internal/genallowlist -base internal/allowlist/testdata [-n N]
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

func enc(xs []string) string {
	s := ""
	for _, x := range xs {
		s += x + "\x00"
	}
	return "=" + base64.StdEncoding.EncodeToString([]byte(s))
}

func main() {
	base := flag.String("base", "internal/allowlist/testdata", "testdata directory")
	n := flag.Int("n", 150, "random cases")
	flag.Parse()
	type cs struct {
		agent, tier, layout string
		extras              []string
	}
	var cases []cs
	agents := []string{"claude", "codex", "copilot", "grok", "opencode", "bogus"}
	layouts := []string{"o=org-a", "o=org-a,u=uc-a", "o=org-a,b=ov-a", "o=org-a,u=uc-a,b=ov-a", "o=-", "o=org-b", "o=REAL"}
	for _, a := range agents {
		for _, t := range []string{"1", "2", "3", "x"} {
			cases = append(cases, cs{a, t, "o=org-a", nil})
		}
	}
	hand := [][]string{
		{"*.gitea.com"}, {"*.aws.amazon.com"}, {"*.co.uk"}, {"*.com"}, {"*."}, {"*"}, {"*.Gitea.COM."},
		{"*.evil.com"}, {"*.user-blocked.org"}, {"*.ov-blocked.com"}, {"*.x.prod.example.com"}, {"*.discord.com"},
		{"*.gitea.com", "gitea.com"}, {"gitea.com", "*.gitea.com"}, {"a.example.org", "a.example.org"},
		{"api.anthropic.com"}, {"", " ", "\t", "x.example.org"}, {"a\nb.example.org", "b.example.org"},
		{"*.a\nb.org"}, {"*.github.io"}, {"*.foo.github.io"}, {"*.sub.example.co.uk"}, {"*.example.co.uk"},
		{"*.*.example.org"}, {"*.metadata.google.internal"}, {"*.smtp.example.org"}, {"*.EVIL.org"},
	}
	for _, h := range hand {
		for _, l := range layouts {
			cases = append(cases, cs{"claude", "2", l, h})
		}
	}
	pool := []string{"*.gitea.com", "gitea.com", "*.example.org", "example.org", "x.example.org", "*.co.uk",
		"*.example.co.uk", "*.evil.com", "evil.com", "*.ovwild.net", "*.user-blocked.org", "api.github.com",
		"*.github.com", "github.com", "*.discord.com", "claude.ai", "*.claude.ai", "registry.npmjs.org", ""}
	r := rand.New(rand.NewSource(7))
	for i := 0; i < *n; i++ {
		var ex []string
		for j := r.Intn(6); j > 0; j-- {
			ex = append(ex, pool[r.Intn(len(pool))])
		}
		cases = append(cases, cs{agents[r.Intn(5)], fmt.Sprint(1 + r.Intn(3)), layouts[r.Intn(len(layouts))], ex})
	}
	var rows []string
	for i, c := range cases {
		rows = append(rows, fmt.Sprintf("a%04d\t%s\t%s\t%s\t%s", i, c.agent, c.tier, c.layout, enc(c.extras)))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
