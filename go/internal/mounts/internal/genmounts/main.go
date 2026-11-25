// genmounts writes testdata/cases.tsv for the mounts corpus: one case per line, "id repos tree"
// (repos: the NUL-joined repo paths relative to the case home; tree: steps as in the workspace
// baseline corpus).
//
// Usage: go run ./internal/mounts/internal/genmounts -base internal/mounts/testdata
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

func e(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

type tree []string

func (t tree) add(op string, f ...string) tree {
	parts := []string{e(op)}
	for _, x := range f {
		parts = append(parts, e(x))
	}
	return append(append(tree(nil), t...), strings.Join(parts, " "))
}
func (t tree) f(p, c string) tree  { return t.add("f", p, c) }
func (t tree) d(p string) tree     { return t.add("d", p) }
func (t tree) l(p, to string) tree { return t.add("l", p, to) }
func (t tree) p(p string) tree     { return t.add("p", p) }

func main() {
	base := flag.String("base", "internal/mounts/testdata", "testdata directory")
	n := flag.Int("n", 60, "random cases")
	flag.Parse()
	type cs struct {
		repos []string
		t     tree
	}
	cfg := func(r, body string) tree { return tree{}.f(r+"/.sandbox/config.yaml", "masked_paths:\n"+body) }
	one := []string{"r"}
	var cases []cs
	for _, c := range []cs{
		{one, tree{}.d("r")},
		{one, tree{}.f("r/.env", "x").f("r/.env.local", "x").f("r/.npmrc", "x").f("r/clouds.yaml", "x").f("r/kubeconfig", "x")},
		{one, tree{}.d("r/.env").f("r/.npmrc", "x").l("r/kubeconfig", ".npmrc").l("r/clouds.yaml", "nowhere")},
		{one, tree{}.f("r/b-openrc.sh", "x").f("r/a-openrc.sh", "x").f("r/sub/c-openrc.sh", "x").d("r/d-openrc.sh").l("r/e-openrc.sh", "a-openrc.sh").f("r/-openrc.sh", "x")},
		{one, tree{}.d("r/.kube").f("r/.kube/config", "x")},
		{one, tree{}.f("r/.kube", "file not dir")},
		{one, tree{}.d("r/real").l("r/.kube", "real")},
		{one, cfg("r", "  - secrets.txt\n  - certs/\n  - missing.txt\n  - gone/\n  -\n  - dirfile/\n  - plain\n").f("r/secrets.txt", "s").d("r/certs").f("r/dirfile", "x").d("r/plain")},
		{one, cfg("r", "  - \"q uoted.txt\"\n  - a/b/c.txt\n  - a/\n  - .env\n").f("r/q uoted.txt", "q").f("r/a/b/c.txt", "c").f("r/.env", "e")},
		{one, cfg("r", "  - -n\n  - ../outside.txt\n").f("r/-n", "x").f("outside.txt", "o")},
		{one, tree{}.f("r/.git/config", "c").d("r/.git/hooks").f("r/.gitmodules", "m").d("r/.vscode").d("r/.idea").d("r/.devcontainer")},
		{one, tree{}.d("r/.git/config").f("r/.git/hooks", "x").d("r/.gitmodules").f("r/.vscode", "x")},
		{one, tree{}.f("r/.git", "gitdir: ../x/.git/worktrees/r\n").f("r/.gitmodules", "m")},
		{one, tree{}.d("r/.git").d("hooksreal").l("r/.git/hooks", "../../hooksreal").l("r/.idea", "nowhere")},
		{[]string{"a/r", "b/s"}, tree{}.f("a/r/.env", "x").d("a/r/.kube").f("b/s/.npmrc", "x").d("b/s/.vscode").f("b/s/x-openrc.sh", "x")},
		{[]string{"a/r", "b/s", "c/t"}, cfg("b/s", "  - k/\n  - f.txt\n").d("b/s/k").f("b/s/f.txt", "f").f("c/t/.git/config", "c").f("a/r/kubeconfig", "k")},
		{[]string{"r/", "s"}, tree{}.f("r/.env", "x").f("s/.env", "y")},
		{[]string{"my repo"}, tree{}.f("my repo/.env", "x")},
		{[]string{"x", "y"}, tree{}.d("x").d("y")},
		{[]string{"z-openrc.sh"}, tree{}.d("z-openrc.sh").f("z-openrc.sh/.env", "x")},
		{one, tree{}.d("r").l("r/q-openrc.sh", "nowhere").l("r/.kube", "nowhere")},
		{one, cfg("r", "  - two//\n  - lnk\n  - lnkd/\n  - \"sp ace/\"\n").f("r/two", "x").d("r/real").l("r/lnk", "real").l("r/lnkd", ".env").f("r/.env", "e").f("r/sp ace", "s")},
		{one, tree{}.d("r").p("r/.env").p("r/.kube").p("r/f-openrc.sh")},
		{one, cfg("r", "  - fifo\n  - fifod/\n").p("r/fifo").p("r/fifod")},
		{[]string{"a/r/", "b/s"}, tree{}.d("a/r/x-openrc.sh").d("b/s/.npmrc").f("b/s/.kube", "k")},
	} {
		cases = append(cases, c)
	}
	rnd := rand.New(rand.NewSource(5))
	files := []string{".env", ".env.local", ".npmrc", "clouds.yaml", "kubeconfig", "a-openrc.sh", ".gitmodules", ".git/config", "m.txt", "n.txt"}
	dirs := []string{".kube", ".git/hooks", ".vscode", ".idea", ".devcontainer", "md"}
	for i := 0; i < *n; i++ {
		t := tree{}.d("r")
		for j := rnd.Intn(6); j > 0; j-- {
			t = t.f("r/"+files[rnd.Intn(len(files))], "x")
		}
		for j := rnd.Intn(4); j > 0; j-- {
			t = t.d("r/" + dirs[rnd.Intn(len(dirs))])
		}
		if rnd.Intn(2) == 0 {
			t = t.f("r/.sandbox/config.yaml", "masked_paths:\n  - m.txt\n  - md/\n  - n.txt/\n")
		}
		cases = append(cases, cs{one, t})
	}
	var rows []string
	for i, c := range cases {
		rows = append(rows, fmt.Sprintf("m%04d\t%s\t%s", i, e(strings.Join(c.repos, "\x00")), e(strings.Join(c.t, "\n"))))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
