// genbaseline writes testdata/baseline/cases.tsv for the workspace baseline and diff corpus: one
// case per line, "id prune repos before after". prune is real (the install's
// config/workspace-audit.yaml), none (no file), or a fixture name; repos is the NUL-joined list of
// repo paths relative to the case home; before and after are tree steps (one per line, fields
// base64 and space-separated) applied before the baseline and before the diff.
//
// Usage: go run ./internal/workspace/internal/genbaseline -base internal/workspace/testdata/baseline
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
func (t tree) r(p string) tree     { return t.add("r", p) }
func (t tree) u(p string) tree     { return t.add("u", p) }
func (t tree) p(p string) tree     { return t.add("p", p) }

type cs struct {
	prune         string
	repos         []string
	before, after tree
}

func main() {
	base := flag.String("base", "internal/workspace/testdata/baseline", "testdata directory")
	n := flag.Int("n", 60, "random cases")
	flag.Parse()
	var cases []cs
	r1 := tree{}.f("r/a.txt", "a").f("r/b.txt", "b").f("r/sub/c.txt", "c").d("r/empty")
	one := []string{"r"}
	for _, c := range []cs{
		{"real", one, r1, nil},
		{"real", one, r1, tree{}.f("r/a.txt", "A")},
		{"real", one, r1, tree{}.f("r/new.txt", "n")},
		{"real", one, r1, tree{}.r("r/b.txt")},
		{"real", one, r1, tree{}.f("r/a.txt", "A").f("r/z.txt", "z").r("r/sub")},
		{"real", one, tree{}.d("r"), nil},
		{"real", one, tree{}.d("r"), tree{}.f("r/x", "x").f("r/y", "y")},
		{"real", one, r1, tree{}.r("r/a.txt").r("r/b.txt").r("r/sub")},
		{"real", []string{"nope"}, nil, nil},
		{"real", []string{"r", "s"}, r1.f("s/a.txt", "a").f("s/q.txt", "q"), tree{}.f("s/a.txt", "changed").f("r/b.txt", "B")},
		{"real", []string{"s", "r"}, r1.f("s/a.txt", "a"), tree{}.f("r/n.txt", "n")},
		// pruning
		{"real", one, r1.f("r/node_modules/x/i.js", "i").f("r/.venv/bin/p", "p").f("r/deep/build/o", "o").f("r/build", "file named build"), tree{}.f("r/node_modules/x/j.js", "j")},
		{"real", one, r1.f("r/.git/objects/ab/cdef", "obj").f("r/.git/HEAD", "ref: x\n").f("r/.git/config", "c"), nil},
		{"real", []string{"r/"}, r1.f("r/.git/objects/ab/cdef", "obj").f("r/.git/HEAD", "h"), nil},
		{"real", []string{"r//"}, r1.f("r/.git/objects/ab/cdef", "obj"), nil},
		{"real", []string{"build"}, tree{}.f("build/a", "a").f("build/sub/b", "b"), tree{}.f("build/a", "A")},
		{"real", []string{"x/out"}, tree{}.f("x/out/a", "a"), nil},
		{"real", []string{"x[1]"}, tree{}.f("x[1]/a", "a").f("x[1]/.git/objects/o", "o").f("x1/.git/objects/p", "p"), nil},
		{"real", []string{"a*b"}, tree{}.f("a*b/a", "a").f("a*b/.git/objects/o", "o"), nil},
		{"real", []string{"r"}, tree{}.f("r/.git/objects/x", "o").f("r/sub/.git/objects/y", "o2"), nil},
		{"none", one, r1.f("r/node_modules/x/i.js", "i").f("r/.git/objects/ab/cd", "o"), nil},
		{"custom.yaml", one, r1.f("r/a.tmp", "t").f("r/cache/x", "x").f("r/quoted/q", "q").f("r/nodash/n", "n").f("r/TAB/t", "t").f("r/after/a", "a").f("r/again/a", "a").f("r/other/o", "o"), nil},
		{"empty.yaml", one, r1.f("r/node_modules/m", "m"), nil},
		// what is and is not hashed
		{"real", one, r1.l("r/link", "a.txt").l("r/dangling", "nowhere").l("r/dirlink", "sub").p("r/fifo"), nil},
		{"real", one, r1.u("r/b.txt"), tree{}.f("r/a.txt", "AA")},
		{"real", one, r1.f("r/sp ace.txt", "s").f("r/back\\slash", "b").f("r/new\nline", "n").f("r/car\rret", "c").f("r/üni", "u").f("r/-dash", "d"), nil},
		{"real", one, r1.f("r/sp ace.txt", "s").f("r/back\\slash", "b"), tree{}.f("r/back\\slash", "B").f("r/new\nline", "n")},
		{"real", one, r1.f("r/.hidden", "h").f("r/.config/x", "x"), nil},
		{"real", one, r1, tree{}.r("r/a.txt").f("r/a.txt", "a")},
	} {
		cases = append(cases, c)
	}
	// the diff with no baseline
	cases = append(cases, cs{"real", one, r1, tree{}.r("LOG/baseline.sha256")})
	rnd := rand.New(rand.NewSource(11))
	names := []string{"a", "b", "c", "d/e", "d/f", "g/h/i", "node_modules/k", "x y", "build/z", "out"}
	for i := 0; i < *n; i++ {
		var bt, at tree
		for j := rnd.Intn(8); j > 0; j-- {
			bt = bt.f("r/"+names[rnd.Intn(len(names))], fmt.Sprint(rnd.Intn(4)))
		}
		for j := rnd.Intn(5); j > 0; j-- {
			nm := "r/" + names[rnd.Intn(len(names))]
			if rnd.Intn(3) == 0 {
				at = at.r(nm)
			} else {
				at = at.f(nm, fmt.Sprint(rnd.Intn(4)))
			}
		}
		cases = append(cases, cs{"real", one, tree{}.d("r").add("noop").clean(bt), at})
	}
	var rows []string
	for i, c := range cases {
		rows = append(rows, fmt.Sprintf("w%04d\t%s\t%s\t%s\t%s", i, c.prune, e(strings.Join(c.repos, "\x00")),
			e(strings.Join(c.before, "\n")), e(strings.Join(c.after, "\n"))))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}

// clean drops the placeholder step and appends t.
func (t tree) clean(more tree) tree {
	var out tree
	for _, s := range t {
		if s != e("noop") {
			out = append(out, s)
		}
	}
	return append(out, more...)
}
