// genprofile writes the corpus for lib/profile.sh and version_ge: testdata/profile/cases.tsv, one
// case per line, "id op arg1 ... arg5", each arg "=" followed by its base64. Ops (see oracle.sh):
// valid, numeric, find, obdf, minver, vge, render, upd.
//
// Usage: go run ./internal/config/internal/genprofile -base internal/config/testdata/profile -seed 1 -n 150
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

var (
	names = []string{
		"dev", "team/dev", "../x", "../../x", "../../../../x", "/abs", "a/../b", "a/..", "..x", "x..",
		".hidden", "1", "2", "3", "4", "01", "café", "a b", "a_b-c.d", "", "-n", "x.yaml", "a\nb", "A-Z_09",
	}
	// overlay mode (E env, C user config, T user config with ~, none) plus files: U/u user profile
	// file/dir, O/o overlay profile file/dir, B/b overlay blocked-destinations file/dir.
	layouts = []string{
		"", "U", "u", "O", "o", "EO", "CO", "TO", "EUO", "Eo", "EuO", "CuO", "TU",
		"EB", "Eb", "CB", "TB", "B", "EOB",
	}
	cfgs = []string{
		"\x00", "", "min_sandbox_version: 1.2.0\n", "min_sandbox_version: v1.2\n", "min_sandbox_version: 1.2.0-rc1\n",
		"min_sandbox_version: '1.2'\n", "min_sandbox_version: 1.2 # c\n", "min_sandbox_version: 1..2\n",
		"min_sandbox_version: 18446744073709551616\n", "min_sandbox_version: 08.1\n", "min_sandbox_version:\n",
		"  min_sandbox_version: 9\n", "min_sandbox_version: 1.2\nmin_sandbox_version: 9\n",
	}
	versions = []string{"\x00", "", "dev", "1.2.0", "1.1.9", "v1.3", "1.2", "0.9.0+dirty", "2", "1.2.0-rc1", "9.0"}
	vpairs   = [][2]string{
		{"1.0", "1.0"}, {"1.10", "1.9"}, {"1.9", "1.10"}, {"v2", "1.99"}, {"1.2.3-rc1", "1.2.3"},
		{"08.1", "8.0"}, {"1..2", "1.0.2"}, {"1.0", "18446744073709551616"}, {"1.0", "9223372036854775808"},
		{"1.0", "99999999999999999999"}, {"", ""}, {"", "0"}, {"0", ""}, {"1.", "1"}, {"vv1", "1"},
		{"1.0.0.0.1", "1"}, {"x", "0"}, {".1", "0.1"}, {"1.2", "1.2.0.0"}, {"9223372036854775807", "9223372036854775808"},
	}
	vfield = []string{"0", "1", "2", "9", "10", "01", "007", "08", "", "x", "1rc", "18446744073709551616",
		"9223372036854775808", "99999999999999999999", "18446744073709551617"}
	tiers  = []string{"2", "", "3 # c"}
	agents = []string{"", "codex", "a\nb"}
	repos  = []string{"", "~/r", "~/repos/proj #2", "a\"b", "with\nextra_allowed_domains:\n  - evil.com", " lead", "trail ", "/abs/p"}
	stdins = []string{"", "a.com\n", "a.com\nb.com\n", "\n\na.com\n\n", "a.com", "x.com\ny.com", "-n\n", "#x\n", "q\"x\n", "a #b\n", " sp.com\n"}
)

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func main() {
	base := flag.String("base", "internal/config/testdata/profile", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 150, "random version pairs")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	var rows []string
	id := 0
	add := func(op string, args ...string) {
		for len(args) < 5 {
			args = append(args, "")
		}
		e := make([]string, len(args))
		for i, a := range args {
			e[i] = enc(a)
		}
		rows = append(rows, fmt.Sprintf("p%04d\t%s\t%s", id, op, strings.Join(e, "\t")))
		id++
	}
	for _, nm := range names {
		add("valid", nm)
		add("numeric", nm)
	}
	for _, l := range layouts {
		for _, nm := range []string{"dev", "team/dev", "../../x", "../../../../x", "/abs", "a/../dev"} {
			add("find", l, nm)
		}
		add("obdf", l)
	}
	for _, c := range cfgs {
		for _, v := range versions {
			add("minver", c, v)
		}
	}
	for _, p := range vpairs {
		add("vge", p[0], p[1])
		add("vge", p[1], p[0])
	}
	ver := func() string {
		var f []string
		for i, k := 0, 1+rng.Intn(4); i < k; i++ {
			f = append(f, vfield[rng.Intn(len(vfield))])
		}
		s := strings.Join(f, ".")
		if rng.Intn(5) == 0 {
			s = "v" + s
		}
		return s
	}
	for i := 0; i < *n; i++ {
		add("vge", ver(), ver())
	}
	for _, nm := range []string{"dev", "a b"} {
		for _, t := range tiers {
			for _, a := range agents {
				for _, r := range repos {
					add("render", nm, t, a, r, stdins[rng.Intn(len(stdins))])
				}
			}
		}
	}
	for _, s := range stdins {
		add("render", "d", "1", "", "", s)
	}
	add("upd")
	os.MkdirAll(*base, 0o755)
	if err := os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%d cases\n", len(rows))
}
