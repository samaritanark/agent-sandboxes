// genmasked writes the corpus for the is_path_masked / extract_yaml_list_from_file differential:
// config files (testdata/masked/cfgs/*.yaml) and cases-masked.tsv (cfg, relpath).
// Usage: go run ./internal/genmasked -base internal/gate/testdata/masked -seed 1 -n 300
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var hand = map[string]string{
	"empty":    "",
	"nokey":    "other:\n  - a\n",
	"basic":    "masked_paths:\n  - secrets.txt\n  - private/\n",
	"quoted":   "masked_paths:\n  - \"a b.txt\"\n  - 'dir with space/'\n  - \"it's\"\n",
	"comments": "masked_paths:\n  # a comment\n  - a.txt   # trailing\n  - b.txt #nospace\n  - c.txt#glued\n  -   d.txt\t# tab\n  - # only comment\n  -\n",
	"stops":    "masked_paths:\n  - a.txt\nnext_key:\n  - b.txt\n  - c/\n",
	"twice":    "masked_paths:\n  - a.txt\nother:\n  - x\nmasked_paths:\n  - b.txt\n",
	"crlf":     "masked_paths:\r\n  - a.txt\r\n  - dir/\r\n",
	"nonl":     "masked_paths:\n  - a.txt\n  - last",
	"echoopt":  "masked_paths:\n  -n\n  -e\n  -E\n  -neE\n  -nx\n  - n\n  -ne \n  -  -n\n",
	"slashes":  "masked_paths:\n  - /\n  - //\n  - ./x\n  - a//b/\n  - ../up\n",
	"globs":    "masked_paths:\n  - '*.pem'\n  - secrets/*\n  - '[ab].txt'\n  - ?.key\n",
	"indent0":  "masked_paths:\n- a.txt\n- dir/\n",
	"inline":   "masked_paths: [a.txt, b/]\n",
	"keysub":   "masked_paths_extra:\n  - nope\nmasked_paths:\n  - yes\n",
	"underscr": "masked_paths:\n  - a\n_private: 1\n  - hidden\n",
	"builtin":  "masked_paths:\n  - .env\n  - .kube/\n  - x-openrc.sh\n",
	"unicode":  "masked_paths:\n  - café.txt\n  - 日本/\n",
	"dashes":   "masked_paths:\n  - -rf\n  - --flag\n  - - nested\n",
	"upper":    "Masked_paths:\n  - nope\nmasked_paths:\n  - Yes.TXT\n",
	"blankmid": "masked_paths:\n\n  - a\n\n  - b/\n",
	"echocol0": "masked_paths:\n-n\n-e\n-nE\n- ok\n-ne x\n-n\n",
	"tabs":     "masked_paths:\n\t- tabbed.txt\n  -\ttab2.txt\n",
}

func main() {
	base := flag.String("base", "", "testdata/masked directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 300, "mutant configs")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	cfgDir := filepath.Join(*base, "cfgs")
	os.RemoveAll(cfgDir)
	os.MkdirAll(cfgDir, 0o755)

	cfgs := map[string]string{}
	for k, v := range hand {
		cfgs["h-"+k] = v
	}
	names := make([]string, 0, len(hand))
	for k := range hand {
		names = append(names, k)
	}
	sort.Strings(names)
	frag := []string{"  - a.txt\n", "  - dir/\n", "masked_paths:\n", "other:\n", "# c\n", "\n", "  - \"q.txt\" # n\n",
		"  -n\n", "-n\n", "-e\n", "  - x-openrc.sh\n", "  - .kube/sub\n", "- top\n", "  -\tt\n", "  - 'z z/'\n", "key: v\n", "  - a#b\n", "  - a #b\n", "  - é/\n", "  - /\n"}
	for i := 0; i < *n; i++ {
		var sb strings.Builder
		parts := 2 + rng.Intn(8)
		if rng.Intn(4) != 0 {
			sb.WriteString("masked_paths:\n")
		}
		for j := 0; j < parts; j++ {
			if rng.Intn(5) == 0 {
				sb.WriteString(hand[names[rng.Intn(len(names))]])
			} else {
				sb.WriteString(frag[rng.Intn(len(frag))])
			}
		}
		s := sb.String()
		switch rng.Intn(6) {
		case 0:
			s = strings.ReplaceAll(s, "\n", "\r\n")
		case 1:
			s = strings.TrimSuffix(s, "\n")
		}
		cfgs[fmt.Sprintf("m-%04d", i)] = s
	}

	base0 := []string{".env", ".env.local", ".npmrc", "clouds.yaml", "kubeconfig", ".kube", ".kube/", ".kube/config", ".kube/a/b",
		".kubex", ".kube2/x", "a/.env", "./.env", ".env/", ".envx", ".ENV", "x-openrc.sh", "-openrc.sh", "a-openrc.sh", "a/x-openrc.sh",
		"x-openrc.sh/", "x-openrc.shx", "openrc.sh", "x_openrc.sh", "xopenrc.sh", "-openrc.shx", "x-openrc.SH", "x-openrc", "kubeconfig/x", "dir/kubeconfig", "", "/", ".", "a", "secrets.txt", "private", "private/",
		"private/x", "privatex", "a.txt", "dir", "dir/", "dir/x", "dir/x/y", "tab bed", "café.txt", "日本", "日本/x", "n", "e", "E", "ne", "nx",
		"yes", "Yes.TXT", "tabbed.txt", "tab2.txt", "-rf", "--flag", "- nested", "nested", "x", "b/", "b", "b/c", "c/d", "top", "t", "q.txt", "z z", "z z/y", "é", "é/x"}
	var rows []string
	keys := make([]string, 0, len(cfgs))
	for k := range cfgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := os.WriteFile(filepath.Join(cfgDir, k+".yaml"), []byte(cfgs[k]), 0o644); err != nil {
			panic(err)
		}
		set := map[string]bool{}
		for _, b := range base0 {
			set[b] = true
		}
		// derive candidates from the config's own entries
		for _, l := range strings.Split(cfgs[k], "\n") {
			l = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(l), "-"))
			l = strings.Trim(l, "\"'")
			if i := strings.Index(l, " #"); i >= 0 {
				l = l[:i]
			}
			l = strings.TrimSpace(l)
			if l == "" || strings.ContainsAny(l, "\t\x1f\r") {
				continue
			}
			d := strings.TrimSuffix(l, "/")
			for _, c := range []string{l, d, d + "/", d + "/x", d + "x", "a/" + d, "./" + d, strings.ToUpper(d), d + "/y/z"} {
				set[c] = true
			}
		}
		cand := make([]string, 0, len(set))
		for c := range set {
			if strings.ContainsAny(c, "\t\n\x1f\r") {
				continue
			}
			cand = append(cand, c)
		}
		sort.Strings(cand)
		for _, c := range cand {
			rows = append(rows, k+"\t"+c)
		}
	}
	if err := os.WriteFile(filepath.Join(*base, "cases-masked.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%d configs, %d cases\n", len(cfgs), len(rows))
}
