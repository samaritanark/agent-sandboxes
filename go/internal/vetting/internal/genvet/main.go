// genvet writes the corpus for the vetting config differential: user and overlay configs
// (testdata/config/{user,overlay}/*.yaml, "@T@" is the fixture root), cases.tsv, signer.tsv.
// Usage: go run ./internal/genvet -base internal/vetting/testdata/config -seed 1
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

var vals = map[string][]string{
	"vetting":                          {"off", "advisory", "required", "Required", "requird", "", "'off'", "\"required\"", "off # c", "required#x"},
	"vetting_max_commits_behind":       {"", "0", "1", "5", "05", "010", "08", "007", "100", "abc", "-1", "1.5", "99999999999999999999", "9223372036854775807", "9223372036854775808", "3 # c", "'7'"},
	"vetting_max_age_days":             {"", "0", "1", "30", "010", "09", "x", "-2", "365", "18446744073709551616", "00"},
	"vetting_exceptions_require_head":  {"true", "false", "True", "yes", "", "1", "true # x", "'true'", "\"true\""},
	"vetting_require_clean_worktree":   {"true", "false", "True", "yes", "", "1", "true # x"},
	"vetting_exceptions_from_commit":   {"true", "false", "True", "yes", "", "1"},
	"vetting_forbid_unvetted_override": {"true", "false", "True", "yes", "", "1"},
	"vetting_trust_root":               {"", "~/home_signers", "@T@/abs_signers", "rel_signers", "@T@/missing", "~/missing", "@T@/ov/signers", "~", "./rel_signers", "rel_signers/", "@T@/abs_signers # c"},
	"vetting_trust_format":             {"ssh", "gpg", "GPG", "", "x", "gpg # c", "'gpg'"},
	"vetting_signing_key":              {"", "~/key", "/k", "@T@/k", "~", "rel/k"},
	"overlay":                          {},
}

func main() {
	base := flag.String("base", "", "testdata/config")
	seed := flag.Int64("seed", 1, "seed")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	var keys []string
	for k := range vals {
		if k != "overlay" {
			keys = append(keys, k)
		}
	}
	// stable order
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, d := range []string{"user", "overlay"} {
		os.RemoveAll(filepath.Join(*base, d))
		os.MkdirAll(filepath.Join(*base, d), 0o755)
	}
	gen := func(dir string, n int) []string {
		var names []string
		for i := 0; i < n; i++ {
			var sb strings.Builder
			if rng.Intn(6) == 0 {
				sb.WriteString("# header\n")
			}
			for _, k := range keys {
				if rng.Intn(3) != 0 {
					continue
				}
				v := vals[k][rng.Intn(len(vals[k]))]
				if rng.Intn(12) == 0 {
					sb.WriteString("  ") // indented: not a top-level key
				}
				fmt.Fprintf(&sb, "%s: %s\n", k, v)
				if rng.Intn(15) == 0 { // a duplicate: the first one wins
					fmt.Fprintf(&sb, "%s: %s\n", k, vals[k][rng.Intn(len(vals[k]))])
				}
			}
			name := fmt.Sprintf("%s-%03d", dir[:1], i)
			os.WriteFile(filepath.Join(*base, dir, name+".yaml"), []byte(sb.String()), 0o644)
			names = append(names, name)
		}
		return names
	}
	users := gen("user", 140)
	ovs := gen("overlay", 90)
	var rows []string
	n := 0
	add := func(u, o, home string) {
		rows = append(rows, fmt.Sprintf("v%04d\t%s\t%s\t%s", n, u, o, home))
		n++
	}
	for _, u := range users {
		add(u, "-", "a")
		add(u, "-", "b")
		add(u, ovs[rng.Intn(len(ovs))], []string{"a", "b"}[rng.Intn(2)])
		add(u, "noconfig", "a")
	}
	for _, o := range ovs {
		add("-", o, "a")
		add("-", o, "b")
		for k := 0; k < 4; k++ {
			add(users[rng.Intn(len(users))], o, []string{"a", "b"}[rng.Intn(2)])
		}
	}
	add("-", "-", "a")
	add("-", "-", "b")
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)

	// _vetting_extract_signer inputs
	outs := []string{
		"Good \"git\" signature for alice@example.com with ED25519 key SHA256:abc",
		"Good \"git\" signature for  with key",
		"gpg: Good signature from \"Alice <a@x>\" [ultimate]",
		"gpg: Good signature from \"A\" \ngpg: Good signature from \"B\"",
		"x Good signature from \"A\" y Good signature from \"B\" z",
		"Good \"git\" signature for a Good \"git\" signature for b",
		"BAD signature",
		"",
		"Good \"\" signature for p",
		"Good signature from \"\"",
		"line1\nGood \"git\" signature for first\nGood \"git\" signature for second",
		"Good \"git\" signature for\ttab",
		"Good signature from \"unterminated",
		"Good \"git\" signature for me@x.y\r",
	}
	var sig []string
	for _, o := range outs {
		for _, f := range []string{"ssh", "gpg"} {
			sig = append(sig, f+"\t"+strings.NewReplacer("\n", "\\n", "\r", "\\r", "\t", "\\t").Replace(o))
		}
	}
	os.WriteFile(filepath.Join(*base, "signer.tsv"), []byte(strings.Join(sig, "\n")+"\n"), 0o644)
	fmt.Printf("%d user, %d overlay configs, %d cases, %d signer cases\n", len(users), len(ovs), len(rows), len(sig))
}
