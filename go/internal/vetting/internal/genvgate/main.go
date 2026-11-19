// genvgate writes scenarios and cases for the vetting_gate_repos differential:
// testdata/gate/scen/<scenario>/<repo-basename> (the status line a mocked vetting_status_repo
// returns) and testdata/gate/cases.tsv.
// Usage: go run ./internal/genvgate -base internal/vetting/testdata/gate -seed 1 -n 220
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

const now = 1800000000 // FAKE_NOW in the oracle

func main() {
	base := flag.String("base", "", "testdata/gate")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 220, "scenarios")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	sha := func() string { return fmt.Sprintf("%016x%016x%08x", rng.Uint64(), rng.Uint64(), rng.Uint32()) }
	day := func(d int) string { return fmt.Sprint(now - d*86400 - rng.Intn(3600)) }

	vetted := func() string {
		behind := pick([]string{"0", "0", "0", "1", "3", "10", "100", "08", "010"})
		tagdate := pick([]string{"", day(0), day(1), day(5), day(40), fmt.Sprint(now + 99999), "abc", day(400)})
		return strings.Join([]string{"vetted", sha(), "agent-vetted/" + pick([]string{"t1", "rel 2", "é"}), pick([]string{"alice@example.com", "unknown", "bob"}), behind, tagdate}, "\t")
	}
	other := func() string {
		switch rng.Intn(9) {
		case 0:
			return "unvetted\t" + sha() + "\tno agent-vetted/* tag present — if the repo is vetted upstream, 'git fetch --tags' may reveal the attestation"
		case 1:
			return "unvetted\t" + sha() + "\t3 agent-vetted/* tag(s) present but none is an ancestor of HEAD (an older checkout or a divergent branch?) — check out the vetted commit, or attest this HEAD"
		case 2:
			return "unvetted\t" + sha() + "\t2 reachable tag(s) but none verified against the trust root"
		case 3:
			return "dirty\t" + sha()
		case 4:
			return "not-git\t/work/x is not a git repository"
		case 5:
			return "error\tcannot access /work/x"
		case 6:
			return "weird\tfoo\tbar"
		case 7:
			return ""
		}
		return "unvetted\t" + sha() + "\tno tag"
	}
	status := func() string {
		if rng.Intn(10) < 6 {
			return vetted()
		}
		return other()
	}
	repoNames := []string{"r1", "r2", "r3", "my repo", "é"}
	scenRepos := map[string][]string{}
	put := func(scn, repo, line string) {
		d := filepath.Join(*base, "scen", scn)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, repo), []byte(line+"\n"), 0o644)
	}
	os.RemoveAll(filepath.Join(*base, "scen"))
	var scns []string
	for i := 0; i < *n; i++ {
		name := fmt.Sprintf("s%03d", i)
		k := 1 + rng.Intn(3)
		for j := 0; j < k; j++ {
			put(name, repoNames[j], status())
			scenRepos[name] = append(scenRepos[name], repoNames[j])
		}
		scns = append(scns, name)
	}
	// hand-written scenarios for the branches that need exact combinations
	hand := map[string][]string{
		"h-fresh":        {fmt.Sprintf("vetted\t%s\ttag\talice\t0\t%s", sha(), day(1))},
		"h-behind":       {fmt.Sprintf("vetted\t%s\ttag\talice\t4\t%s", sha(), day(1))},
		"h-stale":        {fmt.Sprintf("vetted\t%s\ttag\talice\t0\t%s", sha(), day(40))},
		"h-stale-behind": {fmt.Sprintf("vetted\t%s\ttag\talice\t7\t%s", sha(), day(40))},
		"h-unvetted-no":  {"unvetted\t" + sha() + "\tno agent-vetted/* tag present"},
		"h-two-behind":   {fmt.Sprintf("vetted\t%s\ttag\talice\t4\t%s", sha(), day(1)), fmt.Sprintf("vetted\t%s\ttag\tbob\t9\t%s", sha(), day(1))},
		"h-mixed":        {fmt.Sprintf("vetted\t%s\ttag\talice\t0\t%s", sha(), day(1)), "unvetted\t" + sha() + "\tno agent-vetted/* tag present", "dirty\t" + sha()},
	}
	for name, lines := range hand {
		for j, l := range lines {
			put(name, repoNames[j], l)
			scenRepos[name] = append(scenRepos[name], repoNames[j])
		}
		scns = append(scns, name)
	}
	type c struct{ scn, posture, accept, drift, forbid, cap, agecap, roots, tty, sign, attest string }
	var cases []c
	pb := []string{"false", "true"}
	// every posture/flag combination on the hand scenarios, with and without caps
	for name := range hand {
		for _, post := range []string{"off", "advisory", "required"} {
			for _, acc := range pb {
				for _, dr := range pb {
					for _, cap := range []string{"-", "0", "5"} {
						for _, ac := range []string{"-", "30"} {
							cases = append(cases, c{name, post, acc, dr, "false", cap, ac, "some", "-", "-", "-"})
						}
					}
				}
			}
		}
		// prompts and inline attest
		for _, post := range []string{"required"} {
			for _, replies := range []string{"y", "n", "EOF", "y|y|y", "n|y|n", "Y", " y", "yes|no"} {
				for _, ac := range []string{"-", "30"} {
					for _, attest := range []string{"-", "r1", "r1,r2,r3", "r2"} {
						cases = append(cases, c{name, post, "false", "false", "false", "-", ac, "some", replies, "r1,r2,r3", attest})
					}
				}
			}
		}
		cases = append(cases, c{name, "required", "true", "false", "true", "-", "-", "some", "-", "-", "-"})
		cases = append(cases, c{name, "required", "false", "false", "true", "-", "-", "some", "-", "-", "-"})
		cases = append(cases, c{name, "required", "false", "false", "false", "-", "-", "none", "-", "-", "-"})
		cases = append(cases, c{name, "advisory", "false", "false", "false", "-", "-", "none", "-", "-", "-"})
	}
	posts := []string{"off", "advisory", "required", "required", "required", "EMPTY", "x"}
	caps := []string{"-", "-", "0", "1", "5", "08", "010", "99999999999999999999"}
	agecaps := []string{"-", "-", "0", "1", "30", "09", "010"}
	for _, name := range scns {
		for k := 0; k < 8; k++ {
			tty := "-"
			if rng.Intn(4) == 0 {
				tty = pick([]string{"y", "n", "EOF", "y|y|y", "n|y|n", "y|n|y"})
			}
			cases = append(cases, c{name, pick(posts), pick(append(pb, "", "yes")), pick(pb), pick(append(pb, "True")), pick(caps), pick(agecaps), pick([]string{"some", "some", "some", "none"}), tty,
				pick([]string{"-", "r1,r2,r3", "r1"}), pick([]string{"-", "r1", "r1,r2,r3", "r2,r3"})})
		}
	}
	var rows []string
	for i, x := range cases {
		repos := strings.Join(scenRepos[x.scn], ",")
		rows = append(rows, strings.Join([]string{fmt.Sprintf("g%05d", i), x.scn, repos, x.posture, x.accept, x.drift, x.forbid, x.cap, x.agecap, x.roots, x.tty, x.sign, x.attest}, "\t"))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d scenarios, %d cases\n", len(scns), len(rows))
}
