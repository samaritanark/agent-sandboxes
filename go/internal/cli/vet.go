package cli

import (
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/vetting"
)

// cmdVet is cmd_vet: attest a repo (sign agent-vetted/<HEAD>) or print its vetting status.
func cmdVet(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_vet")
	}
	status, repo, msg, yes := false, "", "vetted for agent use", "false"
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--repo"); ok {
			repo = v
			continue
		}
		if v, ok := flagValue(c, args, &i, "--message"); ok {
			msg = v
			continue
		}
		switch {
		case a == "--help" || a == "-h" || a == "help":
			c.usage("usage_vet")
		case a == "--status":
			status = true
		case a == "--yes" || a == "-y":
			yes = "true"
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'vet': %s", a)
		default:
			c.die("Unexpected argument for 'vet': %s", a)
		}
	}
	if repo == "" {
		c.die("Usage: sandbox vet --repo <PATH> [--status] [--message <MSG>]")
	}
	repo = c.expandHome(repo)
	if err := c.workspace().ValidateRepoPath(repo); err != nil {
		c.fail(err)
	}
	v := c.vetting()
	if status {
		vetStatus(c, v, repo)
		return
	}
	a := vetting.Attester{Ctx: v, Out: c.stdout, Err: c.stderr, Stdin: c.stdin,
		Warn: func(m string) { c.warn("%s", m) },
		Scan: func(r, accept string) []string { return gate.ScanRepoSecrets(c.env.Env, r, accept, c.stderr) }}
	if a.SigningSetupAssist(repo) != 0 {
		panic(exit(1))
	}
	if rc := a.AttestRepo(repo, msg, yes); rc != 0 {
		panic(exit(rc))
	}
}

func vetStatus(c *cmdCtx, v vetting.Ctx, repo string) {
	f := bashcompat.SplitTab(v.StatusRepo(repo), 6)
	st, f2, f3, f4, f5, f6 := f[0], f[1], f[2], f[3], f[4], f[5]
	or := func(s, d string) string {
		if s == "" {
			return d
		}
		return s
	}
	switch st {
	case "vetted":
		c.out("vetted:   %s", repo)
		c.out("  HEAD:   %s", f2)
		c.out("  tag:    %s", f3)
		c.out("  signer: %s", or(f4, "unknown"))
		if vetting.NumCmp(or(f5, "0"), "0", "eq") {
			c.out("  behind: 0 (attestation is at HEAD)")
		} else {
			c.out("  behind: %s commit(s) — the attestation is an ancestor of HEAD", f5)
		}
		age, cap := v.AgeDays(f6), v.MaxAgeDays()
		if age != "" {
			switch {
			case cap == "":
				c.out("  age:    %s day(s) (no recency window set)", age)
			case vetting.NumCmp(age, cap, "gt"):
				c.out("  age:    %s day(s) — STALE, past the %s-day recency window (re-vet)", age, cap)
			default:
				c.out("  age:    %s day(s) — within the %s-day recency window", age, cap)
			}
		}
	case "unvetted":
		c.out("UNVETTED: %s", repo)
		c.out("  HEAD:   %s", f2)
		c.out("  reason: %s", f3)
	case "dirty":
		c.out("DIRTY:    %s (HEAD %s)", repo, f2)
		c.out("  Working tree is not clean and vetting_require_clean_worktree is set.")
		c.out("  Commit, stash (git stash -u), or remove the changes, then attest.")
	case "error":
		c.errOut("ERROR:    %s", f2)
		panic(exit(1))
	default:
		c.out("%s: %s", st, f2)
	}
}
