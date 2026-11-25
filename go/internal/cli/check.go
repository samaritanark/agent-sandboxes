package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/vetting"
	"github.com/samaritanark/agent-sandboxes/go/internal/workspace"
)

func (c *cmdCtx) vetting() vetting.Ctx {
	v := vetting.Ctx{Env: c.env.Env, TrustRootDefault: c.env.Home + "/.sandbox/vetting/allowed_signers",
		TagPrefix: "agent-vetted/", Stderr: c.stderr, Now: c.env.Now}
	if c.env.VettingTrustRootDefault != "" {
		v.TrustRootDefault = c.env.VettingTrustRootDefault
	}
	return v
}

func (c *cmdCtx) workspace() workspace.Ctx {
	return workspace.Ctx{Env: c.env.Env, SandboxRoot: c.env.SandboxRoot, IsWSL: c.env.IsWSL}
}

// cmdCheck is cmd_check: the workspace pre-flight and a preview of the secret gate.
func cmdCheck(c *cmdCtx, args []string) {
	const usage = "Usage: sandbox check <WORKSPACE_PATH>"
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") && deviation.Fixed(deviation.CheckHelp) {
		c.out("%s", usage)
		return
	}
	if len(args) == 0 || args[0] == "" {
		c.missingArg("1", usage)
	}
	ws := args[0]
	if strings.HasPrefix(ws, "~") {
		ws = c.env.Home + ws[1:]
	}
	c.out("==> Checking workspace: %s", ws)
	if err := c.workspace().ValidateRepoPath(ws); err != nil {
		c.fail(err)
	}
	for _, l := range workspace.Prescan(ws) {
		c.out("%s", l)
	}
	if _, err := exec.LookPath("betterleaks"); err != nil {
		c.out("  WARN: betterleaks not found; 'sandbox run' would refuse to launch (fail closed).")
		c.out("")
		c.out("Workspace check passed.")
		return
	}
	c.out("  Scanning for unmasked secrets with betterleaks (preview)...")
	if len(config.LoadRepoAcceptedSecrets(ws)) > 0 {
		c.warn("accepted_secrets: in %s is no longer honored — run 'sandbox exceptions migrate --repo %s' to move it to %s.",
			config.RepoConfigName, ws, config.RepoIgnoreName)
	}
	accept, _ := os.CreateTemp(c.env.TmpDir, "sandbox-accept-")
	for _, fp := range c.vetting().VettedAcceptedFingerprints(ws, "") {
		fmt.Fprintln(accept, fp)
	}
	accept.Close()
	defer os.Remove(accept.Name())
	unmasked, encrypted, accepted, gitconfig, failed := 0, 0, 0, 0, false
	var entries []string
	for _, row := range gate.ScanRepoSecrets(c.env.Env, ws, accept.Name(), c.stderr) {
		f := bashcompat.SplitTab(row, 5)
		m, rel, rule, ln, match := f[0], f[1], f[2], f[3], f[4]
		if rel == "" {
			continue
		}
		switch m {
		case "error":
			failed = true
		case "sealed":
			encrypted++
		case "accepted":
			accepted++
		case "no", "gitconfig":
			unmasked++
			c.out("  UNMASKED: %s:%s:%s", rel, rule, ln)
			if m == "no" {
				entries = append(entries, ws+"\t"+rel+"\t"+rule+"\t"+ln+"\t"+match)
			} else {
				gitconfig++
			}
		}
	}
	if encrypted > 0 {
		c.out("  %d encrypted-at-rest finding(s) (SealedSecret/SOPS) — safe, not gated.", encrypted)
	}
	if accepted > 0 {
		c.out("  %d finding(s) accepted via the vetted exceptions list — not gated.", accepted)
	}
	switch {
	case failed:
		c.out("  WARN: betterleaks scan failed; 'sandbox run' would refuse to launch (fail closed).")
	case unmasked > 0:
		c.out("  %d unmasked secret(s) would block 'sandbox run'.", unmasked)
		if len(entries) > 0 {
			c.out("  Mask them:")
			gate.PrintMaskAddCommands(c.stdout, entries)
			c.out("  Or record reviewed false positives as exceptions (honored once the")
			c.out("  repo is vetted — 'sandbox vet'):")
			gate.PrintExceptionsAddCommands(c.stdout, entries)
		}
		if gitconfig > 0 {
			c.out("  .git/config finding(s) cannot be masked; scrub the credential instead:")
			c.out("        git -C %s remote set-url origin <https-url-without-credentials>", ws)
		}
	default:
		c.out("  betterleaks: no unmasked secrets.")
	}
	c.out("")
	c.out("Workspace check passed.")
}
