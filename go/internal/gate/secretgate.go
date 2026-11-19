package gate

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"git.theark.cloud/acs/agent-sandboxes/go/internal/bashcompat"
)

// GateDeps are the things secret_gate_repos gets from the rest of the bash (vetting, audit,
// config, the terminal). They are injected so the gate can be ported and tested before those
// modules are.
type GateDeps struct {
	Out, Err io.Writer
	Stdin    *bufio.Reader // read for the interactive prompt; nil behaves as end of input
	IsTTY    bool          // [[ -t 0 ]]

	VettedAcceptedFingerprints func(repo, acceptUnvetted string) string // vetted_accepted_fingerprints
	ExceptionsFromCommit       func() bool                              // vetting_exceptions_from_commit
	RecordOverride             func(mechanism, what string, repos []string)
	LoadRepoAcceptedSecrets    func(repo string) string // retired accepted_secrets: list
	Warn                       func(msg string)
	Scan                       func(repo, acceptFile string) []string // scan_repo_secrets
}

func printUnmaskedFindings(w io.Writer, entries []string) {
	for _, e := range entries {
		f := bashcompat.ReadTab(e, 5)
		fmt.Fprintf(w, "    %s:%s:%s\n", f[1], f[2], f[3])
		switch match := f[4]; {
		case match == "":
		case strings.Contains(match, "REDACTED"):
			fmt.Fprintln(w, "        match: REDACTED")
		default:
			fmt.Fprintf(w, "        match: %s\n", match)
		}
	}
}

func printMaskAddCommands(w io.Writer, entries []string) {
	var seenRepos []string
	for _, e := range entries {
		repo := bashcompat.ReadTab(e, 5)[0]
		if contains(seenRepos, repo) {
			continue
		}
		seenRepos = append(seenRepos, repo)
		cmd := "        sandbox mask add --repo " + repo
		var seenPaths []string
		for _, e2 := range entries {
			f := bashcompat.ReadTab(e2, 5)
			if f[0] != repo || contains(seenPaths, f[1]) {
				continue
			}
			seenPaths = append(seenPaths, f[1])
			cmd += " " + bashcompat.QuoteQ(f[1])
		}
		fmt.Fprintln(w, cmd)
	}
}

func printExceptionsAddCommands(w io.Writer, entries []string) {
	var seenRepos []string
	for _, e := range entries {
		repo := bashcompat.ReadTab(e, 5)[0]
		if contains(seenRepos, repo) {
			continue
		}
		seenRepos = append(seenRepos, repo)
		cmd := "        sandbox exceptions add --repo " + repo
		for _, e2 := range entries {
			f := bashcompat.ReadTab(e2, 5)
			if f[0] == repo {
				cmd += " " + bashcompat.QuoteQ(f[1]+":"+f[2]+":"+f[3])
			}
		}
		fmt.Fprintln(w, cmd)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// SecretGateRepos is secret_gate_repos in lib/filesystem.sh. rc is 0 for the bash's `return 0`
// and 1 for its `exit 1`; summary is SESSION_SECRET_SUMMARY.
func SecretGateRepos(d GateDeps, accept, endpointTrusted, acceptUnvetted string, repos []string) (rc int, summary string) {
	if len(repos) == 0 {
		return 0, ""
	}
	out, errw := d.Out, d.Err
	e := func(lines ...string) {
		for _, l := range lines {
			fmt.Fprintln(errw, l)
		}
	}
	if _, err := exec.LookPath("betterleaks"); err != nil {
		e("",
			"ERROR: betterleaks is required to scan workspaces for secrets, but it",
			"       was not found on PATH. Tier 2/3 launches are gated on it so a",
			"       workspace secret the mask would not hide cannot silently reach",
			"       the agent. Install betterleaks and re-run.",
			"")
		return 1, ""
	}
	fmt.Fprintln(out, "  Scanning workspace(s) for secrets with betterleaks...")

	var unmasked, gitconfig []string
	totalMasked, totalEncrypted, totalAccepted := 0, 0, 0
	for _, repo := range repos {
		if strings.TrimRight(d.LoadRepoAcceptedSecrets(repo), "\n") != "" {
			d.Warn(fmt.Sprintf("%s: accepted_secrets: in %s is no longer honored — run 'sandbox exceptions migrate --repo %s' to move it to %s.",
				bashcompat.Basename(repo), repoConfigName, repo, repoIgnoreName))
		}
		af, _ := os.CreateTemp(os.TempDir(), "sandbox-accept-")
		af.WriteString(d.VettedAcceptedFingerprints(repo, acceptUnvetted))
		af.Close()
		lines := d.Scan(repo, af.Name())
		for _, line := range lines {
			f := bashcompat.ReadTab(line, 5)
			m, relpath, ruleid, ln, match := f[0], f[1], f[2], f[3], f[4]
			if relpath == "" {
				continue
			}
			if m == "error" {
				os.Remove(af.Name())
				e("",
					fmt.Sprintf("ERROR: betterleaks failed to scan %s (%s).", repo, relpath),
					"       The workspace could not be verified free of unmasked",
					"       secrets, so the launch is refused. Re-run, or check the",
					"       betterleaks installation and any repo-local config.",
					"")
				return 1, ""
			}
			entry := strings.Join([]string{repo, relpath, ruleid, ln, match}, "\t")
			switch m {
			case "yes":
				totalMasked++
			case "sealed":
				totalEncrypted++
			case "accepted":
				totalAccepted++
			case "gitconfig":
				gitconfig = append(gitconfig, entry)
			default:
				unmasked = append(unmasked, entry)
			}
		}
		os.Remove(af.Name())
	}

	if totalMasked > 0 {
		fmt.Fprintf(out, "  %d secret finding(s) reside in masked paths (hidden from the agent).\n", totalMasked)
	}
	if totalEncrypted > 0 {
		fmt.Fprintf(out, "  %d secret finding(s) are encrypted at rest (SealedSecret/SOPS); the agent reads only ciphertext.\n", totalEncrypted)
	}
	if totalAccepted > 0 {
		fmt.Fprintf(out, "  %d secret finding(s) accepted via the repo's exceptions list (reviewed false positives; the agent WILL read these).\n", totalAccepted)
	}

	src := "working-copy"
	if d.ExceptionsFromCommit() {
		src = "commit"
	}
	counts := fmt.Sprintf("masked=%d, encrypted=%d, accepted=%d, source=%s", totalMasked, totalEncrypted, totalAccepted, src)
	summary = fmt.Sprintf("no unmasked secrets (%s)", counts)

	if len(unmasked) == 0 && len(gitconfig) == 0 {
		fmt.Fprintln(out, "  betterleaks: no unmasked secrets.")
		return 0, summary
	}

	n := len(unmasked) + len(gitconfig)
	var affected []string
	seen := map[string]bool{}
	for _, ent := range append(append([]string{}, unmasked...), gitconfig...) {
		r := ent
		if i := strings.IndexByte(ent, '\t'); i >= 0 {
			r = ent[:i]
		}
		if strings.TrimSpace(r) == "" || seen[r] { // awk 'NF && !seen[$0]++'
			continue
		}
		seen[r] = true
		affected = append(affected, r)
	}

	if accept == "true" {
		e("", fmt.Sprintf("  NOTICE: %d unmasked secret(s) found. Proceeding anyway", n),
			"  because --i-accept-unmasked-secrets was given — the agent WILL read these:")
		printUnmaskedFindings(errw, unmasked)
		printUnmaskedFindings(errw, gitconfig)
		e("")
		summary = fmt.Sprintf("OVERRIDE accepted %d unmasked secret(s) via --i-accept-unmasked-secrets (%s)", n, counts)
		d.RecordOverride("flag:--i-accept-unmasked-secrets", fmt.Sprintf("%d unmasked secret(s) the agent will read", n), affected)
		return 0, summary
	}

	if endpointTrusted == "true" && d.IsTTY {
		e("", fmt.Sprintf("  NOTICE: %d unmasked secret(s) found in the workspace(s):", n))
		printUnmaskedFindings(errw, unmasked)
		printUnmaskedFindings(errw, gitconfig)
		e("",
			"  Your inference endpoint is a trusted internal model, so this launch may",
			"  proceed with your confirmation. The agent WILL read the secret(s) above",
			"  and could still act on them or exfiltrate them via shell egress — a",
			"  trusted endpoint only closes the model channel; it does not make the",
			"  secret safe.")
		fmt.Fprint(errw, "  Start the sandbox anyway? [y/N] ")
		reply := ""
		if d.Stdin != nil {
			line, _ := d.Stdin.ReadString('\n')
			reply = strings.Trim(strings.TrimSuffix(line, "\n"), " \t")
		}
		if len(reply) > 0 && (reply[0] == 'y' || reply[0] == 'Y') {
			e("  Proceeding — the agent will read the secret(s) above.", "")
			summary = fmt.Sprintf("accepted %d unmasked secret(s) via interactive prompt (trusted endpoint) (%s)", n, counts)
			d.RecordOverride("interactive-prompt", fmt.Sprintf("%d unmasked secret(s) the agent will read (trusted inference endpoint)", n), affected)
			return 0, summary
		}
		e("  Aborted; the sandbox was not started.", "")
		return 1, summary
	}

	e("", "ERROR: betterleaks found secret(s) the sandbox mask will NOT hide. The",
		"       agent would be able to read them, so the launch is refused:")
	if len(unmasked) > 0 {
		e("")
		printUnmaskedFindings(errw, unmasked)
		e("",
			"  Resolve this in one of these ways:",
			"    - Remove or relocate the secret(s) above, or",
			"    - Mask the file(s) so the agent sees an empty overlay (adds them to",
			"      <repo>/.sandbox/config.yaml masked_paths:):",
			"")
		printMaskAddCommands(errw, unmasked)
		e("",
			"    - Or, if a finding is a reviewed false positive, record it as an",
			"      exception (honored once a reviewer vets the repo — 'sandbox vet'):",
			"")
		printExceptionsAddCommands(errw, unmasked)
	}
	if len(gitconfig) > 0 {
		e("", "  Secret(s) in .git/config (the agent can read .git in the workspace):")
		printUnmaskedFindings(errw, gitconfig)
		e("",
			"  .git/config cannot be masked (an empty overlay would break git). Scrub",
			"  the credential instead — e.g. set a credential-less remote URL and let",
			"  a credential helper supply the secret:",
			"        git -C <repo> remote set-url origin <https-url-without-credentials>")
	}
	e("", "    - Or launch anyway, accepting that the agent will see these secrets:",
		"        re-run 'sandbox run' with --i-accept-unmasked-secrets", "")
	return 1, summary
}
