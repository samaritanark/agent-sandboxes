package vetting

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"git.theark.cloud/acs/agent-sandboxes/go/internal/bashcompat"
)

// GateConfig is what the gate reads from the vetting configuration (ported in config.go); it is a
// value here so the gate can be exercised with scripted settings.
type GateConfig struct {
	ForbidOverride string // vetting_forbid_unvetted_override: "true" or "false"
	TrustRoots     []string
	TrustRoot      string
	Cap, AgeCap    string // vetting_max_commits_behind, vetting_max_age_days ("" = unset)
	AgeDays        func(epoch string) string
}

// GateDeps are the gate's collaborators: git classification, audit, attestation, and the terminal.
type GateDeps struct {
	Out, Err io.Writer
	Stdin    *bufio.Reader // answers the y/N prompts; nil behaves as end of input
	TTY      bool          // [[ -t 0 && -t 1 ]]

	Status            func(repo string) string // vetting_status_repo
	RecordOverride    func(mechanism, what string, repos []string)
	SigningConfigured func(repo string) bool      // _vetting_signing_configured
	InlineAttest      func(repo, sha string) bool // _vetting_inline_attest
	Cfg               GateConfig
}

// substr12 is ${s:0:12}, counting characters.
func substr12(s string) string {
	r := []rune(s)
	if len(r) > 12 {
		r = r[:12]
	}
	return string(r)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func (d GateDeps) errln(lines ...string) {
	for _, l := range lines {
		fmt.Fprintln(d.Err, l)
	}
}

// reply reads one y/N answer the way `read -r reply || true` does, with default IFS trimming.
func (d GateDeps) reply() string {
	if d.Stdin == nil {
		return ""
	}
	line, _ := d.Stdin.ReadString('\n')
	return strings.Trim(strings.TrimSuffix(line, "\n"), " \t")
}

func yes(r string) bool { return len(r) > 0 && (r[0] == 'y' || r[0] == 'Y') }

// DriftDecision is _vetting_drift_decision: under `required`, whether a verified attestation that
// is `behind` commits behind HEAD and/or stale may launch. It prints its reasoning.
func (d GateDeps) DriftDecision(repo, tag, signer, behind, cap, ageDays, ageCap, acceptUnvetted, acceptDrift string) bool {
	overCommit := cap != "" && bashcompat.ArithCmp(behind, cap, "gt")
	overAge := ageCap != "" && ageDays != "" && bashcompat.ArithCmp(ageDays, ageCap, "gt")

	if overCommit {
		if acceptUnvetted == "true" {
			d.errln(fmt.Sprintf("  %s: vetted but %s commit(s) behind HEAD — over cap %s, proceeding via --i-accept-unvetted-repo.", repo, behind, cap))
			d.RecordOverride("flag:--i-accept-unvetted-repo",
				fmt.Sprintf("vetted but %s commit(s) behind HEAD, over the %s-commit cap", behind, cap), []string{repo})
			return true
		}
		d.errln(fmt.Sprintf("  %s: vetted at %s but %s commit(s) behind HEAD, exceeding the cap of %s.", repo, tag, behind, cap))
		return false
	}

	if cap != "" && !overAge {
		fmt.Fprintf(d.Out, "  ✓ %s: vetted %s commit(s) behind HEAD, within cap %s (tag %s, signer %s)\n", repo, behind, cap, tag, orUnknown(signer))
		return true
	}

	if overAge {
		if acceptUnvetted == "true" || acceptDrift == "true" {
			d.errln(fmt.Sprintf("  %s: attestation is %s day(s) old, over vetting_max_age_days %s — accepted non-interactively (tag %s, signer %s).", repo, ageDays, ageCap, tag, orUnknown(signer)))
			m := "flag:--i-accept-vetting-drift"
			if acceptDrift != "true" {
				m = "flag:--i-accept-unvetted-repo"
			}
			d.RecordOverride(m, fmt.Sprintf("stale attestation %sd old (over the %s-day window), code %s commit(s) behind HEAD", ageDays, ageCap, behind), []string{repo})
			return true
		}
		if d.TTY {
			d.errln("",
				fmt.Sprintf("  %s: the verified attestation (%s, signer %s) is", repo, tag, orUnknown(signer)),
				fmt.Sprintf("  %s day(s) old, past the %s-day re-vetting window. The code is", ageDays, ageCap),
				fmt.Sprintf("  still vetted (%s commit(s) behind HEAD), but the sign-off has gone stale.", behind))
			fmt.Fprint(d.Err, "  Accept the stale attestation and launch? [y/N] ")
			if yes(d.reply()) {
				d.errln("  Accepted.")
				d.RecordOverride("interactive-prompt", fmt.Sprintf("stale attestation %sd old (over the %s-day window) accepted", ageDays, ageCap), []string{repo})
				return true
			}
			d.errln("  Declined.")
			return false
		}
		d.errln(fmt.Sprintf("  %s: attestation is %s day(s) old, past vetting_max_age_days %s and", repo, ageDays, ageCap),
			"  there is no terminal to accept the staleness on. Re-vet (sandbox vet),",
			"  re-run with --i-accept-vetting-drift, or raise vetting_max_age_days.")
		return false
	}

	if acceptUnvetted == "true" || acceptDrift == "true" {
		d.errln(fmt.Sprintf("  %s: vetted %s commit(s) behind HEAD — accepted non-interactively (tag %s, signer %s).", repo, behind, tag, orUnknown(signer)))
		m := "flag:--i-accept-vetting-drift"
		if acceptDrift != "true" {
			m = "flag:--i-accept-unvetted-repo"
		}
		d.RecordOverride(m, fmt.Sprintf("%s commit(s) of unattested drift (no cap set)", behind), []string{repo})
		return true
	}
	if d.TTY {
		d.errln("",
			fmt.Sprintf("  %s: the freshest verified attestation (%s, signer %s)", repo, tag, orUnknown(signer)),
			fmt.Sprintf("  is %s commit(s) behind HEAD. Those commits reached the branch through", behind),
			"  your normal code review, but no reviewer has attested this exact HEAD.")
		fmt.Fprintf(d.Err, "  Accept %s commit(s) of unattested drift and launch? [y/N] ", behind)
		if yes(d.reply()) {
			d.errln("  Accepted.")
			d.RecordOverride("interactive-prompt", fmt.Sprintf("%s commit(s) of unattested drift accepted", behind), []string{repo})
			return true
		}
		d.errln("  Declined.")
		return false
	}
	d.errln(fmt.Sprintf("  %s: vetted %s commit(s) behind HEAD; no cap is set and there is", repo, behind),
		"  no terminal to accept the drift on. Re-run with --i-accept-vetting-drift,",
		"  or set vetting_max_commits_behind: to bound it.")
	return false
}

func (d GateDeps) printFindings(entries []string) {
	for _, e := range entries {
		f := bashcompat.ReadTab(e, 4)
		repo, status, f2, f3 := f[0], f[1], f[2], f[3]
		switch status {
		case "unvetted":
			d.errln(fmt.Sprintf("    %s: no verified attestation (HEAD %s; %s)", repo, substr12(f2), f3))
		case "drift":
			d.errln(fmt.Sprintf("    %s: %s (HEAD %s)", repo, f3, substr12(f2)))
		case "dirty":
			d.errln(fmt.Sprintf("    %s: working tree is not clean (vetting_require_clean_worktree is set) — commit, stash (git stash -u), or remove the changes, then attest (HEAD %s)", repo, substr12(f2)))
		case "not-git":
			d.errln(fmt.Sprintf("    %s: not a git repository — run 'git init' and make a commit, then attest with 'sandbox vet --repo %s'", repo, repo))
		case "error":
			d.errln(fmt.Sprintf("    %s: %s", repo, f2))
		default:
			d.errln(fmt.Sprintf("    %s: %s %s", repo, status, f2))
		}
	}
}

// VettingGateRepos is vetting_gate_repos. rc is 0 for `return 0` and 1 for `exit 1`; summary is
// SESSION_VETTING_SUMMARY.
func (d GateDeps) VettingGateRepos(posture, accept, acceptDrift string, repos []string) (rc int, summary string) {
	if len(repos) == 0 {
		return 0, ""
	}
	summary = "posture=" + posture
	if posture == "off" {
		return 0, summary
	}
	cfg := d.Cfg

	overrideForbidden := false
	if cfg.ForbidOverride == "true" {
		overrideForbidden = true
		if accept == "true" {
			d.errln("  NOTICE: --i-accept-unvetted-repo is disabled by an overlay policy",
				"  (vetting_forbid_unvetted_override); it will not be honored.")
			accept = "false"
		}
	}

	if len(cfg.TrustRoots) == 0 {
		if posture == "required" {
			d.errln("",
				"ERROR: vetting is required but no signer trust root exists. Provide one:",
				"         - link a team overlay that ships its reviewer list",
				"           (config.yaml vetting_trust_root:), or",
				"         - create "+cfg.TrustRoot,
				"           (an SSH allowed_signers file, or a GnuPG home if",
				"           vetting_trust_format: gpg) with the reviewers' public keys.",
				"       See docs/how-to/vetting.md. This is a config error, so the",
				"       --i-accept-unvetted-repo override does not apply.",
				"")
			return 1, summary
		}
		fmt.Fprintf(d.Out, "  Vetting (advisory): no trust root (%s, none from the overlay) — cannot verify, skipping.\n", cfg.TrustRoot)
		return 0, fmt.Sprintf("posture=%s; no trust root — not verified", posture)
	}

	fmt.Fprintf(d.Out, "  Checking workspace vetting attestation(s) [posture: %s]...\n", posture)
	cap, ageCap := cfg.Cap, cfg.AgeCap
	if cap != "" {
		fmt.Fprintf(d.Out, "  Drift cap: attestations may be at most %s commit(s) behind HEAD.\n", cap)
	}
	if ageCap != "" {
		fmt.Fprintf(d.Out, "  Recency: attestations must be at most %s day(s) old (else re-vet).\n", ageCap)
	}

	var unvetted []string
	driftAccepted := 0
	driftDetail := ""
	for _, repo := range repos {
		f := bashcompat.ReadTab(d.Status(repo), 6)
		status, f2, f3, f4, f5, f6 := f[0], f[1], f[2], f[3], f[4], f[5]

		if status == "vetted" {
			ageDays := cfg.AgeDays(f6)
			overAge := ageCap != "" && ageDays != "" && bashcompat.ArithCmp(ageDays, ageCap, "gt")
			if bashcompat.ArithCmp(f5, "0", "eq") && !overAge {
				fmt.Fprintf(d.Out, "  ✓ %s: vetted at %s (tag %s, signer %s)\n", repo, substr12(f2), f3, orUnknown(f4))
				continue
			}
			driftNote := f5 + " behind"
			if overAge {
				driftNote += ", " + ageDays + "d old"
			}
			if driftDetail != "" {
				driftDetail += ", "
			}
			driftDetail += repo + "(" + driftNote + ")"
			if posture == "advisory" {
				switch {
				case cap != "" && bashcompat.ArithCmp(f5, cap, "gt"):
					d.errln(fmt.Sprintf("  %s: vetted at %s, %s commit(s) behind HEAD — over cap %s (advisory, proceeding).", repo, substr12(f2), f5, cap))
				case overAge:
					d.errln(fmt.Sprintf("  %s: vetted at %s, attestation %s day(s) old — over the %s-day window (advisory, proceeding).", repo, substr12(f2), ageDays, ageCap))
				default:
					fmt.Fprintf(d.Out, "  %s: vetted at %s, %s commit(s) behind HEAD (tag %s, signer %s).\n", repo, substr12(f2), f5, f3, orUnknown(f4))
				}
				continue
			}
			if d.DriftDecision(repo, f3, f4, f5, cap, ageDays, ageCap, accept, acceptDrift) {
				driftAccepted++
				continue
			}
			blk := fmt.Sprintf("vetted but %s commit(s) behind HEAD (over the cap, or drift not accepted)", f5)
			if overAge {
				blk = fmt.Sprintf("vetted but the attestation is %s day(s) old, past the %s-day window (not accepted)", ageDays, ageCap)
			}
			unvetted = append(unvetted, strings.Join([]string{repo, "drift", f2, blk}, "\t"))
			continue
		}
		unvetted = append(unvetted, strings.Join([]string{repo, status, f2, f3}, "\t"))
	}

	if len(unvetted) == 0 {
		sum := fmt.Sprintf("posture=%s; all %d workspace(s) vetted", posture, len(repos))
		if driftAccepted > 0 {
			sum += fmt.Sprintf("; %d accepted with drift", driftAccepted)
		}
		if driftDetail != "" {
			sum += " [" + driftDetail + "]"
		}
		fmt.Fprintln(d.Out, "  All workspace(s) carry a verified attestation reachable from HEAD.")
		return 0, sum
	}

	detailOf := func(es []string) string {
		det := ""
		for _, e := range es {
			f := bashcompat.ReadTab(e, 4)
			if det != "" {
				det += ", "
			}
			det += f[0] + "(" + f[1] + ")"
		}
		return det
	}
	detail := detailOf(unvetted)

	if posture == "advisory" {
		d.errln("", fmt.Sprintf("  NOTICE: %d workspace(s) are not vetted for agent use.", len(unvetted)),
			"  Proceeding because posture is advisory (set 'vetting: required' to enforce):")
		d.printFindings(unvetted)
		d.errln("")
		asum := fmt.Sprintf("posture=advisory; %d unvetted, proceeded: %s", len(unvetted), detail)
		if driftDetail != "" {
			asum += "; drift: " + driftDetail
		}
		return 0, asum
	}

	if accept != "true" && d.TTY {
		var remaining []string
		attested := 0
		for _, e := range unvetted {
			f := bashcompat.ReadTab(e, 4)
			ir, is, if2, if3 := f[0], f[1], f[2], f[3]
			if ((is == "unvetted" && strings.HasPrefix(if3, "no ")) || is == "drift") &&
				d.SigningConfigured(ir) && d.InlineAttest(ir, if2) {
				attested++
			} else {
				remaining = append(remaining, e)
			}
		}
		if len(remaining) == 0 {
			fmt.Fprintln(d.Out, "  All workspace(s) now carry a current, verified attestation.")
			return 0, fmt.Sprintf("posture=required; %d workspace(s) attested at launch; all vetted", attested)
		}
		unvetted = remaining
		detail = detailOf(unvetted)
		if attested > 0 {
			detail += fmt.Sprintf(" (%d other(s) attested at launch)", attested)
		}
	}

	if accept == "true" {
		d.errln("", fmt.Sprintf("  NOTICE: proceeding despite %d unvetted workspace(s) because", len(unvetted)),
			"  --i-accept-unvetted-repo was given:")
		d.printFindings(unvetted)
		d.errln("")
		var rs []string
		for _, e := range unvetted {
			rs = append(rs, bashcompat.ReadTab(e, 4)[0])
		}
		d.RecordOverride("flag:--i-accept-unvetted-repo",
			fmt.Sprintf("%d unvetted workspace(s) launched without a verified attestation", len(unvetted)), rs)
		return 0, fmt.Sprintf("posture=required; OVERRIDE accepted %d unvetted: %s", len(unvetted), detail)
	}

	anyDrift := false
	for _, e := range unvetted {
		if bashcompat.ReadTab(e, 4)[1] == "drift" {
			anyDrift = true
			break
		}
	}
	d.errln("",
		"ERROR: vetting is required, but the following workspace(s) have no accepted,",
		"       verified agent-vetting attestation at HEAD, so the launch is refused:",
		"")
	d.printFindings(unvetted)
	d.errln("", "  A trusted reviewer must attest the current HEAD:", "        sandbox vet --repo <PATH>")
	if anyDrift {
		d.errln("  Or, for a repo that is vetted but behind HEAD or past its recency",
			"  window, re-vet, accept it (--i-accept-vetting-drift), or raise",
			"        vetting_max_commits_behind: / vetting_max_age_days: in your config/overlay.")
	}
	if overrideForbidden {
		d.errln("  The --i-accept-unvetted-repo override is disabled by an overlay policy",
			"  (vetting_forbid_unvetted_override), so it cannot be forced through — a",
			"  trusted reviewer must attest HEAD.")
	} else {
		d.errln("  Override (audited), accepting the risk for this launch:",
			"        re-run with --i-accept-unvetted-repo")
	}
	d.errln("")
	return 1, summary
}
