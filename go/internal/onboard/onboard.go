// Package onboard is lib/onboard.sh: staging an operator's host-side agent login state (OAuth
// token files and benign settings) into the agent home, hardening the staged Codex and Grok
// configs, refusing API-key agents, and writing the starter user config. In v3 the destination
// becomes the credential broker's store (design 5.9.6); which files are taken, and how the configs
// are hardened, carries over.
package onboard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// ForbiddenEnv is ONBOARD_FORBIDDEN_ENV: host variables onboard never persists and warns about.
var ForbiddenEnv = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
	"COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GROK_DEPLOYMENT_KEY"}

// Ctx is what onboard reads: $HOME and the agent-home base (ONBOARD_AGENT_HOME_BASE, fixed at
// $HOME/.sandbox/agent-home when the bash library is loaded).
type Ctx struct {
	Home, AgentHomeBase string
	DryRun, Force       bool
}

// Out collects what onboard prints.
type Out struct{ Stdout, Stderr []string }

func (o *Out) say(f string, a ...interface{}) { o.Stdout = append(o.Stdout, fmt.Sprintf(f, a...)) }

// WarnForbiddenEnv is warn_forbidden_env: a warning per forbidden variable that is set, and the
// count.
func WarnForbiddenEnv(getenv func(string) string) (stderr []string, count int) {
	for _, v := range ForbiddenEnv {
		if getenv(v) != "" {
			stderr = append(stderr, fmt.Sprintf("  WARN: host env '%s' is set.", v),
				"        onboard will NOT copy it. PRINCIPLES.md rule 1 forbids",
				"        baking long-lived API keys into agent state.")
			count++
		}
	}
	return stderr, count
}

func (c Ctx) disp(p string) string {
	if c.Home != "" && strings.HasPrefix(p, c.Home) {
		return "~" + p[len(c.Home):]
	}
	return p
}

func isRegular(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }

// lnoRegular reports whether p is a regular file itself (not through a symlink).
func lnoRegular(p string) bool { st, err := os.Lstat(p); return err == nil && st.Mode().IsRegular() }

func lexists(p string) bool { _, err := os.Lstat(p); return err == nil }

// noFollow reports whether the AgentHomeNoFollow fix is on.
func noFollow() bool { return deviation.Fixed(deviation.AgentHomeNoFollow) }

// unsafeTarget, with AgentHomeNoFollow, is why onboard must not write path p: it exists and is
// not a regular file (a symlink, a directory, a device), or its directory is a symlink.
func unsafeTarget(p string) bool {
	if !noFollow() {
		return false
	}
	if st, err := os.Lstat(filepath.Dir(p)); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return lexists(p) && !lnoRegular(p)
}

// writeNoFollow writes data to p through a fresh temp file in the same directory, renamed over p:
// the rename replaces whatever is at p (a symlink included) and never writes through it.
func writeNoFollow(p string, data []byte) error {
	b := make([]byte, 8)
	rand.Read(b)
	tmp := filepath.Join(filepath.Dir(p), ".onboard-"+hex.EncodeToString(b))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// StageFile is stage_file: "copied", "skipped-exists", "missing-src", or (with AgentHomeNoFollow)
// "refused-nonregular".
//
// In legacy mode the copy is `cp -f` and `chmod 0600`, which follow a symlink at the destination
// (GNU cp writes through a symlink to an existing file), and a directory there receives the file
// inside it. With AgentHomeNoFollow a destination that is not a regular file is refused, and the
// copy goes through a fresh temp file renamed into place. stderr is what cp and chmod print: GNU
// cp refuses to write through a dangling symlink, and stage_file reports "copied" anyway.
func (c Ctx) StageFile(src, dst string) (result string, stderr []string) {
	if !isRegular(src) {
		return "missing-src", nil
	}
	if unsafeTarget(dst) {
		return "refused-nonregular", nil
	}
	if isRegular(dst) && !c.Force {
		return "skipped-exists", nil
	}
	if c.DryRun {
		return "copied", nil
	}
	os.MkdirAll(filepath.Dir(dst), 0o755)
	data, err := os.ReadFile(src)
	if err != nil {
		return "copied", nil
	}
	if noFollow() {
		writeNoFollow(dst, data)
		return "copied", nil
	}
	if lexists(dst) && !config.Exists(dst) { // a dangling symlink
		return "copied", []string{
			fmt.Sprintf("cp: not writing through dangling symlink '%s'", dst),
			fmt.Sprintf("chmod: cannot operate on dangling symlink '%s'", dst),
		}
	}
	target := dst
	if st, err := os.Stat(dst); err == nil && st.IsDir() {
		target = filepath.Join(dst, filepath.Base(src))
	}
	if st, err := os.Stat(target); err == nil {
		os.WriteFile(target, data, st.Mode().Perm()) // cp keeps an existing file's mode
	} else {
		os.WriteFile(target, data, 0o644)
	}
	os.Chmod(dst, 0o600)
	return "copied", nil
}

// PrintStageResult is print_stage_result.
func (c Ctx) PrintStageResult(o *Out, agent, src, dst, result string) {
	switch result {
	case "copied":
		o.say("  %s: staged %s → %s", agent, c.disp(src), c.disp(dst))
	case "skipped-exists":
		o.say("  %s: %s already exists — re-run with --force to overwrite.", agent, c.disp(dst))
	case "missing-src":
		o.say("  %s: no host-side state at %s — skipping.", agent, c.disp(src))
	case "refused-nonregular":
		o.say("  %s: %s is not a regular file (a symlink or other) — not writing through it; remove it and re-run.", agent, c.disp(dst))
	}
}

// Agent is onboard_agent: false for an unknown agent.
func (c Ctx) Agent(agent string) (Out, bool) {
	var o Out
	stage := func(name string, pairs ...[2]string) {
		for _, p := range pairs {
			res, errs := c.StageFile(p[0], p[1])
			o.Stderr = append(o.Stderr, errs...)
			c.PrintStageResult(&o, name, p[0], p[1], res)
		}
	}
	h, base := c.Home, c.AgentHomeBase
	mk := func(a string) string {
		d := base + "/" + a
		if !(noFollow() && lexists(d) && !isDirNoFollow(d)) {
			os.MkdirAll(d, 0o755)
		}
		return d
	}
	switch agent {
	case "claude":
		ah := mk("claude")
		stage("claude", [2]string{h + "/.claude/.credentials.json", ah + "/.credentials.json"},
			[2]string{h + "/.claude/settings.json", ah + "/settings.json"})
	case "codex":
		ah := mk("codex")
		stage("codex", [2]string{h + "/.codex/auth.json", ah + "/auth.json"},
			[2]string{h + "/.codex/config.toml", ah + "/config.toml"})
		c.EnsureCodexSandboxMode(&o, ah+"/config.toml")
	case "copilot":
		ah := mk("copilot")
		stage("copilot", [2]string{h + "/.copilot/config.json", ah + "/config.json"})
	case "grok":
		ah := mk("grok")
		stage("grok", [2]string{h + "/.grok/auth.json", ah + "/auth.json"})
		src, dst := h+"/.grok/config.toml", ah+"/config.toml"
		if isRegular(src) && grepE(src, `^[[:space:]]*(api_key|env_key)[[:space:]]*=`) {
			o.say("  grok: %s pins a per-model api_key/env_key — NOT staging it.", c.disp(src))
			o.say("        That key would outrank the OAuth session token (PRINCIPLES.md")
			o.say("        rule 1). Authenticate in-pod with 'grok login --device-auth'.")
		} else {
			stage("grok", [2]string{src, dst})
		}
		c.EnsureGrokPrivacyConfig(&o, dst)
	case "opencode":
		o.say("  opencode: refused — opencode authenticates with an API key, not")
		o.say("            OAuth. PRINCIPLES.md rule 1 forbids baking long-lived")
		o.say("            API keys into agent state. Use 'sandbox secret set")
		o.say("            opencode-api-key' (Phase 4) instead; the secret is")
		o.say("            kept host-side and injected as a session-scoped K8s")
		o.say("            Secret at launch, then deleted on teardown.")
	default:
		o.Stderr = append(o.Stderr, fmt.Sprintf("  %s: not a known agent — skipping.", agent))
		return o, false
	}
	return o, true
}

func isDirNoFollow(p string) bool { st, err := os.Lstat(p); return err == nil && st.IsDir() }

// grepE is `grep -qE re file` (the patterns here use only [[:space:]] and literals).
func grepE(path, re string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	r := regexp.MustCompile(re)
	for _, l := range bashcompat.SplitRecords(b) {
		if r.MatchString(l) {
			return true
		}
	}
	return false
}

// readable reports whether onboard may read cfg: in legacy mode any file reachable through
// symlinks; with AgentHomeNoFollow only a regular file that is not a symlink.
func readable(cfg string) bool {
	if noFollow() {
		return lnoRegular(cfg)
	}
	return isRegular(cfg)
}

// rewrite writes the hardened config: in legacy mode content goes to cfg.tmp (following a
// symlink there), which is then renamed over cfg, and cfg is chmodded (following a symlink);
// with AgentHomeNoFollow it goes through a fresh temp file.
func rewrite(cfg string, data []byte, viaTmp bool) {
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	if noFollow() {
		writeNoFollow(cfg, data)
		return
	}
	if viaTmp {
		os.WriteFile(cfg+".tmp", data, 0o644)
		os.Rename(cfg+".tmp", cfg)
	} else {
		os.WriteFile(cfg, data, 0o644)
	}
	os.Chmod(cfg, 0o600)
}

// catTrimmed is "$(cat file)": the content with trailing newlines (and any NUL) removed.
func catTrimmed(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimRight(strings.ReplaceAll(string(b), "\x00", ""), "\n")
}

const codexHeader = `# Added by 'sandbox onboard'. The pod already isolates this agent (gVisor +
# Cilium default-deny egress + filesystem masking), so Codex's own
# bubblewrap sandbox is redundant — and it cannot start under gVisor
# (bwrap loopback RTM_NEWADDR failure), which blocks apply_patch. This
# disables only that inner OS-sandbox; egress and approval prompts are
# unaffected. Remove this line to restore Codex's built-in sandboxing.
sandbox_mode = "danger-full-access"`

// EnsureCodexSandboxMode is ensure_codex_sandbox_mode: prepend sandbox_mode =
// "danger-full-access" unless the config already sets sandbox_mode.
func (c Ctx) EnsureCodexSandboxMode(o *Out, cfg string) {
	d := c.disp(cfg)
	if unsafeTarget(cfg) || noFollow() && unsafeTarget(cfg+".tmp") {
		o.say("  codex: %s is not a regular file (a symlink or other) — not editing it; remove it and re-run.", d)
		return
	}
	if readable(cfg) && grepE(cfg, `^[[:space:]]*sandbox_mode[[:space:]]*=`) {
		o.say("  codex: %s already sets sandbox_mode — leaving it as-is.", d)
		return
	}
	if c.DryRun {
		o.say("  codex: would set sandbox_mode=\"danger-full-access\" in %s", d)
		return
	}
	if readable(cfg) {
		rewrite(cfg, []byte(codexHeader+"\n\n"+catTrimmed(cfg)), true)
	} else {
		rewrite(cfg, []byte(codexHeader+"\n"), false)
	}
	o.say("  codex: set sandbox_mode=\"danger-full-access\" in %s", d)
}

const grokBlock = `# Added by 'sandbox onboard'. grok 0.2.93 uploaded the ENTIRE repository — not
# just files a prompt read — to xAI's grok-code-session-traces bucket. The pod
# egress allowlist already blocks the hosts those uploads used, but api.x.ai —
# which a session must reach — is not a pure inference channel, so this is the
# client-side veto (defense-in-depth). Reverse-engineered for grok 0.2.93; run
# 'grok inspect' to confirm it still loads. Remove these to restore defaults.
[harness]
disable_codebase_upload = true

[telemetry]
trace_upload = false
enabled = false`

// EnsureGrokPrivacyConfig is ensure_grok_privacy_config: append the [harness] and [telemetry]
// tables that turn off whole-repository upload and trace telemetry, unless the config already sets
// disable_codebase_upload or declares either table.
func (c Ctx) EnsureGrokPrivacyConfig(o *Out, cfg string) {
	d := c.disp(cfg)
	if unsafeTarget(cfg) || noFollow() && unsafeTarget(cfg+".tmp") {
		o.say("  grok: %s is not a regular file (a symlink or other) — not editing it; remove it and re-run.", d)
		return
	}
	if readable(cfg) && grepE(cfg, `^[[:space:]]*disable_codebase_upload[[:space:]]*=`) {
		o.say("  grok: %s already sets disable_codebase_upload — leaving it as-is.", d)
		return
	}
	if readable(cfg) && grepE(cfg, `^[[:space:]]*\[(harness|telemetry)\]`) {
		o.say("  grok: %s already declares a [harness]/[telemetry] table — NOT", d)
		o.say("        auto-editing it (TOML forbids a duplicate header). Add")
		o.say("        'disable_codebase_upload = true' under [harness] (and")
		o.say("        trace_upload = false / enabled = false under [telemetry]) to")
		o.say("        keep whole-repo upload off.")
		return
	}
	if c.DryRun {
		o.say("  grok: would set disable_codebase_upload=true (+ telemetry off) in %s", d)
		return
	}
	if readable(cfg) {
		rewrite(cfg, []byte(catTrimmed(cfg)+"\n\n"+grokBlock+"\n"), true)
	} else {
		rewrite(cfg, []byte(grokBlock+"\n"), false)
	}
	o.say("  grok: set disable_codebase_upload=true (+ telemetry off) in %s", d)
}

const starterConfig = `# ~/.sandbox/config.yaml
#
# Per-user defaults for sandbox sessions. See docs/how-to/persistent-domains.md
# and docs/how-to/profiles-and-overlays.md for the full schema.
# All keys below are optional.

# Extra allowed egress domains, merged with the tier defaults on every
# run. Subject to the org-level blocked-destinations check (and the
# overlay's, if one is configured).
# extra_allowed_domains:
#   - internal-registry.example.com
#   - artifactory.example.com

# Path to a team overlay directory (ships profiles/, GOVERNANCE.md, an
# additional blocked-destinations.yaml, and extra-ca-certs/). See
# examples/overlay-template/. Overlays can only ADD restrictions; they
# cannot weaken org-level controls or the tier model.
# overlay: ~/overlays/myteam
#
# If your team's overlay lives in a (private) git repo, don't set 'overlay:'
# by hand — run 'sandbox link <git-url>' and it will clone the repo, pin it
# to a ref, and manage the overlay/link_url/link_ref/link_commit keys here
# for you. See 'sandbox link --help'.
`

// WriteStarterUserConfig is write_starter_user_config.
func (c Ctx) WriteStarterUserConfig(o *Out) {
	dst := c.Home + "/.sandbox/config.yaml"
	d := c.disp(dst)
	if isRegular(dst) && !c.Force {
		o.say("  config: %s already exists — leaving it alone.", d)
		return
	}
	if c.DryRun {
		o.say("  config: would write starter %s", d)
		return
	}
	os.MkdirAll(filepath.Dir(dst), 0o755)
	os.WriteFile(dst, []byte(starterConfig), 0o644)
	os.Chmod(dst, 0o600)
	o.say("  config: wrote starter %s", d)
}
