package cli

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
)

// LaunchSpec is what the first stage of `sandbox run` decides (cmd_run up to
// ensure_cluster_ready, design group B1): who runs, at which tier, on which repos, with which
// egress, credentials, and overrides. The cluster work that followed in v2 is sandboxd's in v3.
type LaunchSpec struct {
	Agent, Tier, Profile, Overlay, Name string
	Repos, Domains, InfraEndpoints      []string
	InfraTokens                         []string // ENVNAME=PATH
	InfraKubeconfigs                    []string
	InfraKubeContext                    string
	Secrets                             []string
	MCPs, Services                      string // comma-joined, as SESSION_PROFILE_MCPS / _SERVICES
	DryRun, KeepAlive, AllowExecPlugin  bool
	AcceptUnmasked, AcceptUnvetted      bool
	AcceptDrift                         bool
	BaseURL                             string // OPENCODE_BASE_URL after --base-url
	HomeDir                             string // SANDBOX_AGENT_HOME_OVERRIDE
	HasSecrets                          bool
}

var (
	envName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	httpURL  = regexp.MustCompile(`^https?://[^/[:space:]]`)
	secretRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// urlHost is url_host: the host of a URL (scheme, path, query, and a final ":port" removed; a
// userinfo part is kept).
func urlHost(u string) string {
	r := u
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	}
	if i := strings.Index(r, "/"); i >= 0 {
		r = r[:i]
	}
	if i := strings.Index(r, "?"); i >= 0 {
		r = r[:i]
	}
	if i := strings.LastIndex(r, ":"); i >= 0 {
		r = r[:i]
	}
	return r
}

// xargsBasenames is `printf '%s\n' repos | xargs -n1 basename`: xargs splits its input on
// whitespace, so a path with a space yields the basenames of its pieces. With
// DuplicateBasenameExact each repo path is one name.
func xargsBasenames(repos []string) []string {
	var out []string
	for _, r := range repos {
		if deviation.Fixed(deviation.DuplicateBasenameExact) {
			out = append(out, bashcompat.Basename(r))
			continue
		}
		for _, tok := range strings.Fields(r) {
			out = append(out, bashcompat.Basename(tok))
		}
	}
	return out
}

// firstDuplicate is `sort | uniq -d | head -1`.
func firstDuplicate(xs []string) string {
	s := append([]string(nil), xs...)
	sort.Strings(s)
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			return s[i]
		}
	}
	return ""
}

// profileListNames is the bash's split of SESSION_PROFILE_SECRETS: in legacy mode an unquoted
// expansion with IFS=',' (so each piece is glob-expanded against the current directory), then
// `echo | tr -d '[:space:]'`; with LiteralProfileLists each comma-separated piece is taken as
// written, with surrounding whitespace trimmed.
func profileListNames(joined string) []string {
	var out []string
	if deviation.Fixed(deviation.LiteralProfileLists) {
		for _, p := range strings.Split(joined, ",") {
			if p = strings.Trim(p, " \t\n\v\f\r"); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	echoOpt := regexp.MustCompile(`^-[neE]+$`)
	for _, w := range config.IFSSplit(joined, ',') {
		for _, s := range config.BashGlob(w) {
			if echoOpt.MatchString(s) {
				out = append(out, "")
				continue
			}
			out = append(out, strings.Map(func(r rune) rune {
				if strings.ContainsRune(" \t\n\v\f\r", r) {
					return -1
				}
				return r
			}, s))
		}
	}
	return out
}

func (c *cmdCtx) tildeExpand(p string) string {
	if strings.HasPrefix(p, "~") {
		return c.env.Home + p[1:]
	}
	return p
}

// runSyncs is the run path's overlay sync and leakscan config refresh.
func runSyncs(c *cmdCtx) {
	l := c.link()
	l.NoLinkCheck = c.env.NoLinkCheck
	r := l.SyncOnRun()
	for _, o := range r.Stdout {
		c.out("%s", o)
	}
	for _, e := range r.Stderr {
		fmt.Fprintln(c.stderr, e)
	}
	if r.Die != "" {
		c.die("%s", r.Die)
	}
	gate.FetchLeakscanConfig(c.env.Env, gate.FetchEnv{}, func(m string) { c.warn("%s", m) }, c.stdout)
}

// runDecide is cmd_run from argument parsing to ensure_cluster_ready.
func runDecide(c *cmdCtx, args []string) LaunchSpec {
	s := LaunchSpec{Agent: "claude", Tier: "1"}
	agentExplicit, tierExplicit := false, false
	profile := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func(flag string, set func(string)) bool {
			v, ok := flagValue(c, args, &i, flag)
			if ok {
				set(v)
			}
			return ok
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_run")
		case val("--agent", func(v string) { s.Agent, agentExplicit = v, true }):
		case val("--tier", func(v string) { s.Tier, tierExplicit = v, true }):
		case val("--profile", func(v string) { profile = v }):
		case val("--repo", func(v string) { s.Repos = append(s.Repos, v) }):
		case val("--allow-domain", func(v string) { s.Domains = append(s.Domains, v) }):
		case val("--base-url", func(v string) { s.BaseURL = v }):
		case val("--homedir", func(v string) { s.HomeDir = v }):
		case val("--infra-token", func(v string) { s.InfraTokens = append(s.InfraTokens, v) }):
		case val("--infra-kubeconfig", func(v string) { s.InfraKubeconfigs = append(s.InfraKubeconfigs, v) }):
		case val("--infra-kube-context", func(v string) { s.InfraKubeContext = v }):
		case a == "--allow-exec-plugin":
			s.AllowExecPlugin = true
		case val("--infra-endpoint", func(v string) { s.InfraEndpoints = append(s.InfraEndpoints, v) }):
		case a == "--dry-run":
			s.DryRun = true
		case val("--name", func(v string) { s.Name = v }):
		case a == "--keep-alive":
			s.KeepAlive = true
		case a == "--i-accept-unmasked-secrets":
			s.AcceptUnmasked = true
		case a == "--i-accept-unvetted-repo":
			s.AcceptUnvetted = true
		case a == "--i-accept-vetting-drift":
			s.AcceptDrift = true
		default:
			c.die("Unknown option: %s. Run 'sandbox run --help' for usage.", a)
		}
	}
	for i := range s.Repos {
		s.Repos[i] = c.tildeExpand(s.Repos[i])
	}
	for i := range s.InfraKubeconfigs {
		s.InfraKubeconfigs[i] = c.tildeExpand(s.InfraKubeconfigs[i])
	}
	homedir := s.HomeDir
	s.HomeDir = c.env.AgentHomeOverride
	if homedir != "" {
		if c.env.IsMacOS {
			c.warn("--homedir is not supported on macOS (the pod mounts a VM-local agent-home); ignoring.")
		} else {
			s.HomeDir = c.tildeExpand(homedir)
		}
	}

	// The run-path overlay sync, the leakscan config refresh, and the overlay's minimum CLI. The
	// host's pre-pass skips the first two: the run that follows does them.
	if !c.prepass {
		runSyncs(c)
	}
	if ov := config.ResolveOverlayPath(c.env.Env); ov != "" && isDir(ov) {
		unmet, warns := config.OverlayMinVersionUnmet(ov, c.env.Version.Version)
		for _, w := range warns {
			c.warn("%s", w)
		}
		if unmet != "" {
			c.die("overlay '%s' requires agent-sandboxes >= %s, but this is %s. Run 'sandbox upgrade' and launch again.", c.tilde(ov), unmet, c.env.version())
		}
	}

	// Profile resolution.
	var secretsJoined string
	if profile != "" {
		s.Overlay = config.ResolveOverlayPath(c.env.Env)
		if config.IsNumericProfile(profile) {
			if tierExplicit && s.Tier != profile {
				c.die("--profile %s conflicts with --tier %s; pass only one.", profile, s.Tier)
			}
			s.Tier, s.Profile = profile, profile
		} else {
			p, ok := config.FindProfilePath(c.env.Env, profile)
			if !ok {
				c.die("Profile '%s' not found in ~/.sandbox/profiles/ or overlay ($SANDBOX_OVERLAY / ~/.sandbox/config.yaml overlay:).", profile)
			}
			s.Profile = profile
			c.out("==> Loading profile '%s' (%s)", profile, c.tilde(p))
			pt := config.ExtractYAMLScalar(p, "tier")
			if pt == "" {
				c.die("Profile '%s' missing required 'tier:' field.", profile)
			}
			if tierExplicit && s.Tier != pt {
				c.die("Profile '%s' declares tier %s but --tier %s was also passed; remove --tier or change the profile.", profile, pt, s.Tier)
			}
			s.Tier = pt
			if pa := config.ExtractYAMLScalar(p, "agent"); pa != "" {
				if agentExplicit && s.Agent != pa {
					c.die("Profile '%s' declares agent '%s' but --agent '%s' was also passed; remove --agent or change the profile.", profile, pa, s.Agent)
				}
				s.Agent = pa
				c.out("    agent: %s", pa)
			}
			if dr := config.ExtractYAMLScalar(p, "default_repo"); dr != "" && len(s.Repos) == 0 {
				s.Repos = append(s.Repos, c.tildeExpand(dr))
				c.out("    default_repo: %s", dr)
			}
			for _, d := range config.ExtractYAMLList(p, "extra_allowed_domains") {
				if d != "" {
					s.Domains = append(s.Domains, d)
				}
			}
			secretsJoined = strings.Join(config.ExtractYAMLList(p, "secrets"), ",")
			s.MCPs = strings.Join(config.ExtractYAMLList(p, "mcps"), ",")
			s.Services = strings.Join(config.ExtractYAMLList(p, "services"), ",")
		}
	}

	// Step 1: validate the inputs.
	c.out("==> Validating inputs...")
	if err := agents.Validate(s.Agent); err != nil {
		c.fail(err)
	}
	if err := tier.Validate(s.Tier); err != nil {
		c.fail(err)
	}
	baseURL := c.env.OpencodeBaseURL
	if s.BaseURL != "" {
		baseURL = s.BaseURL
	}
	s.BaseURL = baseURL
	if s.Agent == "opencode" {
		if c.env.OpencodeAPIKey == "" {
			c.die("OPENCODE_API_KEY must be set in host environment for opencode agent.")
		}
		if baseURL == "" {
			c.die("opencode requires an OpenAI-compatible endpoint URL — pass --base-url <URL> or set OPENCODE_BASE_URL in the host environment.")
		}
		if !httpURL.MatchString(baseURL) {
			c.die("OPENCODE_BASE_URL must be a complete URL with http(s) scheme — got '%s'. Example: https://vllm-proxy.example.com/v1", baseURL)
		}
	}
	if s.Tier != "1" && len(s.Repos) == 0 {
		c.die("Tier %s requires --repo <PATH>.", s.Tier)
	}
	image := "docker.io/library/sandbox:" + s.Agent
	if s.Tier == "3" {
		image += "-infra"
	}
	if c.env.ImagePresent != nil && c.env.ImagePresent(image) == 1 {
		for _, l := range []string{
			"ERROR: image '" + image + "' is not present in the cluster.",
			"  Agent pods use imagePullPolicy: Never, so this image must be built",
			"  and imported locally before a session can start. The usual cause is",
			"  an install that ran without Docker or Podman (the image build is",
			"  skipped with only a warning). Install a container runtime, then:",
			"",
			"    sandbox rebuild --agent all   # rebuild + import all images",
			"    # or re-run the full install once a runtime is present:",
			"    sandbox install",
			"",
		} {
			c.errOut("%s", l)
		}
		c.die("No runnable image for agent '%s' (tier %s).", s.Agent, s.Tier)
	}
	for _, repo := range s.Repos {
		if err := c.workspace().ValidateRepoPath(repo); err != nil {
			c.fail(err)
		}
	}
	if len(s.Repos) > 1 {
		if dup := firstDuplicate(xargsBasenames(s.Repos)); dup != "" {
			c.die("duplicate --repo basename '%s' — rename one repo or symlink it before passing both.", dup)
		}
	}

	// Infra tokens: NAME=PATH (when NAME is an env name) or a bare PATH.
	var pairs, seen []string
	for _, tok := range s.InfraTokens {
		name, path, env := tok, tok, "INFRA_TOKEN"
		if i := strings.Index(tok, "="); i >= 0 {
			name = tok[:i]
			if envName.MatchString(name) {
				path, env = tok[i+1:], "INFRA_TOKEN_"+name
			}
		}
		path = c.tildeExpand(path)
		for _, e := range seen {
			if e == env {
				c.die("Duplicate infra token target '%s'. Give each --infra-token a distinct NAME=PATH (a bare --infra-token maps to INFRA_TOKEN).", env)
			}
		}
		seen = append(seen, env)
		pairs = append(pairs, env+"="+path)
	}
	s.InfraTokens = pairs
	if s.Tier == "3" {
		if len(pairs) == 0 && len(s.InfraKubeconfigs) == 0 {
			c.die("Tier 3 requires at least one of --infra-token <[NAME=]PATH> or --infra-kubeconfig <PATH>.")
		}
		for _, p := range pairs {
			if f := p[strings.Index(p, "=")+1:]; !config.IsFile(f) {
				c.die("Infra token file not found: %s.", f)
			}
		}
		for _, k := range s.InfraKubeconfigs {
			if !config.IsFile(k) {
				c.die("Kubeconfig file not found: %s.", k)
			}
		}
	} else if len(s.InfraKubeconfigs) > 0 {
		c.die("--infra-kubeconfig is only valid for tier 3.")
	}
	if s.InfraKubeContext != "" && len(s.InfraKubeconfigs) == 0 {
		c.die("--infra-kube-context requires --infra-kubeconfig.")
	}
	if s.InfraKubeContext != "" && len(s.InfraKubeconfigs) > 1 {
		c.die("--infra-kube-context is only valid with a single --infra-kubeconfig. With multiple kubeconfigs, each contributes its own current-context; pre-select the context in each file before mounting.")
	}

	// The egress allowlist: operator extras, then the vetted per-repo lists.
	ue := c.env.Env
	for _, d := range config.UserExtraAllowedDomains(ue) {
		if d != "" {
			s.Domains = append(s.Domains, d)
		}
	}
	honor := "false"
	if config.HonorRepoAllowedDomains(c.env.Env) {
		honor = "true"
	}
	v := c.vetting()
	var honored, ungranted []string
	for _, repo := range s.Repos {
		rc := repo + "/" + config.RepoConfigName
		if !config.IsFile(rc) {
			continue
		}
		var got []string
		for _, d := range v.RepoGrantedAllowedDomains(honor, repo) {
			if d == "" {
				continue
			}
			got = append(got, d)
			s.Domains = append(s.Domains, d)
			honored = append(honored, bashcompat.Basename(repo)+": "+d)
		}
		for _, d := range config.LoadExtraAllowedDomains(rc) {
			if d == "" {
				continue
			}
			in := false
			for _, h := range got {
				if h == d {
					in = true
					break
				}
			}
			if !in {
				ungranted = append(ungranted, bashcompat.Basename(repo)+": "+d)
			}
		}
	}
	if len(honored) > 0 {
		c.out("==> Honoring %d vetted per-repo egress domain(s) (overlay opted in via honor_repo_allowed_domains; read from each repo's signed HEAD, not its working tree); each still passes the block-list check:", len(honored))
		for _, d := range honored {
			c.out("      - %s", d)
		}
	}
	if len(ungranted) > 0 {
		e := func(f string, a ...interface{}) { c.errOut(f, a...) }
		if honor == "true" {
			e("==> NOTICE: %d extra egress domain(s) requested by a repo's", len(ungranted))
			e("    .sandbox/config.yaml were NOT granted — they are not in that repo's current")
			e("    vetting attestation (the repo is unvetted, or the list changed since it was")
			e("    signed, so the signature does not cover them):")
			for _, d := range ungranted {
				e("      - %s", d)
			}
			e("    Re-vet the repo ('sandbox vet') to cover the updated list, or grant one this")
			e("    launch with --allow-domain <domain>. See docs/how-to/persistent-domains.md.")
		} else {
			e("==> NOTICE: %d extra egress domain(s) are requested by a repo's", len(ungranted))
			e("    .sandbox/config.yaml but were NOT granted — a repo config cannot widen egress")
			e("    (an in-sandbox agent could otherwise self-add an exfil destination):")
			for _, d := range ungranted {
				e("      - %s", d)
			}
			e("    To allow one, grant it operator-side: --allow-domain <domain> (this launch),")
			e("    extra_allowed_domains: in ~/.sandbox/config.yaml, or an overlay profile; or set")
			e("    honor_repo_allowed_domains: true in your team overlay to honor each repo's")
			e("    VETTED domain list. See docs/how-to/persistent-domains.md.")
		}
	}

	// Every egress target, infra endpoint, and blocked CIDR through the checks.
	chk := c.checks()
	egress := func(t string) {
		w, err := chk.CheckEgressTargetNotBlocked(t)
		for _, l := range w {
			fmt.Fprintln(c.stderr, l)
		}
		if err != nil {
			c.fail(err)
		}
	}
	for _, d := range s.Domains {
		egress(d)
	}
	for _, ep := range s.InfraEndpoints {
		if h := urlHost(ep); h != "" {
			egress(h)
		}
	}
	if err := chk.CheckBlockedCIDRsValid(); err != nil {
		c.fail(err)
	}

	// Profile-declared secrets must be in the host-side store.
	if secretsJoined != "" {
		for _, name := range profileListNames(secretsJoined) {
			if name == "" {
				continue
			}
			switch {
			case len(name) > 64:
				c.errOut("ERROR: secret name '%s' is longer than 64 characters.", name)
				panic(exit(1))
			case !secretRe.MatchString(name):
				c.errOut("ERROR: secret name '%s' must match [A-Z_][A-Z0-9_]* — the", name)
				c.errOut("       name is also the env-var the agent sees inside the pod.")
				panic(exit(1))
			}
			if !c.secretPresent(name) {
				c.die("Profile '%s' requires secret '%s' but it's not in the host-side store. Run 'sandbox secret set %s' first.", s.Profile, name, name)
			}
			s.Secrets = append(s.Secrets, name)
		}
		if len(s.Secrets) > 0 {
			s.HasSecrets = true
			c.out("==> Profile secrets to inject: %s", strings.Join(s.Secrets, " "))
		}
	}
	return s
}

// cmdRun is cmd_run up to the cluster work: the launch decisions (B1), then the gates and the
// session record (B3). The session itself is sandboxd's in v3 and does not exist yet; nor does
// the broker that takes --infra-kubeconfig (design 5.9.5), which replaces v2's Step 1b.
func cmdRun(c *cmdCtx, args []string) {
	s := runDecide(c, args)
	if c.env.StopAtDecisions && c.env.RunHandoff != nil {
		c.env.RunHandoff(s, nil)
		return
	}
	if len(s.InfraKubeconfigs) > 0 {
		c.die("--infra-kubeconfig is not yet available in the Go port of the sandbox CLI: v3 hands kubeconfigs to the credential broker (design 5.9.5), which does not exist yet.")
	}
	rec := runPrepare(c, &s)
	if c.env.RunHandoff != nil {
		c.env.RunHandoff(s, &rec)
		return
	}
	if c.env.Launch.Sessions != nil {
		c.launch(s, rec)
		return
	}
	c.die("'run' is not yet available in the Go port of the sandbox CLI: the launch decisions are made and the session recorded, but the session runtime (sandboxd) does not exist yet.")
}
