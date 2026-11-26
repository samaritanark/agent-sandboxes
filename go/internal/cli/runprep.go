package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/catalogue"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/mounts"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
	"github.com/samaritanark/agent-sandboxes/go/internal/vetting"
	"github.com/samaritanark/agent-sandboxes/go/internal/workspace"
)

// Dependency is one resolved profile dependency (resolve_session_dependencies): the catalogue
// entry, its kind and port, the secrets it declares, and for an MCP server its transport and
// path. v2's Kubernetes naming (resource name, service FQDN) is kept for the comparison only;
// in v3 sandboxd names the dependency microVM.
type Dependency struct {
	Name, Kind, Resource, Port, Path string
	Secrets                          []string
	MCPRecord                        string // name|transport|url for an MCP server
}

// SessionRecord is what the second stage of `sandbox run` adds (cmd_run Steps 2 to 4, design
// group B3): the gates have passed, and the session has an ID, a name, a session.json, a
// workspace baseline, and the inputs of its egress policy.
type SessionRecord struct {
	ID, PodName, LogDir string
	EndpointTrusted     string        // "true" or "false" once the tier 2/3 gates ran; "" at tier 1
	Image               string        // the agent image (v2's container_image)
	Policy              PolicyRequest // what v2 handed build_cilium_policy
	Dependencies        []Dependency
	DomainCount         int    // the recorded allowlist's length, for the banner
	AgentSessionID      string // the agent's pinned conversation id, when it takes one
}

// randBytes is head -c n /dev/urandom.
func (c *cmdCtx) randBytes(n int) []byte {
	if c.env.RandBytes != nil {
		return c.env.RandBytes(n)
	}
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (c *cmdCtx) now() time.Time { return time.Unix(c.env.Now(), 0).UTC() }

func (c *cmdCtx) stamp() string { return c.now().Format("2006-01-02T15:04:05Z") }

// sessionID is generate_session_id: ses-<YYYYMMDD>-<HHMMSS>-<4hex>.
func (c *cmdCtx) sessionID() string {
	t := c.now()
	return "ses-" + t.Format("20060102") + "-" + t.Format("150405") + "-" + hex.EncodeToString(c.randBytes(2))
}

// uuid is generate_uuid: a v4 UUID laid out from 16 random bytes exactly as the bash does it
// (nibble 12 is dropped for the version digit, nibble 16 becomes the variant).
func (c *cmdCtx) uuid() string {
	h := hex.EncodeToString(c.randBytes(16))
	n, _ := strconv.ParseUint(h[16:17], 16, 8)
	return fmt.Sprintf("%s-%s-4%s-%x%s-%s", h[0:8], h[8:12], h[13:16], n&0x3|0x8, h[17:20], h[20:32])
}

// dnsLabel is `echo "$s" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-' | sed
// 's/^-*//;s/-*$//'` in the C locale: bytewise, every run of other bytes (and of hyphens)
// becomes one hyphen, with hyphens trimmed from both ends. echo swallows an option word.
func dnsLabel(s string) string {
	if echoOption.MatchString(s) {
		s = ""
	}
	var b strings.Builder
	dash := false
	for _, ch := range []byte(asciiLower(s) + "\n") {
		ok := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9'
		if ok {
			b.WriteByte(ch)
			dash = false
			continue
		}
		if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// asciiLower lowercases A-Z only (tr '[:upper:]' '[:lower:]' under LC_ALL=C).
func asciiLower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + 32
		}
	}
	return string(b)
}

var echoOption = regexp.MustCompile(`^-[neE]+$`)

// namespace is SANDBOX_NAMESPACE, a constant in bin/sandbox.
const namespace = "sandbox"

func (c *cmdCtx) catalogue() catalogue.Ctx {
	return catalogue.Ctx{Ctx: c.checks(), SandboxRoot: c.env.SandboxRoot,
		HasCosign: func() bool { _, err := exec.LookPath("cosign"); return err == nil },
		RunCosign: func(args []string) bool { return exec.Command("cosign", args...).Run() == nil }}
}

// resolveDependencies is the policy half of resolve_session_dependencies: each name in the
// profile's mcps: and services: lists must be a valid catalogue entry of that kind, within the
// per-session ceiling, with its declared secrets in the host store, and an MCP server only for an
// agent that can use one. ok is false after the error lines are printed.
func (c *cmdCtx) resolveDependencies(sessionID, agent, mcps, services string) ([]Dependency, bool) {
	type want struct{ kind, name string }
	var pending []want
	for _, n := range profileListNames(mcps) {
		if n != "" {
			pending = append(pending, want{"mcp", n})
		}
	}
	for _, n := range profileListNames(services) {
		if n != "" {
			pending = append(pending, want{"service", n})
		}
	}
	if len(pending) == 0 {
		return nil, true
	}
	e := func(lines ...string) {
		for _, l := range lines {
			fmt.Fprintln(c.stderr, l)
		}
	}
	max := "6"
	if c.env.MaxDeps != "" {
		max = c.env.MaxDeps
	}
	if m, _ := strconv.Atoi(max); len(pending) > m {
		e(fmt.Sprintf("ERROR: profile declares %d dependencies, over the per-session", len(pending)),
			fmt.Sprintf("       ceiling of %s. Trim the profile, or raise", max),
			"       SANDBOX_MAX_DEPS_PER_SESSION if your node can carry more.")
		return nil, false
	}
	cat := c.catalogue()
	var deps []Dependency
	for _, w := range pending {
		path, ok := cat.Resolve(w.name)
		if !ok {
			e(fmt.Sprintf("ERROR: profile declares dependency '%s' but no catalogue entry", w.name),
				"       was found (config/catalogue/ or the overlay's catalogue/).")
			return nil, false
		}
		if err := cat.ValidateEntry(path, w.name); err != nil {
			c.printErr(err)
			return nil, false
		}
		kind, port := catalogue.Field(path, "kind", ""), catalogue.Field(path, "port", "")
		if w.kind != kind {
			e(fmt.Sprintf("ERROR: dependency '%s' is declared under '%ss:'", w.name, w.kind),
				fmt.Sprintf("       but its catalogue entry is kind '%s'. Move it to the", kind),
				fmt.Sprintf("       '%ss:' list.", kind))
			return nil, false
		}
		d := Dependency{Name: w.name, Kind: kind, Resource: "dep-" + dnsLabel(w.name) + "-" + sessionID, Port: port, Path: path}
		for _, s := range catalogue.List(path, "secrets") {
			if s == "" {
				continue
			}
			if !c.secretPresent(s) {
				e(fmt.Sprintf("ERROR: dependency '%s' requires secret '%s' but it is", w.name, s),
					fmt.Sprintf("       not in the host-side store. Run 'sandbox secret set %s'.", s))
				return nil, false
			}
			d.Secrets = append(d.Secrets, s)
		}
		if kind == "mcp" {
			if !agents.SupportsMCP(agent) {
				e(fmt.Sprintf("ERROR: profile declares MCP dependency '%s', but agent", w.name),
					fmt.Sprintf("       '%s' has no per-session MCP wiring yet (only 'claude'", agent),
					"       is supported). Remove it or use --agent claude.")
				return nil, false
			}
			url := "http://" + d.Resource + "." + namespace + ".svc.cluster.local:" + port + catalogue.Field(path, "mcp_path", "/mcp")
			d.MCPRecord = w.name + "|" + catalogue.Field(path, "mcp_transport", "http") + "|" + url
		}
		deps = append(deps, d)
	}
	for _, d := range deps {
		if catalogue.Field(d.Path, "class", "") == "browser" {
			e("WARN: this session includes a browser dependency. Even fully",
				"      contained, a browser is a richer exfiltration channel WITHIN",
				"      the allowlist than the bare agent (it can POST bodies, open",
				"      WebSockets, and encode data into a wildcard-allowed domain).",
				"      Audit sees destination granularity, not URL paths or bodies",
				"      inside TLS (§1.7). Keep the allowlist tight.")
			break
		}
	}
	return deps, true
}

// printErr prints an error's lines to stderr.
func (c *cmdCtx) printErr(err error) { fmt.Fprintln(c.stderr, err.Error()) }

// runPrepare is cmd_run Steps 2 to 7: the workspace gates, the session ID and name, the profile
// dependencies, the session record, the workspace baseline, the image, and the inputs of the
// egress policy. It stops where v2 rendered the policy for the cluster.
func runPrepare(c *cmdCtx, s *LaunchSpec) SessionRecord {
	var rec SessionRecord
	var overrides []audit.Override
	var vettingSummary, secretSummary string

	// Step 2: the workspace check and the two gates.
	if t, _ := strconv.Atoi(s.Tier); t >= 2 && len(s.Repos) > 0 {
		c.out("==> Running pre-session workspace check...")
		for _, r := range s.Repos {
			for _, l := range workspace.Prescan(r) {
				c.out("%s", l)
			}
		}
		c.maskTypeCheck(s.Repos)
		vettingSummary, secretSummary, rec.EndpointTrusted = c.workspaceGates(s.Agent, s.BaseURL, s.Repos,
			s.AcceptUnmasked, s.AcceptUnvetted, s.AcceptDrift, &overrides)
	}

	// Step 3: the session ID, the profile's dependencies, and the names.
	rec.ID = c.sessionID()
	c.out("==> Session ID: %s", rec.ID)
	deps, ok := c.resolveDependencies(rec.ID, s.Agent, s.MCPs, s.Services)
	if !ok {
		c.die("Dependency resolution failed; aborting launch.")
	}
	rec.Dependencies = deps
	if len(deps) > 0 {
		var names []string
		for _, d := range deps {
			names = append(names, d.Name)
		}
		c.out("==> Profile dependencies: %s", strings.Join(names, " "))
	}
	if s.Name == "" {
		switch len(s.Repos) {
		case 0:
			s.Name = s.Agent
		case 1:
			s.Name = bashcompat.Basename(s.Repos[0]) + "/" + s.Agent
		default:
			s.Name = "multi/" + s.Agent
		}
	}
	rec.PodName = "sandbox-" + dnsLabel(s.Name) + "-" + rec.ID[strings.LastIndex(rec.ID, "-")+1:]

	// Step 4: the session record.
	rec.LogDir = c.env.LogsDir + "/" + rec.ID
	if err := os.MkdirAll(rec.LogDir, 0o755); err != nil {
		c.die("cannot create %s: %v", rec.LogDir, err)
	}
	ad, _ := agents.Domains(s.Agent, s.BaseURL)
	var domains []string
	seen := map[string]bool{}
	for _, d := range append(append(ad, tier.Domains(s.Tier)...), s.Domains...) {
		// awk 'NF && !seen[$0]++': blank and whitespace-only lines are dropped.
		if strings.Trim(d, " \t\n") == "" || seen[d] {
			continue
		}
		seen[d] = true
		domains = append(domains, d)
	}
	line, _ := audit.WriteSessionJSON(rec.LogDir, audit.Session{ID: rec.ID, Agent: s.Agent, Tier: s.Tier,
		User: c.env.User, Repos: s.Repos, Name: s.Name, PodName: rec.PodName, StartTime: c.stamp(),
		CredentialType: agents.CredentialType(s.Agent), Domains: domains, Profile: s.Profile,
		Overlay: s.Overlay, InfraToken: len(s.InfraTokens) > 0, InfraKubeconfig: len(s.InfraKubeconfigs) > 0})
	if line != "" {
		c.out("%s", line)
	}
	rec.DomainCount = len(domains)
	if agents.SessionIDFlag(s.Agent) != "" {
		rec.AgentSessionID = c.uuid()
		audit.RecordAgentSessionID(rec.LogDir, rec.AgentSessionID)
	}
	if vettingSummary != "" {
		audit.LogEvent(rec.LogDir, "vetting", vettingSummary, c.stamp())
	}
	if secretSummary != "" {
		audit.LogEvent(rec.LogDir, "secret-scan", secretSummary, c.stamp())
	}
	audit.FlushOverrides(rec.LogDir, overrides, c.stamp())

	// Step 5: the workspace baseline; Step 6: the image; Step 7: the policy's inputs.
	if t, _ := strconv.Atoi(s.Tier); t >= 2 && len(s.Repos) > 0 {
		c.out("==> Capturing workspace baseline...")
		c.out("%s", workspace.CaptureBaseline(rec.LogDir, s.Repos, workspace.PruneDirs(c.env.SandboxRoot)))
	}
	image := "docker.io/library/sandbox:" + s.Agent
	if s.Tier == "3" {
		image += "-infra"
	}
	c.out("==> Image: %s", image)
	c.out("==> Building network policy...")
	rec.Image = image
	rec.Policy = PolicyRequest{SessionID: rec.ID, Agent: s.Agent, Tier: s.Tier,
		Extras: append(infraPolicyNames(s.InfraEndpoints), s.Domains...)}
	return rec
}

// infraPolicyNames is what each --infra-endpoint contributes to the session's allowlist. v2 handed
// the value to the policy builder as given, so a URL became a name that matched nothing, while the
// block check had looked at its host; with InfraEndpointHost the allowlist takes the host the
// block check saw (url_host), and an endpoint with no host adds nothing.
func infraPolicyNames(eps []string) []string {
	out := []string{}
	for _, ep := range eps {
		if !deviation.Fixed(deviation.InfraEndpointHost) {
			out = append(out, ep)
		} else if h := urlHost(ep); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// workspaceGates is the tier 2/3 gate sequence cmd_run Step 2 and recreate_session_pod share:
// the vetting gate, then the secret gate (with the trusted-endpoint downgrade and the overlay's
// forbidden-override knob). A refusal exits; otherwise it returns the two gates' summaries and
// whether the inference endpoint is trusted, and appends each accepted override.
func (c *cmdCtx) workspaceGates(agent, baseURL string, repos []string, acceptUnmasked, acceptUnvettedFlag, acceptDrift bool,
	overrides *[]audit.Override) (vettingSummary, secretSummary, trusted string) {
	tf := func(b bool) string {
		if b {
			return "true"
		}
		return "false"
	}
	recordOverride := func(m, what string, repos []string) {
		*overrides = append(*overrides, audit.RecordOverride(m, what, repos...))
	}
	v := c.vetting()
	a := vetting.Attester{Ctx: v, Out: c.stdout, Err: c.stderr, Stdin: c.stdin,
		Warn: func(m string) { c.warn("%s", m) },
		Scan: func(r, accept string) []string { return gate.ScanRepoSecrets(c.env.Env, r, accept, c.stderr) }}
	vd := vetting.GateDeps{Out: c.stdout, Err: c.stderr, Stdin: c.stdin, TTY: c.env.StdinTTY && c.env.StdoutTTY,
		Status: v.StatusRepo, RecordOverride: recordOverride, SigningConfigured: v.SigningConfigured,
		InlineAttest: a.InlineAttest,
		Cfg: vetting.GateConfig{ForbidOverride: v.ForbidUnvettedOverride(), TrustRoots: v.TrustRoots(),
			TrustRoot: v.TrustRoot(), Cap: v.MaxCommitsBehind(), AgeCap: v.MaxAgeDays(), AgeDays: v.AgeDays}}
	rc, sum := vd.VettingGateRepos(v.ResolvePosture(), tf(acceptUnvettedFlag), tf(acceptDrift), repos)
	if rc != 0 {
		panic(exit(rc))
	}
	vettingSummary = sum
	trusted = "false"
	if ep := agents.InferenceEndpoint(agent, baseURL); ep != "" && c.checks().InferenceEndpointIsTrusted(ep) {
		trusted = "true"
	}
	acceptUnvetted := acceptUnvettedFlag && v.ForbidUnvettedOverride() != "true"
	var stdin *bufio.Reader
	if c.env.StdinTTY {
		stdin = c.stdin
	}
	gd := gate.GateDeps{Out: c.stdout, Err: c.stderr, Stdin: stdin, IsTTY: c.env.StdinTTY,
		VettedAcceptedFingerprints: func(repo, unvetted string) string {
			var b strings.Builder
			for _, l := range v.VettedAcceptedFingerprints(repo, unvetted) {
				b.WriteString(l + "\n")
			}
			return b.String()
		},
		ExceptionsFromCommit: func() bool { return v.ExceptionsFromCommit() == "true" },
		RecordOverride:       recordOverride,
		LoadRepoAcceptedSecrets: func(repo string) string {
			return strings.Join(config.LoadRepoAcceptedSecrets(repo), "\n")
		},
		Warn: func(m string) { c.warn("%s", m) },
		Scan: func(r, accept string) []string { return gate.ScanRepoSecrets(c.env.Env, r, accept, c.stderr) }}
	rc, sum = gate.SecretGateRepos(gd, tf(acceptUnmasked), trusted, tf(acceptUnvetted), repos)
	if rc != 0 {
		panic(exit(rc))
	}
	secretSummary = sum
	return vettingSummary, secretSummary, trusted
}

// maskTypeCheck is the refusal of check_masking_paths: a path a mask would cover that exists as
// the other type stops the launch (kept as policy in v3; see mounts.Mismatches).
func (c *cmdCtx) maskTypeCheck(repos []string) {
	var all []mounts.Mismatch
	for _, r := range repos {
		all = append(all, mounts.Mismatches(r)...)
	}
	if len(all) == 0 {
		return
	}
	why := "(would crash gVisor at container start):"
	if deviation.Fixed(deviation.MaskMismatchNoGVisor) {
		why = "(the mask would not cover them):"
	}
	fmt.Fprintf(c.stderr, "\nERROR: workspace paths exist with a type the mask cannot safely apply\n       %s\n", why)
	for _, m := range all {
		fmt.Fprintf(c.stderr, "    %s\n      mask expects %s, found %s\n", m.Path, m.Expected, m.Actual)
	}
	fmt.Fprint(c.stderr, "\n  Either remove these paths or convert them to the expected type.\n \n")
	panic(exit(1))
}
