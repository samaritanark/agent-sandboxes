package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
)

// PolicyRequest is what v2 handed build_cilium_policy when it regenerated a live session's egress
// policy: the session, its agent and tier, the recorded kube API endpoint, the extra domains (the
// allowlist minus the agent and tier defaults), and the dependencies' endpoints. In v3 sandboxd
// and the gateway take it instead.
type PolicyRequest struct {
	SessionID, Agent, Tier      string
	KubeAPICIDR, KubeAPIPort    string
	KubeHostEntity              string
	Extras, DependencyEndpoints []string // DependencyEndpoints: "resource_name port"
}

// sessionRecord reads <logs>/<id>/session.json as one JSON object; ok is false for anything else.
func sessionRecord(path string) (jqjson.Value, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return jqjson.Value{}, false
	}
	v, err := jqjson.ParseOne(string(b))
	if err != nil || v.Kind != jqjson.Object {
		return jqjson.Value{}, false
	}
	return v, true
}

// jqRawField is `jq -r '.KEY // DEF'` on an object: strings raw, other values in jq's compact
// layout, DEF for a missing, null, or false field.
func jqRawField(v jqjson.Value, key, def string) string {
	x := v.Get(key)
	switch {
	case x.Kind == jqjson.Null || (x.Kind == jqjson.Bool && !x.B):
		return def
	case x.Kind == jqjson.String:
		return x.Str
	}
	return strings.TrimSuffix(jqjson.Encode(x), "\n")
}

// stringsUnique is jq's `unique` on strings: sorted bytewise, duplicates removed.
func stringsUnique(xs []string) []string {
	s := append([]string(nil), xs...)
	sort.Strings(s)
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// stringsMinus is jq's array subtraction: every element of a that is not in b, order kept.
func stringsMinus(a []string, b ...[]string) []string {
	drop := map[string]bool{}
	for _, l := range b {
		for _, x := range l {
			drop[x] = true
		}
	}
	var out []string
	for _, x := range a {
		if !drop[x] {
			out = append(out, x)
		}
	}
	return out
}

// cmdAllow is cmd_allow: add domains to a live session's egress allowlist. The checks, the merge,
// and the session record are ported; the policy itself is sandboxd's and the gateway's in v3.
func cmdAllow(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_allow")
	}
	var sessionID string
	var add []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			c.usage("usage_allow")
		}
		if v, ok := flagValue(c, args, &i, "--add-domain"); ok {
			add = append(add, v)
			continue
		}
		if strings.HasPrefix(a, "-") {
			c.die("Unknown option for 'allow': %s", a)
		}
		if sessionID != "" {
			c.die("Unexpected extra argument: %s (only one session-id allowed).", a)
		}
		sessionID = a
	}
	if sessionID == "" {
		c.die("Usage: sandbox allow <session-id> --add-domain <DOMAIN> [...]")
	}
	if len(add) == 0 {
		c.die("At least one --add-domain is required.")
	}
	logDir := c.env.LogsDir + "/" + sessionID
	sj := logDir + "/session.json"
	if !config.IsFile(sj) {
		c.die("No session.json for %s at %s/.", sessionID, c.tilde(logDir))
	}

	// Each new domain through the block lists, before any session is touched.
	chk := c.checks()
	for _, d := range add {
		var w []string
		var err error
		if deviation.Fixed(deviation.AllowEgressFullCheck) {
			w, err = chk.CheckEgressTargetNotBlocked(d)
		} else {
			w, err = chk.CheckDomainNotBlocked(d)
		}
		for _, l := range w {
			fmt.Fprintln(c.stderr, l)
		}
		if err != nil {
			c.fail(err)
		}
	}
	if err := chk.CheckBlockedCIDRsValid(); err != nil {
		c.fail(err)
	}

	// The session must be live: hot-reload against a stopped one would leave the record wrong.
	rec, ok := sessionRecord(sj)
	if !ok {
		c.die("%s is not a session record (one JSON object).", c.tilde(sj))
	}
	pod := jqRawField(rec, "pod_name", "")
	if pod == "" {
		pod = "sandbox-" + sessionID
	}
	if c.env.SessionLive == nil || c.env.ApplyPolicy == nil {
		c.die("'allow' is not yet available in the Go port of the sandbox CLI: the domains pass the checks, but the session runtime (sandboxd) does not exist yet.")
	}
	if !c.env.SessionLive(sessionID, pod) {
		c.die("Pod %s not running — hot-reload only works on live sessions. (Use 'sandbox run' to start a new session with the wider allowlist.)", pod)
	}

	agent, tierV := jqInterp(rec.Get("agent")), jqInterp(rec.Get("tier")) // jq -r '.agent', '.tier'
	ad, err := agents.Domains(agent, c.env.OpencodeBaseURL)
	if err != nil {
		c.fail(err)
	}
	var cur []string
	switch x := rec.Get("allowed_domains"); x.Kind {
	case jqjson.Null:
		// v2 merges a missing list as empty, then fails counting the new domains with
		// `($cur | unique)`. run always writes the list, so only a hand-made record gets here.
		c.errOut("jq: error (at <unknown>): Cannot iterate over null (null)")
		panic(exit(5))
	case jqjson.Array:
		for _, e := range x.Arr {
			if e.Kind != jqjson.String {
				c.die("%s: allowed_domains holds a value that is not a string.", c.tilde(sj))
			}
			cur = append(cur, e.Str)
		}
	default:
		c.die("%s: allowed_domains is not a list.", c.tilde(sj))
	}
	full := stringsUnique(append(append([]string(nil), cur...), add...))
	extras := stringsMinus(full, ad, tier.Domains(tierV))
	added := len(stringsMinus(stringsUnique(add), stringsUnique(cur)))
	if added == 0 {
		c.out("All requested domains are already in the allowlist; nothing to do.")
		return
	}

	req := PolicyRequest{SessionID: sessionID, Agent: agent, Tier: tierV,
		KubeAPICIDR: jqRawField(rec, "kube_api_cidr", ""), KubeAPIPort: jqRawField(rec, "kube_api_port", ""),
		KubeHostEntity: jqRawField(rec, "kube_host_entity", ""), Extras: extras}
	if deps := rec.Get("dependencies"); deps.Kind == jqjson.Array {
		for _, d := range deps.Arr {
			req.DependencyEndpoints = append(req.DependencyEndpoints,
				jqInterp(d.Get("resource_name"))+" "+jqInterp(d.Get("port")))
		}
	}
	c.out("==> Regenerating CiliumNetworkPolicy for %s...", sessionID)
	if err := c.env.ApplyPolicy(req); err != nil {
		c.die("%v", err)
	}
	c.out("  Applied: %d new domain(s).", added)

	fv := jqjson.Arr()
	for _, d := range full {
		fv.Arr = append(fv.Arr, jqjson.Str(d))
	}
	audit.SetField(logDir, "allowed_domains", fv)
	audit.LogEvent(logDir, "allowlist-extended", "Added domains: "+strings.Join(add, ","), c.stamp())
	c.out("")
	c.out("Allowlist updated for %s.", sessionID)
	c.out("  Full allowed-domain count: %d", len(full))
}

// jqInterp is a value as `jq -r '.x'` prints a scalar, and as a jq string interpolation "\(.x)"
// renders one: strings raw, null as "null", numbers and booleans as written. (Arrays and objects
// differ between the two layouts; a session record does not hold one in these fields.)
func jqInterp(v jqjson.Value) string {
	if v.Kind == jqjson.String {
		return v.Str
	}
	return strings.TrimSuffix(jqjson.Encode(v), "\n")
}
