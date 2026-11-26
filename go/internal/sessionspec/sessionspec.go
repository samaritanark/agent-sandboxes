// Package sessionspec is the session spec (design 5.4.2): the one document the unprivileged
// policy CLI hands sandboxd for a session, replacing v2's pod YAML, network policy, Secrets,
// ConfigMap, and Services. It holds everything sandboxd and the gateway need and nothing else,
// and never a credential value: credentials are broker bindings with placeholders.
//
// Decode is strict (unknown fields are refused), and Validate is sandboxd's structural check.
// Several invariants hold by construction: the spec has no field for privileged mode or
// capabilities, and a dependency has no field for mounts, so a spec asking for either does not
// decode.
package sessionspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// Version is the spec version this package reads and writes.
const Version = 1

// The VM's directories that mounts may come from (design 5.6, 5.7).
const (
	WorkspaceStore = "/var/lib/sandbox/workspaces" // the sync's workspace copies, one per repository
	SessionStore   = "/var/lib/sandbox/sessions"   // each session's own files, by session ID
)

// DefaultMaxDependencies is v2's SANDBOX_MAX_DEPS_PER_SESSION default (design 5.5.3).
const DefaultMaxDependencies = 6

// Spec is one session.
type Spec struct {
	Version      int               `json:"version"`
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Agent        string            `json:"agent"`
	Tier         int               `json:"tier"`
	Image        string            `json:"image"` // pinned by digest
	Command      []string          `json:"command"`
	Resources    Resources         `json:"resources"`
	Mounts       []Mount           `json:"mounts"`
	Env          []EnvVar          `json:"env"`
	Egress       Egress            `json:"egress"`
	Bindings     []Binding         `json:"bindings"`
	Readable     []Readable        `json:"readable,omitempty"`
	Dependencies []Dependency      `json:"dependencies,omitempty"`
	KeepAlive    bool              `json:"keep_alive"`
	Audit        map[string]string `json:"audit,omitempty"`
}

// Resources are a microVM's limits (design 5.5.3); memory is fixed at creation.
type Resources struct {
	CPUs         float64 `json:"cpus"`
	MemoryMiB    int     `json:"memory_mib"`
	EphemeralGiB int     `json:"ephemeral_gib"`
}

// MountKind is what a mount is.
type MountKind string

const (
	Workspace   MountKind = "workspace"    // a workspace copy
	ReadOnly    MountKind = "readonly"     // a read-only overlay of a path in a workspace copy (exec vectors)
	MaskFile    MountKind = "mask-file"    // an empty file over a path (sandboxd makes it)
	MaskDir     MountKind = "mask-dir"     // an empty directory over a path (sandboxd makes it)
	History     MountKind = "history"      // the agent's history store
	AgentConfig MountKind = "agent-config" // re-staged agent configuration (design 5.7)
	CABundle    MountKind = "ca-bundle"
	MCPConfig   MountKind = "mcp-config"
	Kubeconfig  MountKind = "kubeconfig" // generated, placeholders only
)

// Mount is one mount into the session's microVM. Source is a VM path (empty for masks); Target is
// the path in the guest.
type Mount struct {
	Kind     MountKind `json:"kind"`
	Source   string    `json:"source,omitempty"`
	Target   string    `json:"target"`
	ReadOnly bool      `json:"read_only,omitempty"`
}

// EnvVar is one environment variable. A variable that carries a credential holds its binding's
// placeholder (Binding.EnvVar names it).
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Egress is the session's network policy (design 5.8): the allowlist after apex expansion,
// the merged block lists, L7 rules, and the declared host endpoints and extra ports.
type Egress struct {
	Allow         []string       `json:"allow"`
	BlockDomains  []string       `json:"block_domains,omitempty"`
	BlockCIDRs    []string       `json:"block_cidrs,omitempty"`
	L7            []L7Rule       `json:"l7,omitempty"`
	HostEndpoints []HostEndpoint `json:"host_endpoints,omitempty"`
	ExtraPorts    []int          `json:"extra_ports,omitempty"`
}

// L7Rule limits the requests to a destination (design 5.8.5, the l7 package), deny first.
type L7Rule = l7.Rule

// HostEndpoint is a declared Tier 3 host or VPN endpoint (design 5.2.6).
type HostEndpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// Binding is a brokered credential (credential-brokering design): the broker attaches the value
// named by Ref to requests for Hosts that present Placeholder. Never the value itself.
type Binding struct {
	Ref         string   `json:"ref"`
	Hosts       []string `json:"hosts"`
	Inject      string   `json:"inject"` // "bearer", "header:<name>", "query:<name>", "basic"
	Placeholder string   `json:"placeholder"`
	EnvVar      string   `json:"env_var,omitempty"` // the variable that carries the placeholder, if any
	// Limits on the credential's use, enforced by the broker per credential (all bindings of one
	// Ref must state the same): requests a minute and burst (0: the broker's defaults), and a
	// quota of requests for the session's life (0: none).
	RatePerMinute int `json:"rate_per_minute,omitempty"`
	Burst         int `json:"burst,omitempty"`
	Quota         int `json:"quota,omitempty"`
}

// MaxLimit bounds a binding's limits (broker.MaxLimit).
const MaxLimit = 1_000_000

// Readable is a secret the operator explicitly allowed the agent to read (--allow-readable):
// sandboxd resolves Ref from the broker store into EnvVar at start. The value is never in the spec.
type Readable struct {
	Ref    string `json:"ref"`
	EnvVar string `json:"env_var"`
}

// Dependency is a dependency microVM (design 5.5.3), built additive-from-empty: it has no mounts
// (there is no field for them), its own egress and bindings, and a non-root user.
type Dependency struct {
	Name      string    `json:"name"`
	Image     string    `json:"image"`
	Command   []string  `json:"command,omitempty"`
	Port      int       `json:"port"`
	RunAsUser int       `json:"run_as_user"`
	Env       []EnvVar  `json:"env,omitempty"`
	Egress    Egress    `json:"egress"`
	Bindings  []Binding `json:"bindings,omitempty"`
	Resources Resources `json:"resources"`
}

// Decode reads one spec strictly: unknown fields, trailing data, and a different version are
// refused. It does not validate; call Validate.
func Decode(r io.Reader) (*Spec, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("session spec: %w", err)
	}
	if dec.More() {
		return nil, errors.New("session spec: trailing data")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("session spec: trailing data")
	}
	if s.Version != Version {
		return nil, fmt.Errorf("session spec: version %d, want %d", s.Version, Version)
	}
	return &s, nil
}

// Encode writes the spec as JSON.
func (s *Spec) Encode() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var (
	idRE          = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	envNameRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	imageRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	placeholderRE = regexp.MustCompile(`^sbxph_[A-Za-z0-9_-]{43}$`)
	refRE         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	workspaceRE   = regexp.MustCompile(`^` + WorkspaceStore + `/[0-9a-f]{16}(/.*)?$`)
	labelRE       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// PlaceholderPattern is the form of a broker placeholder: "sbxph_" and 32 random bytes in
// unpadded base64url. It names nothing and is worthless off the session's broker.
const PlaceholderPattern = `^sbxph_[A-Za-z0-9_-]{43}$`

// IsPlaceholder reports whether v is a broker placeholder.
func IsPlaceholder(v string) bool { return placeholderRE.MatchString(v) }

// credentialPrefixes are well-known credential formats; an env value that starts with one is a
// credential in plain sight, whatever its name.
var credentialPrefixes = []string{
	"sk-", "sk_live_", "rk_live_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
	"xoxb-", "xoxp-", "xoxa-", "xoxs-", "AKIA", "ASIA", "AIza", "ya29.", "npm_", "pypi-",
	"-----BEGIN", "eyJ", // a PEM block, a JWT
}

// LooksLikeCredential reports whether v has a well-known credential format.
func LooksLikeCredential(v string) bool {
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(v, p) && len(v) >= len(p)+12 {
			return true
		}
	}
	return false
}

// Options tune Validate.
type Options struct {
	MaxDependencies int // 0 means DefaultMaxDependencies
}

// Validate is sandboxd's structural check (design 5.4.2): it refuses what no valid session can
// ask for, whatever the policy layer decided. It returns every problem it finds.
func (s *Spec) Validate(o Options) error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if s.Version != Version {
		bad("version %d, want %d", s.Version, Version)
	}
	if !idRE.MatchString(s.ID) {
		bad("invalid session id %q", s.ID)
	}
	if !idRE.MatchString(s.Name) {
		bad("invalid session name %q", s.Name)
	}
	if !labelRE.MatchString(s.Agent) {
		bad("invalid agent %q", s.Agent)
	}
	if s.Tier < 1 || s.Tier > 3 {
		bad("invalid tier %d", s.Tier)
	}
	if !imageRE.MatchString(s.Image) {
		bad("image %q is not pinned by digest", s.Image)
	}
	checkCommand(s.Command, "command", bad)
	checkResources(s.Resources, "resources", bad)
	checkMounts(s, bad)
	bound := checkBindings(s.Bindings, "bindings", bad)
	checkBindingReach(s.Bindings, s.Egress, "bindings", bad)
	checkEnv(s.Env, bound, "env", bad)
	readable := map[string]bool{}
	for _, r := range s.Readable {
		if !refRE.MatchString(r.Ref) || !envNameRE.MatchString(r.EnvVar) {
			bad("readable secret %q: invalid reference or variable", r.Ref)
		}
		if readable[r.EnvVar] || bound[r.EnvVar] != "" || hasEnv(s.Env, r.EnvVar) {
			bad("readable secret %q: variable %s is set twice", r.Ref, r.EnvVar)
		}
		readable[r.EnvVar] = true
	}
	checkEgress(s.Egress, "egress", bad)
	max := o.MaxDependencies
	if max == 0 {
		max = DefaultMaxDependencies
	}
	if len(s.Dependencies) > max {
		bad("%d dependencies, more than the limit of %d", len(s.Dependencies), max)
	}
	names := map[string]bool{}
	// the agent reaches each dependency on its own port of the gateway's address (5.8.6), so the
	// ports must not collide with each other or with the gateway's own
	usedPorts := map[int]string{53: "DNS", 443: "egress"}
	for _, p := range s.Egress.ExtraPorts {
		usedPorts[p] = "a declared egress port"
	}
	for i, d := range s.Dependencies {
		if other, ok := usedPorts[d.Port]; ok && d.Port > 0 {
			bad("dependency %d (%s): port %d is already used by %s", i, d.Name, d.Port, other)
		} else if d.Port > 0 {
			usedPorts[d.Port] = "dependency " + d.Name
		}
		w := fmt.Sprintf("dependency %d (%s)", i, d.Name)
		if !labelRE.MatchString(d.Name) || names[d.Name] {
			bad("%s: invalid or repeated name", w)
		}
		names[d.Name] = true
		if !imageRE.MatchString(d.Image) {
			bad("%s: image %q is not pinned by digest", w, d.Image)
		}
		if d.Port < 1 || d.Port > 65535 {
			bad("%s: invalid port %d", w, d.Port)
		}
		if d.RunAsUser <= 0 {
			bad("%s: must run as a non-root user", w)
		}
		checkCommand(d.Command, w+" command", bad)
		checkResources(d.Resources, w+" resources", bad)
		dbound := checkBindings(d.Bindings, w+" bindings", bad)
		checkBindingReach(d.Bindings, d.Egress, w+" bindings", bad)
		checkEnv(d.Env, dbound, w+" env", bad)
		checkEgress(d.Egress, w+" egress", bad)
	}
	for k, v := range s.Audit {
		if !envNameRE.MatchString(k) || len(v) > 4096 || LooksLikeCredential(v) {
			bad("invalid audit entry %q", k)
		}
	}
	return errors.Join(errs...)
}

func hasEnv(env []EnvVar, name string) bool {
	for _, e := range env {
		if e.Name == name {
			return true
		}
	}
	return false
}

func checkCommand(c []string, what string, bad func(string, ...any)) {
	for _, a := range c {
		if strings.ContainsRune(a, 0) {
			bad("%s: an argument holds a NUL", what)
		}
	}
}

func checkResources(r Resources, what string, bad func(string, ...any)) {
	if !(r.CPUs > 0 && r.CPUs <= 64) {
		bad("%s: invalid CPUs %v", what, r.CPUs)
	}
	if r.MemoryMiB < 256 || r.MemoryMiB > 1<<20 {
		bad("%s: invalid memory %d MiB", what, r.MemoryMiB)
	}
	if r.EphemeralGiB < 0 || r.EphemeralGiB > 1024 {
		bad("%s: invalid ephemeral storage %d GiB", what, r.EphemeralGiB)
	}
}

// cleanAbs reports whether p is a clean absolute path.
func cleanAbs(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\n")
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

func checkMounts(s *Spec, bad func(string, ...any)) {
	sessionDir := path.Join(SessionStore, s.ID)
	var workspaces []string
	for _, m := range s.Mounts {
		if m.Kind == Workspace && cleanAbs(m.Target) {
			workspaces = append(workspaces, m.Target)
		}
	}
	inWorkspace := func(t string) bool {
		for _, w := range workspaces {
			if under(t, w) && t != w {
				return true
			}
		}
		return false
	}
	targets := map[string]bool{}
	for i, m := range s.Mounts {
		w := fmt.Sprintf("mount %d (%s %s)", i, m.Kind, m.Target)
		if !cleanAbs(m.Target) || m.Target == "/" {
			bad("%s: target must be a clean absolute path below /", w)
			continue
		}
		for _, sys := range []string{"/proc", "/sys", "/dev", "/run/sandbox"} {
			if under(m.Target, sys) {
				bad("%s: target is a system path", w)
			}
		}
		if targets[m.Target] {
			bad("%s: target mounted twice", w)
		}
		targets[m.Target] = true
		switch m.Kind {
		case Workspace:
			if !workspaceRE.MatchString(m.Source) || !cleanAbs(m.Source) {
				bad("%s: source must be a workspace copy under %s", w, WorkspaceStore)
			}
		case ReadOnly:
			if !workspaceRE.MatchString(m.Source) || !cleanAbs(m.Source) {
				bad("%s: source must be in a workspace copy", w)
			}
			if !m.ReadOnly {
				bad("%s: must be read-only", w)
			}
			if !inWorkspace(m.Target) {
				bad("%s: target must be inside a workspace mount", w)
			}
		case MaskFile, MaskDir:
			if m.Source != "" {
				bad("%s: a mask has no source", w)
			}
			if !inWorkspace(m.Target) {
				bad("%s: target must be inside a workspace mount", w)
			}
		case History, AgentConfig, CABundle, MCPConfig, Kubeconfig:
			if !cleanAbs(m.Source) || !under(m.Source, sessionDir) || m.Source == sessionDir {
				bad("%s: source must be in this session's directory %s", w, sessionDir)
			}
			if (m.Kind == CABundle || m.Kind == Kubeconfig) && !m.ReadOnly {
				bad("%s: must be read-only", w)
			}
		default:
			bad("%s: unknown mount kind", w)
		}
	}
}

var injectRE = regexp.MustCompile(`^(bearer|basic|header:[A-Za-z0-9-]{1,64}|query:[A-Za-z0-9_.-]{1,64})$`)

// l7Reachable reports whether an L7 rule's host is one the egress allowlist allows: an exact name
// as the gateway decides it, a wildcard only when the allowlist has that wildcard itself.
func l7Reachable(host string, e Egress) bool {
	h := egressmatch.Normalize(host)
	if strings.HasPrefix(h, "*.") {
		for _, a := range e.Allow {
			if egressmatch.Normalize(a) == h {
				return true
			}
		}
		return false
	}
	return egressmatch.Decide(h, e.Allow, e.BlockDomains)
}

// checkBindingReach refuses a binding whose destination the egress allowlist does not allow: the
// gateway intercepts every binding destination, and could not reach it.
func checkBindingReach(bs []Binding, e Egress, what string, bad func(string, ...any)) {
	for _, b := range bs {
		for _, h := range b.Hosts {
			if validHost(h) && !strings.Contains(h, "*") && !l7Reachable(h, e) {
				bad("%s (%s): destination %q is not on the allowlist", what, b.Ref, h)
			}
		}
	}
}

// checkBindings returns the env variables that carry a placeholder, with the placeholder each
// must hold.
func checkBindings(bs []Binding, what string, bad func(string, ...any)) map[string]string {
	vars := map[string]string{}
	seen := map[string]bool{}
	limits := map[string][3]int{}
	for i, b := range bs {
		w := fmt.Sprintf("%s %d (%s)", what, i, b.Ref)
		l := [3]int{b.RatePerMinute, b.Burst, b.Quota}
		for _, v := range l {
			if v < 0 || v > MaxLimit {
				bad("%s: a limit must be between 0 and %d", w, MaxLimit)
			}
		}
		if prev, ok := limits[b.Ref]; ok && prev != l {
			bad("%s: every binding of a credential must state the same limits", w)
		}
		limits[b.Ref] = l
		if !refRE.MatchString(b.Ref) {
			bad("%s: invalid credential reference", w)
		}
		if len(b.Hosts) == 0 {
			bad("%s: a binding must name its destinations", w)
		}
		for _, h := range b.Hosts {
			if strings.Contains(h, "*") || !validHost(h) {
				bad("%s: destination %q must be one exact host (no wildcards)", w, h)
			}
		}
		if !injectRE.MatchString(b.Inject) {
			bad("%s: invalid injection %q", w, b.Inject)
		}
		if !IsPlaceholder(b.Placeholder) {
			bad("%s: invalid placeholder", w)
		}
		if seen[b.Placeholder] {
			bad("%s: placeholder reused", w)
		}
		seen[b.Placeholder] = true
		if b.EnvVar != "" {
			if !envNameRE.MatchString(b.EnvVar) || vars[b.EnvVar] != "" {
				bad("%s: invalid or repeated variable %q", w, b.EnvVar)
			}
			vars[b.EnvVar] = b.Placeholder
		}
	}
	return vars
}

func checkEnv(env []EnvVar, bound map[string]string, what string, bad func(string, ...any)) {
	seen := map[string]bool{}
	for _, e := range env {
		if !envNameRE.MatchString(e.Name) || seen[e.Name] {
			bad("%s: invalid or repeated variable %q", what, e.Name)
			continue
		}
		seen[e.Name] = true
		if strings.ContainsRune(e.Value, 0) || len(e.Value) > 32768 {
			bad("%s: %s: invalid value", what, e.Name)
		}
		if ph, ok := bound[e.Name]; ok && e.Value != ph {
			bad("%s: %s carries a credential and must hold its binding's placeholder", what, e.Name)
		}
		if LooksLikeCredential(e.Value) {
			bad("%s: %s holds what looks like a credential value", what, e.Name)
		}
	}
	for v := range bound {
		if !seen[v] {
			bad("%s: binding variable %s is not set", what, v)
		}
	}
}

// validBlockPattern is one of egressmatch.Blocked's forms: "*.x", "*suffix", "prefix.*", or a name.
func validBlockPattern(p string) bool {
	if p != egressmatch.Normalize(p) || strings.ContainsAny(p, " \t\x00") {
		return false
	}
	switch {
	case strings.HasPrefix(p, "*."):
		return validHost(p[2:])
	case strings.HasPrefix(p, "*"):
		return len(p) > 1 && !strings.Contains(p[1:], "*")
	case strings.HasSuffix(p, ".*"):
		return len(p) > 2 && !strings.Contains(p[:len(p)-2], "*")
	}
	return validHost(p)
}

// validHost is a DNS name (letters, digits, hyphens, dots; no trailing dot), lower case.
func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 || h != strings.ToLower(h) {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	return true
}

func checkEgress(e Egress, what string, bad func(string, ...any)) {
	for _, a := range e.Allow {
		h := strings.TrimPrefix(strings.TrimPrefix(a, "**."), "*.")
		if !validHost(h) || strings.Contains(h, "*") || !strings.Contains(h, ".") {
			bad("%s: invalid allowlist entry %q", what, a)
		}
	}
	for _, d := range e.BlockDomains {
		if !validBlockPattern(d) {
			bad("%s: invalid blocked domain %q", what, d)
		}
	}
	for _, c := range e.BlockCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			bad("%s: invalid blocked CIDR %q", what, c)
		}
	}
	for _, r := range e.L7 {
		// a rule's host is intercepted, and a leaf certificate covers an exact name or one label
		// under a wildcard, so "**." cannot carry rules; the host must be one the allowlist allows
		h := strings.TrimPrefix(r.Host, "*.")
		if r.Host != l7.AnyHost && (!validHost(h) || strings.Contains(h, "*")) {
			bad("%s: invalid L7 host %q (an exact name or *.domain)", what, r.Host)
		} else if r.Host != l7.AnyHost && !l7Reachable(r.Host, e) {
			bad("%s: L7 host %q is not on the allowlist", what, r.Host)
		}
		if err := r.Validate(); err != nil {
			bad("%s: %v", what, err)
		}
	}
	for _, h := range e.HostEndpoints {
		a, err := netip.ParseAddr(h.Address)
		if err != nil || h.Port < 1 || h.Port > 65535 {
			bad("%s: invalid host endpoint %s:%d", what, h.Address, h.Port)
			continue
		}
		if a.IsUnspecified() || a.IsMulticast() {
			bad("%s: host endpoint %s is not a single host", what, h.Address)
		}
	}
	for _, p := range e.ExtraPorts {
		if p < 1 || p > 65535 {
			bad("%s: invalid extra port %d", what, p)
		}
	}
}
