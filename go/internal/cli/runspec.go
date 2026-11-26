package cli

// The session spec `sandbox run` hands sandboxd (design 5.4.2): v2's pod manifest, network policy,
// and dependency pods, as one document. Building it is policy, so it happens here in the VM;
// sandboxd checks its structure again and builds the session from it.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/allowlist"
	"github.com/samaritanark/agent-sandboxes/go/internal/catalogue"
	"github.com/samaritanark/agent-sandboxes/go/internal/mounts"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
)

// The agent microVM's limits: v2's pod limits (lib/resources.sh).
const (
	agentCPUs         = 4
	agentMemoryMiB    = 6 << 10
	agentEphemeralGiB = 20
)

// The dependency defaults (lib/catalogue.sh) and v2's dependency user (lib/dependency.sh).
const (
	depDefaultCPU       = "1"
	depDefaultMem       = "512Mi"
	depDefaultEphemeral = "1Gi"
	depDefaultUser      = 1000
)

// AgentHome is the agent's home in its microVM, as in v2's pod.
const AgentHome = "/home/agent"

// SpecInputs is what a spec needs beyond run's decisions and its session record: the agent image
// pinned by digest, and the VM copy of each repository (the sync engine's, under
// sessionspec.WorkspaceStore).
type SpecInputs struct {
	Image         string
	WorkspaceCopy func(repo string) (string, error)
}

var (
	cpuQty = regexp.MustCompile(`^([0-9]+)(m?)$`)
	memQty = regexp.MustCompile(`^([0-9]+)(Mi|Gi)$`)
)

// cpus reads a Kubernetes CPU quantity ("1", "250m").
func cpus(q string) (float64, error) {
	m := cpuQty.FindStringSubmatch(q)
	if m == nil {
		return 0, fmt.Errorf("CPU %q is not a whole number of CPUs or of millicpus", q)
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "m" {
		return float64(n) / 1000, nil
	}
	return float64(n), nil
}

// mebibytes reads a Kubernetes memory quantity in Mi or Gi.
func mebibytes(q string) (int, error) {
	m := memQty.FindStringSubmatch(q)
	if m == nil {
		return 0, fmt.Errorf("size %q is not a whole number of Mi or Gi", q)
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "Gi" {
		n <<= 10
	}
	return n, nil
}

// specName is the spec's name: v2's pod name (already a DNS label), at most 63 bytes. The
// session's own name, which may hold any character, goes to the audit record.
func specName(pod string) string {
	if len(pod) > 63 {
		pod = strings.TrimRight(pod[:63], "-")
	}
	return pod
}

// buildSpec is the session spec for run's decisions s and record rec. Secrets are not bound yet
// (the binding source is the owner's open question 3), so the spec carries no bindings; run says
// which secrets it withheld.
func (c *cmdCtx) buildSpec(s LaunchSpec, rec SessionRecord, in SpecInputs) (*sessionspec.Spec, error) {
	tierN, err := strconv.Atoi(s.Tier)
	if err != nil {
		return nil, fmt.Errorf("tier %q", s.Tier)
	}
	spec := &sessionspec.Spec{Version: sessionspec.Version, ID: rec.ID, Name: specName(rec.PodName), Agent: s.Agent, Tier: tierN,
		Image: in.Image, Command: []string{"sleep", "infinity"},
		Resources: sessionspec.Resources{CPUs: agentCPUs, MemoryMiB: agentMemoryMiB, EphemeralGiB: agentEphemeralGiB},
		Bindings:  []sessionspec.Binding{}, KeepAlive: s.KeepAlive,
		Audit: map[string]string{"name": s.Name}}
	if s.Profile != "" {
		spec.Audit["profile"] = s.Profile
	}

	// the workspace copies, then each one's masks and read-only exec vectors, at v2's paths
	for i, repo := range s.Repos {
		copyDir, err := in.WorkspaceCopy(repo)
		if err != nil {
			return nil, err
		}
		target := mounts.MountPath(repo, len(s.Repos))
		spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.Workspace, Source: copyDir, Target: target})
		for _, m := range append(mounts.Masks(i, copyDir), mounts.Readonly(i, copyDir)...) {
			t := target + "/" + m.Rel
			switch m.Kind {
			case mounts.MaskFile:
				spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.MaskFile, Target: t})
			case mounts.MaskDir:
				spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.MaskDir, Target: t})
			default:
				spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.ReadOnly, Source: copyDir + "/" + m.Rel, Target: t, ReadOnly: true})
			}
		}
	}

	// v2's container environment (lib/manifest.sh build_env_block)
	spec.Env = []sessionspec.EnvVar{{Name: "HOME", Value: AgentHome}, {Name: "TERM", Value: "xterm-256color"},
		{Name: "COLORTERM", Value: "truecolor"}}
	if s.Agent == "claude" {
		spec.Env = append(spec.Env, sessionspec.EnvVar{Name: "CLAUDE_CONFIG_DIR", Value: AgentHome + "/.claude"})
	}

	// egress: the allowlist v2 rendered into the session's network policy, the merged block lists
	chk := c.checks()
	ad, _ := agents.Domains(s.Agent, s.BaseURL)
	spec.Egress = sessionspec.Egress{Allow: allowlist.Build(chk, ad, tier.Domains(s.Tier), rec.Policy.Extras),
		BlockDomains: chk.BlockedDomains(), BlockCIDRs: chk.BlockedCIDRs()}

	for _, d := range rec.Dependencies {
		dep, err := c.specDependency(d)
		if err != nil {
			return nil, err
		}
		spec.Dependencies = append(spec.Dependencies, dep)
	}
	return spec, nil
}

// specDependency is a profile dependency's microVM, from its catalogue entry.
func (c *cmdCtx) specDependency(d Dependency) (sessionspec.Dependency, error) {
	f := func(k, def string) string { return catalogue.Field(d.Path, k, def) }
	port, err := strconv.Atoi(d.Port)
	if err != nil {
		return sessionspec.Dependency{}, fmt.Errorf("dependency %s: port %q", d.Name, d.Port)
	}
	uid := depDefaultUser
	if u := f("run_as_user", ""); u != "" {
		if uid, err = strconv.Atoi(u); err != nil {
			return sessionspec.Dependency{}, fmt.Errorf("dependency %s: run_as_user %q", d.Name, u)
		}
	}
	cpu, err := cpus(f("cpu_limit", depDefaultCPU))
	if err != nil {
		return sessionspec.Dependency{}, fmt.Errorf("dependency %s: %w", d.Name, err)
	}
	mem, err := mebibytes(f("mem_limit", depDefaultMem))
	if err != nil {
		return sessionspec.Dependency{}, fmt.Errorf("dependency %s: %w", d.Name, err)
	}
	eph, err := mebibytes(f("ephemeral_limit", depDefaultEphemeral))
	if err != nil {
		return sessionspec.Dependency{}, fmt.Errorf("dependency %s: %w", d.Name, err)
	}
	var allow []string
	for _, e := range catalogue.List(d.Path, "egress") {
		if strings.TrimSpace(e) != "" {
			allow = append(allow, e)
		}
	}
	chk := c.checks()
	return sessionspec.Dependency{Name: d.Name, Image: f("image", ""), Port: port, RunAsUser: uid,
		Resources: sessionspec.Resources{CPUs: cpu, MemoryMiB: mem, EphemeralGiB: (eph + 1023) >> 10},
		Egress:    sessionspec.Egress{Allow: allow, BlockDomains: chk.BlockedDomains(), BlockCIDRs: chk.BlockedCIDRs()}}, nil
}
