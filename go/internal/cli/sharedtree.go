package cli

import (
	"path/filepath"
	"slices"

	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
)

// Shared working trees across sessions (design 5.13, OQ-06; owner decision 2026-11-27). Sessions
// on one repository share its VM copy, so what one agent writes the other reads. Launching a
// session that shares a repository with a running session of a different tier or allowlist warns
// and records an audit event; an overlay's `shared_tree_policy: deny` refuses it instead.

// sharedTree is one running session the launch would share a repository with.
type sharedTree struct {
	ID, Repo, Tier string
	Allowlist      bool // the allowlists differ (the tiers may too)
}

// sharedTrees lists the running sessions that share a repository with the session being launched
// (its record already written) at a different tier or with a different allowlist.
func (c *cmdCtx) sharedTrees(s LaunchSpec, rec SessionRecord) []sharedTree {
	if len(s.Repos) == 0 || c.env.Launch.Sessions == nil {
		return nil
	}
	running, err := c.env.Launch.Sessions.List()
	if err != nil {
		c.warn("cannot list the running sessions to check for shared repositories: %v", err)
		return nil
	}
	own, ok := sessionRecord(filepath.Join(rec.LogDir, "session.json"))
	if !ok {
		return nil
	}
	ownDomains := sortedLines(own.Get("allowed_domains"))
	var out []sharedTree
	for _, st := range running {
		if st.ID == rec.ID || !resumeSessionIDRE.MatchString(st.ID) {
			continue
		}
		other, ok := sessionRecord(filepath.Join(c.env.LogsDir, st.ID, "session.json"))
		if !ok {
			continue
		}
		tier := jqRawField(other, "tier", "")
		domains := sortedLines(other.Get("allowed_domains"))
		diffAllow := !slices.Equal(domains, ownDomains)
		if tier == s.Tier && !diffAllow {
			continue
		}
		for _, r := range jqLines(other.Get("repos")) {
			if slices.Contains(s.Repos, r) {
				out = append(out, sharedTree{ID: st.ID, Repo: r, Tier: tier, Allowlist: diffAllow})
			}
		}
	}
	return out
}

// sortedLines is a JSON array's strings, sorted.
func sortedLines(v jqjson.Value) []string {
	l := jqLines(v)
	slices.Sort(l)
	return l
}

// checkSharedTrees warns about (or, under the overlay's deny policy, refuses) each shared tree.
func (c *cmdCtx) checkSharedTrees(s LaunchSpec, rec SessionRecord) {
	shared := c.sharedTrees(s, rec)
	if len(shared) == 0 {
		return
	}
	deny := false
	if ov := config.ResolveOverlayPath(c.env.Env); ov != "" {
		deny = config.ExtractYAMLScalar(ov+"/config.yaml", "shared_tree_policy") == "deny"
	}
	for _, t := range shared {
		what := "tier " + t.Tier
		if t.Allowlist {
			what += ", a different allowlist"
		}
		msg := "Shares " + t.Repo + " with running session " + t.ID + " (" + what + ")"
		audit.LogEvent(rec.LogDir, "shared-tree", msg, c.stamp())
		if deny {
			c.errOut("ERROR: %s is open in running session %s (%s), and the overlay sets shared_tree_policy: deny.", c.tilde(t.Repo), t.ID, what)
			continue
		}
		c.warn("%s is also open in running session %s (%s). Sessions on one repository share its working tree: what one agent writes, the other reads.", c.tilde(t.Repo), t.ID, what)
	}
	if deny {
		c.die("Stop the other session first, or launch with the same tier and allowlist.")
	}
}
