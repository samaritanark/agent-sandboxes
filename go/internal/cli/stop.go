package cli

// `sandbox stop` (v2's cmd_stop) on sandboxd: the session's microVMs, network, gateway, and bound
// credentials go in one call (sandboxd's teardown, design 5.4.3), then the record is closed as v2
// closed it. v2's Kubernetes Secret deletes, Hubble export, and transcript copy have no
// counterpart: sandboxd's audit log holds the flows, and the broker's values go with the gateway.

import (
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/workspace"
)

// cmdStop is cmd_stop.
func cmdStop(c *cmdCtx, args []string) {
	if len(args) == 0 || args[0] == "" {
		c.missingArg("1", "Usage: sandbox stop <SESSION_ID>")
	}
	if c.env.Launch.Sessions == nil {
		c.die("'stop' is not yet available in the Go port of the sandbox CLI: the session runtime (sandboxd) does not exist yet.")
	}
	c.stopSession(args[0])
}

// stopSession is cmd_stop's body, which run's own teardown also uses.
func (c *cmdCtx) stopSession(id string) {
	logDir := c.env.LogsDir + "/" + id
	sj := logDir + "/session.json"
	pod := jqAlt(sj, "pod_name", "")
	if pod == "" {
		pod = "sandbox-" + id
	}
	c.out("==> Stopping session: %s", id)
	tierV, hadToken, hadKubeconfig := "1", false, false
	var repos []string
	if config.IsFile(sj) {
		rec, _ := sessionRecord(sj)
		tierV = jqRawField(rec, "tier", "1")
		hadToken = jqRawField(rec, "infra_token", "false") == "true"
		hadKubeconfig = jqRawField(rec, "infra_kubeconfig", "false") == "true"
		for _, r := range jqLines(rec.Get("repos")) {
			if r != "" {
				repos = append(repos, r)
			}
		}
	}

	endReason, endDetail := "", ""
	s := c.env.Launch.Sessions
	live, err := s.Live(id)
	switch {
	case err != nil:
		c.warn("Cannot ask sandboxd about session %s: %v", id, err)
		endReason, endDetail = "teardown-incomplete", firstErrLine(err)
	case !live:
		c.warn("Pod %s not found (already stopped).", pod)
	default:
		if err := s.Stop(id, "operator stop"); err != nil {
			c.warn("Session teardown FAILED — containment may be INCOMPLETE; its microVM could still be running. Investigate before trusting this session as stopped. sandboxd: %s", firstErrLine(err))
			endReason, endDetail = "teardown-incomplete", "sandboxd stop failed: "+firstErrLine(err)
		} else {
			c.out("  Pod deleted.")
		}
	}
	if hadToken {
		c.warn("REMINDER: Revoke infra token used in this session.")
	}
	if hadKubeconfig {
		c.warn("REMINDER: kubeconfig credentials used in this session may still be")
		c.warn("         valid on the target cluster. Rotate or let them expire.")
	}
	if tierAtLeast(tierV, "2") && len(repos) > 0 {
		c.out("==> Capturing workspace diff...")
		for _, l := range workspace.CaptureDiff(logDir, repos, workspace.PruneDirs(c.env.SandboxRoot)) {
			c.out("%s", l)
		}
	}
	if isDir(logDir) {
		end := c.stamp()
		audit.UpdateEndTime(logDir, end)
		audit.RecordEndReason(logDir, endReason, endDetail)
		audit.RecordDependenciesDown(logDir, end)
	}
	c.out("")
	c.out("Session %s stopped.", id)
	c.out("Logs: %s", logDir)
}

func firstErrLine(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
