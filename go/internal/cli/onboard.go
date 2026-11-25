package cli

import (
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/onboard"
)

// cmdOnboard is cmd_onboard: stage each agent's host login state into the agent home and write
// the starter user config. In v3 the destination is the credential broker's store (design
// 5.9.6); the command's flow and checks carry over.
func cmdOnboard(c *cmdCtx, args []string) {
	agent := "all"
	var dry, force, skipConfig bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_onboard")
		case a == "--agent":
			agent = c.needValue(args, i, "--agent")
			i++
		case strings.HasPrefix(a, "--agent="):
			agent = a[len("--agent="):]
		case a == "--dry-run":
			dry = true
		case a == "--force":
			force = true
		case a == "--skip-config":
			skipConfig = true
		default:
			c.die("Unknown option: %s. Run 'sandbox onboard --help' for usage.", a)
		}
	}
	switch agent {
	case "claude", "codex", "opencode", "copilot", "grok", "all":
	default:
		c.die("--agent must be one of: claude, codex, opencode, copilot, grok, all")
	}
	if dry {
		c.out("==> sandbox onboard (dry-run)")
	} else {
		c.out("==> sandbox onboard")
	}
	c.out("")
	warns, n := onboard.WarnForbiddenEnv(c.getenv)
	for _, w := range warns {
		c.errOut("%s", w)
	}
	if n > 0 {
		c.out("")
	}
	c.out("==> Staging agent credentials")
	list := []string{agent}
	if agent == "all" {
		list = []string{"claude", "codex", "opencode", "copilot", "grok"}
	}
	oc := onboard.Ctx{Home: c.env.Home, AgentHomeBase: c.env.Home + "/.sandbox/agent-home", DryRun: dry, Force: force}
	emit := func(o onboard.Out) {
		for _, l := range o.Stderr {
			c.errOut("%s", l)
		}
		for _, l := range o.Stdout {
			c.out("%s", l)
		}
	}
	for _, a := range list {
		o, _ := oc.Agent(a)
		emit(o)
	}
	if !skipConfig {
		c.out("")
		c.out("==> Starter user config")
		var o onboard.Out
		oc.WriteStarterUserConfig(&o)
		emit(o)
	}
	c.out("")
	if dry {
		c.out("Dry-run complete; nothing was written.")
	} else {
		c.out("Onboard complete. Run 'sandbox run --agent <name>' to launch a session.")
	}
}
