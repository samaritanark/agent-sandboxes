package cli

import (
	"io"

	"github.com/samaritanark/agent-sandboxes/go/internal/secretcmd"
)

// cmdSecret is cmd_secret. In v3 the store stays on the host and the host binary runs the command
// itself (package secretcmd, which it shares); the in-VM CLI keeps it for the differential tests.
func cmdSecret(c *cmdCtx, args []string) {
	var stdin io.Reader
	if c.stdin != nil {
		stdin = c.stdin
	}
	rc := secretcmd.Run(args, secretcmd.Env{Dir: c.env.SecretsDir, Home: c.env.Home, Root: c.env.Root, Stdin: stdin,
		StdinTTY: c.env.StdinTTY, StderrTTY: c.env.StderrTTY, NoColor: c.env.NoColor, Getenv: c.env.Getenv,
		Location: c.env.Location}, c.stdout, c.stderr)
	if rc != 0 {
		panic(exit(rc))
	}
}
