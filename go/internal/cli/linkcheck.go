package cli

// The VM's half of `sandbox link` (design 5.1.3: the host clones and fetches with the operator's
// git credentials, validates nothing, and pushes the tree; the VM validates shape and pins). The
// host pushes the clone as the operator state's local overlay and asks for its verdict.

import (
	"fmt"
	"io"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// LinkCheck exit statuses besides 0 (valid) and 1 (failed validation).
const LinkCheckNeedsVersion = 3 // the overlay needs a newer sandbox; the version is on stdout

// LinkCheck is `sandbox __link-check DIR`: the overlay shape check and its minimum version, with
// their messages on stderr.
func LinkCheck(args []string, env Env, stdout, stderr io.Writer) int {
	return runCtx(env, stdout, stderr, func(c *cmdCtx) {
		if len(args) != 1 {
			c.die("usage: __link-check DIR")
		}
		if !isDir(args[0]) {
			c.die("the overlay's tree did not reach the sandbox VM (%s)", args[0])
		}
		v := c.link().ValidateShape(args[0])
		for _, s := range v.Stderr {
			fmt.Fprintln(c.stderr, s)
		}
		if !v.OK {
			panic(exit(1))
		}
		unmet, warns := config.OverlayMinVersionUnmet(args[0], c.env.Version.Version)
		for _, w := range warns {
			c.warn("%s", w)
		}
		if unmet != "" {
			fmt.Fprintln(c.stdout, unmet)
			panic(exit(LinkCheckNeedsVersion))
		}
	})
}
