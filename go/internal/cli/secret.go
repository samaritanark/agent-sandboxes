package cli

import (
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/secrets"
)

// cmdSecret is cmd_secret: the host-side secret store (set, list, delete). In v3 the store stays
// on the host and the host binary pushes only a session's bound secrets (design 5.1.4); the
// command is ported here with the rest of the CLI and moves with the host binary.
func cmdSecret(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_secret")
	}
	st := secrets.Store{Dir: c.env.SecretsDir}
	sub, args := args[0], args[1:]
	switch sub {
	case "--help", "-h", "help":
		c.usage("usage_secret")
	case "set":
		var name, fromFile, fromEnv string
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--from-file":
				if i+1 >= len(args) || args[i+1] == "" {
					c.missingArg("2", "--from-file requires a path")
				}
				fromFile = args[i+1]
				i++
			case strings.HasPrefix(a, "--from-file="):
				fromFile = a[len("--from-file="):]
			case a == "--from-env":
				fromEnv = "_USE_DEFAULT"
			case strings.HasPrefix(a, "--from-env="):
				fromEnv = a[len("--from-env="):]
			case a == "--help" || a == "-h":
				c.usage("usage_secret")
			case strings.HasPrefix(a, "-"):
				c.die("Unknown option for 'secret set': %s", a)
			default:
				if name != "" {
					c.die("Unexpected extra argument: %s", a)
				}
				name = a
			}
		}
		if name == "" {
			c.die("Usage: sandbox secret set <NAME> [--from-file PATH | --from-env[=VAR]]")
		}
		if err := secrets.ValidateName(name); err != nil {
			c.fail(err)
		}
		if fromFile != "" && fromEnv != "" {
			c.die("secret set: --from-file and --from-env are mutually exclusive.")
		}
		switch {
		case fromFile != "":
			src := fromFile
			if strings.HasPrefix(src, "~") {
				src = c.env.Home + src[1:]
			}
			if err := st.SetFromFile(name, src); err != nil {
				c.fail(err)
			}
			c.out("Stored secret '%s' from %s.", name, fromFile)
		case fromEnv != "":
			if fromEnv == "_USE_DEFAULT" {
				fromEnv = name
			}
			if !envName.MatchString(fromEnv) {
				if deviation.Fixed(deviation.FromEnvNameChecked) {
					c.die("--from-env: '%s' is not an environment variable name.", fromEnv)
				}
				c.errOut("%s/lib/secrets.sh: line 116: %s: invalid variable name", c.env.Root, fromEnv)
				panic(exit(1))
			}
			if err := st.SetFromEnv(name, fromEnv, c.getenv); err != nil {
				c.fail(err)
			}
			c.out("Stored secret '%s' from $%s.", name, fromEnv)
		default:
			if c.env.StdinTTY {
				c.errOut("Reading secret value from stdin. End with EOF (Ctrl-D).")
			}
			if err := st.SetFromReader(name, c.stdin); err != nil {
				c.fail(err)
			}
			c.out("Stored secret '%s'.", name)
		}
	case "list":
		loc := c.env.Location
		if loc == nil {
			loc = time.Local
		}
		rows := st.List(loc)
		for i, r := range rows {
			if i == 0 {
				c.out("%-32s  %12s  %s", "NAME", "SIZE", "UPDATED")
			}
			c.out("%s", r)
		}
		if len(rows) == 0 {
			c.out("No secrets in %s/.", c.tilde(c.env.SecretsDir))
			c.out("Add one with: sandbox secret set <NAME>")
		}
	case "delete", "rm", "remove":
		if len(args) < 1 {
			c.die("Usage: sandbox secret delete <NAME>")
		}
		name := args[0]
		if err := secrets.ValidateName(name); err != nil {
			c.fail(err)
		}
		if st.Exists(name) {
			if err := st.Delete(name); err != nil {
				c.fail(err)
			}
			c.out("Deleted secret '%s'.", name)
		} else {
			c.errOut("Secret '%s' is not in the store; nothing to delete.", name)
		}
	default:
		c.die("Unknown 'secret' subcommand: %s. Run 'sandbox secret --help'.", sub)
	}
}
