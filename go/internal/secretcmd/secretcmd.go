// Package secretcmd is `sandbox secret` (v2's cmd_secret): set, list, and delete the operator's
// secrets in the host-side store, with v2's flags, messages, and exit codes. In v3 the store stays
// on the host (design 5.1.4), so the host binary runs this itself; the in-VM CLI keeps it for the
// differential tests against the bash. It uses only the store and the named fixes, so it is
// host-safe.
package secretcmd

import (
	_ "embed"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/secrets"
)

//go:embed usage_secret.txt
var usage string

// Env is what the command reads from its surroundings.
type Env struct {
	Dir       string // the store (SANDBOX_SECRETS_DIR, default ~/.sandbox/secrets)
	Home      string // shown as ~ in messages
	Root      string // the install root, in a legacy message only
	Stdin     io.Reader
	StdinTTY  bool
	StderrTTY bool // ERROR lines in color
	NoColor   bool
	Getenv    func(string) string // --from-env reads it; nil reads nothing
	Location  *time.Location      // list's times (nil: the system's)
}

type exit int

type cmd struct {
	env            Env
	stdout, stderr io.Writer
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c *cmd) out(f string, a ...any)    { fmt.Fprintf(c.stdout, f+"\n", a...) }
func (c *cmd) errOut(f string, a ...any) { fmt.Fprintf(c.stderr, f+"\n", a...) }

func (c *cmd) die(f string, a ...any) {
	red, reset := "", ""
	if c.env.StderrTTY && !c.env.NoColor {
		red, reset = "\033[31m", "\033[0m"
	}
	fmt.Fprintf(c.stderr, "%sERROR:%s %s\n", red, reset, fmt.Sprintf(f, a...))
	panic(exit(1))
}

func (c *cmd) fail(err error) {
	fmt.Fprintln(c.stderr, err.Error())
	panic(exit(1))
}

func (c *cmd) usage() {
	io.WriteString(c.stdout, usage)
	panic(exit(0))
}

// missingArg is "${N:?message}" for a missing value (see the in-VM CLI's needValue).
func (c *cmd) missingArg(n, msg string) {
	if deviation.Fixed(deviation.FlagValueErrors) {
		c.die("%s", msg)
	}
	fmt.Fprintf(c.stderr, "sandbox: line 0: %s: %s\n", n, msg)
	panic(exit(1))
}

func (c *cmd) tilde(p string) string {
	if h := c.env.Home; h != "" && strings.HasPrefix(p, h) {
		return "~" + p[len(h):]
	}
	return p
}

func (c *cmd) getenv(k string) string {
	if c.env.Getenv == nil {
		return ""
	}
	return c.env.Getenv(k)
}

// Run runs `sandbox secret ARGS` and returns its exit status.
func Run(args []string, env Env, stdout, stderr io.Writer) (status int) {
	c := &cmd{env: env, stdout: stdout, stderr: stderr}
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(exit)
			if !ok {
				panic(r)
			}
			status = int(e)
		}
	}()
	c.run(args)
	return 0
}

func (c *cmd) run(args []string) {
	if len(args) == 0 {
		c.usage()
	}
	st := secrets.Store{Dir: c.env.Dir}
	sub, args := args[0], args[1:]
	switch sub {
	case "--help", "-h", "help":
		c.usage()
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
				c.usage()
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
			if err := st.SetFromReader(name, c.env.Stdin); err != nil {
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
			c.out("No secrets in %s/.", c.tilde(c.env.Dir))
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
