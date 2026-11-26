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

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/secrets"
)

//go:embed usage_secret.txt
var usageV2 string

// usageBindings is v3's addition to v2's text (which gen-usage.sh regenerates from the bash).
//
//go:embed usage_secret_bindings.txt
var usageBindings string

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
	io.WriteString(c.stdout, usageV2)
	if deviation.Fixed(deviation.SecretBindings) {
		io.WriteString(c.stdout, usageBindings)
	}
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
		var bf bindFlags
		for i := 0; i < len(args); i++ {
			a := args[i]
			if n := c.bindFlag(&bf, "set", args, i); n > 0 {
				i += n - 1
				continue
			}
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
		b, haveBinding := c.binding(bf, "set")
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
		// after the value, so a refused value leaves the binding as it was
		if haveBinding {
			c.setBinding(st, name, b)
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
			if f := strings.Fields(r); len(f) > 0 && deviation.Fixed(deviation.SecretBindings) {
				if b, err := st.Binding(f[0]); err != nil {
					r += "  (unreadable binding)"
				} else if d := describe(b); d != "" {
					r += "  " + d
				}
			}
			c.out("%s", r)
		}
		if len(rows) == 0 {
			c.out("No secrets in %s/.", c.tilde(c.env.Dir))
			c.out("Add one with: sandbox secret set <NAME>")
		}
	case "bind":
		if !deviation.Fixed(deviation.SecretBindings) {
			c.die("Unknown 'secret' subcommand: %s. Run 'sandbox secret --help'.", sub)
		}
		var name string
		var bf bindFlags
		for i := 0; i < len(args); i++ {
			if n := c.bindFlag(&bf, "bind", args, i); n > 0 {
				i += n - 1
				continue
			}
			switch a := args[i]; {
			case a == "--help" || a == "-h":
				c.usage()
			case strings.HasPrefix(a, "-"):
				c.die("Unknown option for 'secret bind': %s", a)
			case name != "":
				c.die("Unexpected extra argument: %s", a)
			default:
				name = a
			}
		}
		if name == "" {
			c.die("Usage: sandbox secret bind <NAME> (--bind HOST [--inject KIND] | --allow-readable | --withhold)")
		}
		if err := secrets.ValidateName(name); err != nil {
			c.fail(err)
		}
		b, ok := c.binding(bf, "bind")
		if !ok {
			c.die("secret bind: give --bind HOST, --allow-readable, or --withhold.")
		}
		if !st.Exists(name) {
			c.die("Secret '%s' is not in the store. Set it first: sandbox secret set %s", name, name)
		}
		c.setBinding(st, name, b)
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

// bindFlags are the binding options of `secret set` and `secret bind` (v3).
type bindFlags struct {
	hosts              []string
	inject             string
	readable, withhold bool
	any                bool
}

// bindFlag consumes a binding option at args[i], returning how many arguments it took (0: none).
func (c *cmd) bindFlag(bf *bindFlags, sub string, args []string, i int) int {
	if !deviation.Fixed(deviation.SecretBindings) {
		return 0
	}
	a := args[i]
	val := func(flag string) (string, int) {
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v, 1
		}
		if i+1 >= len(args) || args[i+1] == "" {
			c.die("secret %s: %s requires a value", sub, flag)
		}
		return args[i+1], 2
	}
	switch {
	case a == "--bind" || strings.HasPrefix(a, "--bind="):
		v, n := val("--bind")
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				bf.hosts = append(bf.hosts, h)
			}
		}
		bf.any = true
		return n
	case a == "--inject" || strings.HasPrefix(a, "--inject="):
		v, n := val("--inject")
		bf.inject, bf.any = v, true
		return n
	case a == "--allow-readable":
		bf.readable, bf.any = true, true
		return 1
	case a == "--withhold":
		bf.withhold, bf.any = true, true
		return 1
	}
	return 0
}

// binding is the binding the options ask for, and whether they ask for one.
func (c *cmd) binding(bf bindFlags, sub string) (brokerseal.Binding, bool) {
	if !bf.any {
		return brokerseal.Binding{}, false
	}
	switch {
	case bf.withhold && (len(bf.hosts) > 0 || bf.inject != "" || bf.readable):
		c.die("secret %s: --withhold takes no other binding option.", sub)
	case bf.readable && (len(bf.hosts) > 0 || bf.inject != ""):
		c.die("secret %s: --allow-readable and --bind are mutually exclusive: a secret the agent may read is not brokered.", sub)
	case bf.inject != "" && len(bf.hosts) == 0:
		c.die("secret %s: --inject needs --bind HOST.", sub)
	}
	b := brokerseal.Binding{Hosts: bf.hosts, Inject: bf.inject, Readable: bf.readable}
	if len(b.Hosts) > 0 && b.Inject == "" {
		b.Inject = "bearer"
	}
	b = b.Canonical()
	if err := b.Validate(); err != nil {
		c.die("secret %s: %v.", sub, err)
	}
	return b, true
}

func (c *cmd) setBinding(st secrets.Store, name string, b brokerseal.Binding) {
	if err := st.SetBinding(name, b); err != nil {
		c.die("could not keep the binding of '%s': %v", name, err)
	}
	switch {
	case b.Readable:
		c.out("The agent may read '%s' (in sessions whose profile or command line names it).", name)
	case len(b.Hosts) > 0:
		c.out("Bound '%s' to %s (%s).", name, strings.Join(b.Hosts, ", "), b.Inject)
	default:
		c.out("'%s' is withheld from sessions (no binding).", name)
	}
}

// describe is a binding as `secret list` shows it.
func describe(b brokerseal.Binding) string {
	switch {
	case b.Readable:
		return "readable"
	case len(b.Hosts) > 0:
		return "-> " + strings.Join(b.Hosts, ",") + " (" + b.Inject + ")"
	}
	return ""
}
