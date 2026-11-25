// Package cli is the in-VM `sandbox` command (design 5.1.6): every v2 subcommand, proxied into the
// VM by the host binary, with v2's flags, messages, and exit codes. It is built command by command
// against bin/sandbox as the oracle; a command not yet ported says so.
package cli

import (
	"embed"
	"fmt"
	"io"
	"strings"
)

//go:embed usage/*.txt
var usageFS embed.FS

// VersionInfo is the build identity bin/sandbox reads from <root>/.version.
type VersionInfo struct {
	Version, Commit, CommitDate, BuildDate, TreeState string
}

// Env is what the CLI reads from its surroundings.
type Env struct {
	Version   VersionInfo // Version "" means "dev"
	Root      string      // the install root (SANDBOX_ROOT)
	LogsDir   string      // SANDBOX_LOGS_DIR
	Runtime   string      // what `version` reports as the runtime ("bash 5.2.21" in v2)
	StdoutTTY bool        // stdout is a terminal (colors)
	StderrTTY bool        // stderr is a terminal (colors)
	NoColor   bool        // NO_COLOR is set
}

func (e Env) version() string {
	if e.Version.Version == "" {
		return "dev"
	}
	return e.Version.Version
}

// cmdCtx carries one invocation's output streams.
type cmdCtx struct {
	env            Env
	stdout, stderr io.Writer
}

// exit is how a command ends early with a status, as the bash's `exit`.
type exit int

func (c *cmdCtx) die(f string, a ...interface{}) {
	red, reset := "", ""
	if c.env.StderrTTY && !c.env.NoColor {
		red, reset = "\033[31m", "\033[0m"
	}
	fmt.Fprintf(c.stderr, "%sERROR:%s %s\n", red, reset, fmt.Sprintf(f, a...))
	panic(exit(1))
}

func (c *cmdCtx) warn(f string, a ...interface{}) {
	yellow, reset := "", ""
	if c.env.StderrTTY && !c.env.NoColor {
		yellow, reset = "\033[33m", "\033[0m"
	}
	fmt.Fprintf(c.stderr, "%sWARN:%s %s\n", yellow, reset, fmt.Sprintf(f, a...))
}

func (c *cmdCtx) out(f string, a ...interface{}) { fmt.Fprintf(c.stdout, f+"\n", a...) }

// usage prints one of bin/sandbox's usage texts (captured by testdata/gen-usage.sh) and ends with
// status 0, as every usage function there does.
func (c *cmdCtx) usage(name string) {
	b, err := usageFS.ReadFile("usage/" + name + ".txt")
	if err != nil {
		panic(fmt.Sprintf("missing usage text %s", name))
	}
	s := strings.NewReplacer("@VERSION@", c.env.version(), "@LOGS_DIR@", c.env.LogsDir).Replace(string(b))
	io.WriteString(c.stdout, s)
	panic(exit(0))
}

// commands maps each v2 subcommand to its port, or nil while it is not yet ported.
var commands = map[string]func(*cmdCtx, []string){
	"run": nil, "resume": nil, "allow": nil, "list": nil, "logs": nil, "flows": nil, "stop": nil,
	"cleanup": nil, "check": nil, "status": nil, "install": nil, "setup": nil, "uninstall": nil,
	"upgrade": nil, "onboard": nil, "secret": nil, "mask": nil, "exceptions": nil, "vet": nil,
	"profile": nil, "link": nil, "configure-network": nil, "setup-proxy-cert": nil, "rebuild": nil,
	"version": cmdVersion,
}

// usageOf names each command's usage text in bin/sandbox.
var usageOf = map[string]string{
	"run": "usage_run", "rebuild": "usage_rebuild", "upgrade": "usage_upgrade", "onboard": "usage_onboard",
	"allow": "usage_allow", "mask": "usage_mask", "exceptions": "usage_exceptions", "secret": "usage_secret",
	"vet": "usage_vet", "link": "usage_link", "profile": "usage_profile",
}

// Run is main(): dispatch args[0] to its command. It returns the exit status.
func Run(args []string, env Env, stdout, stderr io.Writer) (status int) {
	c := &cmdCtx{env: env, stdout: stdout, stderr: stderr}
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exit); ok {
				status = int(e)
				return
			}
			panic(r)
		}
	}()
	if len(args) == 0 {
		c.usage("usage")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "--help", "-h", "help":
		c.usage("usage")
	}
	f, known := commands[cmd]
	if !known {
		c.die("Unknown command: %s. Run 'sandbox --help' for usage.", cmd)
	}
	if f == nil {
		// Until a command is ported, only its help (the first argument --help or -h, as each
		// v2 command's parser handles it) is available.
		if u, ok := usageOf[cmd]; ok && len(rest) > 0 && (rest[0] == "--help" || rest[0] == "-h") {
			c.usage(u)
		}
		c.die("'%s' is not yet available in the Go port of the sandbox CLI.", cmd)
	}
	f(c, rest)
	return 0
}

// cmdVersion is cmd_version.
func cmdVersion(c *cmdCtx, args []string) {
	mode := "full"
	for _, a := range args {
		switch a {
		case "--short":
			mode = "short"
		case "--json":
			mode = "json"
		case "-h", "--help":
			c.out("Usage: sandbox version [--short|--json]")
			return
		default:
			c.die("Unknown flag for 'version': %s (see 'sandbox version --help')", a)
		}
	}
	v, e := c.env.Version, c.env
	switch mode {
	case "short":
		c.out("%s", e.version())
	case "json":
		c.out(`{"version":"%s","commit":"%s","commitDate":"%s","buildDate":"%s","treeState":"%s","runtime":"%s","root":"%s"}`,
			e.version(), v.Commit, v.CommitDate, v.BuildDate, v.TreeState, e.Runtime, e.Root)
	default:
		c.out("sandbox %s", e.version())
		if v.Commit != "" {
			s := "  commit:  " + v.Commit
			if v.CommitDate != "" {
				s += " (" + v.CommitDate + ")"
			}
			c.out("%s", s)
		}
		if v.BuildDate != "" {
			s := "  built:   " + v.BuildDate
			if v.TreeState != "" {
				s += " (" + v.TreeState + ")"
			}
			c.out("%s", s)
		}
		c.out("  runtime: %s", e.Runtime)
		c.out("  root:    %s", e.Root)
	}
}
