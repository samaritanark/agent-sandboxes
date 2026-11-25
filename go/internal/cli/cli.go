// Package cli is the in-VM `sandbox` command (design 5.1.6): every v2 subcommand, proxied into the
// VM by the host binary, with v2's flags, messages, and exit codes. It is built command by command
// against bin/sandbox as the oracle; a command not yet ported says so.
package cli

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/checks"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

//go:embed usage/*.txt
var usageFS embed.FS

// VersionInfo is the build identity bin/sandbox reads from <root>/.version.
type VersionInfo struct {
	Version, Commit, CommitDate, BuildDate, TreeState string
}

// Env is what the CLI reads from its surroundings.
type Env struct {
	config.Env             // HOME, USER_SANDBOX_CONFIG, SANDBOX_OVERLAY, and the rest
	OrgBlockList string    // BLOCKED_DESTINATIONS_CONFIG (default <root>/config/blocked-destinations.yaml)
	Stdin        io.Reader // answers to y/N prompts
	SandboxRoot  string    // the install root the workspace overlap check protects
	IsWSL        bool      // the host is WSL (Windows-drive paths are refused)

	VettingTrustRootDefault string       // SANDBOX_VETTING_TRUST_ROOT_DEFAULT
	Now                     func() int64 // `date +%s`
	LinkOverlaysDir         string       // LINK_OVERLAYS_DIR (default ~/.sandbox/overlays)
	SecretsDir              string       // SANDBOX_SECRETS_DIR (default ~/.sandbox/secrets)
	AgentHomeOverride       string       // SANDBOX_AGENT_HOME_OVERRIDE
	OpencodeAPIKey          string       // OPENCODE_API_KEY
	OpencodeBaseURL         string       // OPENCODE_BASE_URL
	NoLinkCheck             bool         // SANDBOX_NO_LINK_CHECK is set
	IsMacOS                 bool         // the host is macOS
	// ImagePresent is k3s_image_present: 0 present, 1 absent, 2 cannot tell. nil skips the check
	// (v3 has no k3s image store; sandboxd reports a missing image).
	ImagePresent func(tag string) int
	StdinTTY     bool               // [[ -t 0 ]]
	User         string             // ${USER:-$(id -un)}
	MaxDeps      string             // SANDBOX_MAX_DEPS_PER_SESSION
	RandBytes    func(n int) []byte // head -c n /dev/urandom; nil reads crypto/rand
	// RunHandoff receives what `sandbox run` decided: the launch decisions and, unless
	// StopAtDecisions, the session record. nil (the binary today) reports that the session
	// runtime is not available yet; the differential test prints them instead.
	RunHandoff      func(LaunchSpec, *SessionRecord)
	StopAtDecisions bool // hand off after the launch decisions (the test's STOP_AT=b1)
	// SessionLive answers whether a session's workload is running (v2: kubectl get pod), and
	// ApplyPolicy replaces a live session's egress policy (v2: build_cilium_policy | kubectl
	// apply). Both are sandboxd's in v3; while nil, `allow` stops before touching the session.
	SessionLive func(sessionID, pod string) bool
	ApplyPolicy func(PolicyRequest) error

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
	stdin          *bufio.Reader
}

func (c *cmdCtx) checks() checks.Ctx { return checks.Ctx{Env: c.env.Env, OrgFile: c.env.OrgBlockList} }

// readLine is `read -r reply` under the bash's `set -e`: one line from stdin without its newline.
// When input ends before a newline, read fails and errexit ends the command with status 1, saying
// nothing (even a partial "y" is not acted on).
func (c *cmdCtx) readLine() string {
	if c.stdin == nil {
		panic(exit(1))
	}
	l, err := c.stdin.ReadString('\n')
	if err != nil {
		panic(exit(1))
	}
	return strings.TrimSuffix(l, "\n")
}

// tilde is ${p/#${HOME}/\~}: the home prefix shown as ~.
func (c *cmdCtx) tilde(p string) string {
	if h := c.env.Home; h != "" && strings.HasPrefix(p, h) {
		return "~" + p[len(h):]
	}
	return p
}

// fail prints a refusal the bash prints itself before `exit 1` (not through die, so uncolored).
func (c *cmdCtx) fail(err error) {
	fmt.Fprintln(c.stderr, err.Error())
	panic(exit(1))
}

// needValue is the bash's "${2:?<flag> requires a value}": the next argument, which must be
// non-empty. In legacy mode a missing one prints bash's own expansion error (the script path and
// line, which the oracle normalizes to "sandbox: line 0") and exits 1; with FlagValueErrors it is
// an ERROR line like every other refusal.
func (c *cmdCtx) needValue(args []string, i int, flag string) string {
	if i+1 < len(args) && args[i+1] != "" {
		return args[i+1]
	}
	if deviation.Fixed(deviation.FlagValueErrors) {
		c.die("%s requires a value", flag)
	}
	fmt.Fprintf(c.stderr, "sandbox: line 0: 2: %s requires a value\n", flag)
	panic(exit(1))
}

// missingArg is "${N:?message}" for a missing or empty positional argument: as needValue.
func (c *cmdCtx) missingArg(n, msg string) {
	if deviation.Fixed(deviation.FlagValueErrors) {
		c.die("%s", msg)
	}
	fmt.Fprintf(c.stderr, "sandbox: line 0: %s: %s\n", n, msg)
	panic(exit(1))
}

// padRight is printf's %-Ns under LC_ALL=C: pad to n bytes, not runes.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
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

// errOut writes a line to stderr without the ERROR prefix or color.
func (c *cmdCtx) errOut(f string, a ...interface{}) { fmt.Fprintf(c.stderr, f+"\n", a...) }

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
	"run": cmdRun, "resume": nil, "allow": cmdAllow, "list": cmdList, "logs": cmdLogs, "flows": nil, "stop": nil,
	"cleanup": cmdCleanup, "check": cmdCheck, "status": nil, "install": nil, "setup": nil, "uninstall": nil,
	"upgrade": nil, "onboard": nil, "secret": nil, "mask": cmdMask, "exceptions": cmdExceptions, "vet": cmdVet,
	"profile": cmdProfile, "link": cmdLink, "configure-network": nil, "setup-proxy-cert": nil, "rebuild": nil,
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
	if env.Stdin != nil {
		c.stdin = bufio.NewReader(env.Stdin)
	}
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
