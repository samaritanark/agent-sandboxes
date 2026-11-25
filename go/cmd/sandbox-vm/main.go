// Command sandbox-vm is the in-VM `sandbox` (design 5.1.6), installed in the appliance image as
// /usr/bin/sandbox; the host binary proxies every v2 subcommand to it.
package main

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/cli"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/opstate"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncagent"
)

// Set at build time with -ldflags "-X main.version=...".
var version, commit, commitDate, buildDate, treeState string

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// currentUser is ${USER:-$(id -un)}.
func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// receiveOperatorState is the VM half of the operator-state push (design 5.1.4): the host binary
// runs it over SSH, with the archive on stdin, before each proxied command. It is not a CLI command,
// so the in-VM CLI's own commands and texts stay as v2 had them.
const receiveOperatorState = "__receive-operator-state"

// syncAgent is the in-VM end of the workspace sync (design 5.6): the host engine runs it over SSH
// for one workspace copy under /var/lib/sandbox/workspaces.
const syncAgent = "__sync-agent"

func main() {
	if len(os.Args) == 3 && os.Args[1] == syncAgent {
		ws := filepath.Clean(os.Args[2])
		if !strings.HasPrefix(ws, "/var/lib/sandbox/workspaces/") || strings.Count(ws, "/") != 5 {
			os.Stderr.WriteString("ERROR: not a workspace copy: " + os.Args[2] + "\n")
			os.Exit(1)
		}
		if err := syncagent.Serve(ws, os.Stdin, os.Stdout); err != nil {
			os.Stderr.WriteString("ERROR: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == receiveOperatorState {
		dest := os.Getenv("SANDBOX_OPERATOR_DIR")
		if dest == "" {
			dest = "/var/lib/sandbox/operator"
		}
		if err := opstate.Receive(os.Stdin, dest); err != nil {
			os.Stderr.WriteString("ERROR: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	logs := os.Getenv("SANDBOX_LOGS_DIR")
	if logs == "" {
		logs = os.Getenv("HOME") + "/.sandbox/logs"
	}
	root, _ := os.Executable()
	_, noColor := os.LookupEnv("NO_COLOR")
	cfg := config.FromOS()
	org := os.Getenv("BLOCKED_DESTINATIONS_CONFIG")
	if org == "" { // the v2 default, relative to the install root
		org = filepath.Join(filepath.Dir(filepath.Dir(root)), "config", "blocked-destinations.yaml")
	}
	env := cli.Env{
		Env:                     cfg,
		OrgBlockList:            org,
		Stdin:                   os.Stdin,
		SandboxRoot:             filepath.Dir(filepath.Dir(root)),
		VettingTrustRootDefault: os.Getenv("SANDBOX_VETTING_TRUST_ROOT_DEFAULT"),
		Version:                 cli.VersionInfo{Version: version, Commit: commit, CommitDate: commitDate, BuildDate: buildDate, TreeState: treeState},
		Root:                    root,
		LogsDir:                 logs,
		Runtime:                 "go " + strings.TrimPrefix(runtime.Version(), "go"),
		StdoutTTY:               isTTY(os.Stdout),
		StdinTTY:                isTTY(os.Stdin),
		Getenv:                  os.Getenv,
		User:                    currentUser(),
		MaxDeps:                 os.Getenv("SANDBOX_MAX_DEPS_PER_SESSION"),
		StderrTTY:               isTTY(os.Stderr),
		NoColor:                 noColor && os.Getenv("NO_COLOR") != "",
		Now:                     func() int64 { return time.Now().Unix() },
		SecretsDir:              or(os.Getenv("SANDBOX_SECRETS_DIR"), cfg.Home+"/.sandbox/secrets"),
		AgentHomeOverride:       os.Getenv("SANDBOX_AGENT_HOME_OVERRIDE"),
		OpencodeAPIKey:          os.Getenv("OPENCODE_API_KEY"),
		OpencodeBaseURL:         os.Getenv("OPENCODE_BASE_URL"),
		NoLinkCheck:             os.Getenv("SANDBOX_NO_LINK_CHECK") != "",
		IsMacOS:                 runtime.GOOS == "darwin",
		LinkOverlaysDir:         os.Getenv("LINK_OVERLAYS_DIR"),
	}
	os.Exit(cli.Run(os.Args[1:], env, os.Stdout, os.Stderr))
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
