// Command sandbox-vm is the in-VM `sandbox` (design 5.1.6), installed in the appliance image as
// /usr/bin/sandbox; the host binary proxies every v2 subcommand to it.
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/cli"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// Set at build time with -ldflags "-X main.version=...".
var version, commit, commitDate, buildDate, treeState string

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func main() {
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
		StderrTTY:               isTTY(os.Stderr),
		NoColor:                 noColor && os.Getenv("NO_COLOR") != "",
		Now:                     func() int64 { return time.Now().Unix() },
	}
	os.Exit(cli.Run(os.Args[1:], env, os.Stdout, os.Stderr))
}
