package app

// `sandbox onboard` in v3 (design 5.9.6; owner decision, tenth round): the agent's credential goes
// into the sandbox VM's broker store, sealed on the host and bound to the agent's API hosts, and
// never into a home the agent can read. Claude Code is the first agent with an adapter: the
// operator runs `claude setup-token` (a long-lived OAuth token for their subscription), and onboard
// seals it as agent.claude for api.anthropic.com; sessions get a placeholder in
// CLAUDE_CODE_OAUTH_TOKEN. Onboard also copies the agent's benign settings and global instructions
// into ~/.sandbox/agent-config/<agent>/, which every launch re-stages as a writable copy. The token
// is kept nowhere on the host by sandbox; after the VM is recreated, onboard runs again.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

const onboardUsage = `sandbox onboard — Put an agent's login into the sandbox VM's credential broker

USAGE:
  sandbox onboard [--agent claude] [--dry-run]

CLAUDE CODE:
  1. On this machine, run:  claude setup-token
     (it opens a browser to sign in and prints a long-lived token, sk-ant-oat01-...)
  2. Run:  sandbox onboard --agent claude
     and paste the token when asked (or export CLAUDE_CODE_OAUTH_TOKEN first).

  The token is sealed on this machine and stored only in the sandbox VM's broker. A session's
  agent sees a placeholder; the gateway puts the real token into its requests to
  api.anthropic.com. Your ~/.claude/settings.json and ~/.claude/CLAUDE.md are copied to
  ~/.sandbox/agent-config/claude/ and given to each session as a fresh, writable copy.
  Onboard again after the sandbox VM is reinstalled.

OTHER AGENTS:
  codex, copilot, and grok are not yet available in v3 (their broker adapters are not built).
  opencode needs no onboarding: run it with OPENCODE_API_KEY and OPENCODE_BASE_URL set.
`

// claudeToken is the shape of a `claude setup-token` token.
var claudeToken = regexp.MustCompile(`^sk-ant-oat01-[A-Za-z0-9_-]{20,500}$`)

// claudeStaged are the files of ~/.claude onboard copies (settings and global instructions; never
// credentials or history).
var claudeStaged = []string{"settings.json", "CLAUDE.md"}

func (a *app) onboard(args []string) int {
	agent, dry := "claude", false
	for i := 0; i < len(args); i++ {
		switch v := args[i]; {
		case v == "--help" || v == "-h":
			io.WriteString(a.env.Stdout, onboardUsage)
			return 0
		case v == "--agent" && i+1 < len(args):
			agent = args[i+1]
			i++
		case strings.HasPrefix(v, "--agent="):
			agent = v[len("--agent="):]
		case v == "--dry-run":
			dry = true
		case v == "--force" || v == "--skip-config":
			// v2's flags: nothing to overwrite or write here
		default:
			a.die("Unknown option: %s. Run 'sandbox onboard --help' for usage.", v)
		}
	}
	switch agent {
	case "claude", "all":
	case "opencode":
		fmt.Fprintln(a.env.Stdout, "opencode needs no onboarding: run it with OPENCODE_API_KEY and OPENCODE_BASE_URL set on this machine.")
		return 0
	case "codex", "copilot", "grok":
		a.die("%s is not yet available in v3: its credential broker adapter is not built.", agent)
	default:
		a.die("--agent must be one of: claude, codex, opencode, copilot, grok, all")
	}
	fmt.Fprintln(a.env.Stdout, "==> Claude Code")
	staged := a.stageAgentConfig("claude", claudeStaged, dry)
	for _, f := range staged {
		fmt.Fprintf(a.env.Stdout, "    Copied ~/.claude/%s to ~/.sandbox/agent-config/claude/\n", f)
	}
	if dry {
		fmt.Fprintln(a.env.Stdout, "    Would seal the token from 'claude setup-token' into the sandbox VM's broker.")
		fmt.Fprintln(a.env.Stdout, "Dry-run complete; nothing was written.")
		return 0
	}
	tok := a.readClaudeToken()
	defer brokerseal.Wipe(tok)
	ep := a.running()
	a.pushAgentToken(ep, "agent.claude", tok, brokerseal.Binding{Hosts: []string{"api.anthropic.com"}, Inject: "bearer"})
	fmt.Fprintln(a.env.Stdout, "    Sealed the token into the sandbox VM's credential broker (bound to api.anthropic.com).")
	fmt.Fprintln(a.env.Stdout, "Onboard complete. Run 'sandbox run --agent claude' to launch a session.")
	return 0
}

// readClaudeToken takes the token from CLAUDE_CODE_OAUTH_TOKEN, or asks for it (without echo on a
// terminal), and checks its shape.
func (a *app) readClaudeToken() []byte {
	tok := []byte(strings.TrimSpace(a.getenv("CLAUDE_CODE_OAUTH_TOKEN")))
	if len(tok) == 0 {
		fmt.Fprint(a.env.Stdout, "    Paste the token printed by 'claude setup-token': ")
		restore := a.noEcho()
		line, err := bufio.NewReader(a.env.Stdin).ReadBytes('\n')
		restore()
		fmt.Fprintln(a.env.Stdout)
		if err != nil && !errors.Is(err, io.EOF) {
			a.die("could not read the token: %v", err)
		}
		tok = append([]byte(nil), bytes.TrimSpace(line)...)
		brokerseal.Wipe(line)
	}
	if !claudeToken.Match(tok) {
		brokerseal.Wipe(tok)
		a.die("that is not a token from 'claude setup-token' (it starts with sk-ant-oat01-). An API key (sk-ant-api...) is not accepted.")
	}
	return tok
}

// noEcho turns terminal echo off while a secret is typed, if stdin is a terminal.
func (a *app) noEcho() func() {
	if !a.env.StdinTTY {
		return func() {}
	}
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	if off.Run() != nil {
		return func() {}
	}
	return func() {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		on.Run()
	}
}

// stageAgentConfig copies the agent's benign files from ~/.<agent>/ to
// ~/.sandbox/agent-config/<agent>/ (mode 0600) and returns those it copied.
func (a *app) stageAgentConfig(agent string, files []string, dry bool) []string {
	if a.env.Home == "" {
		return nil
	}
	dst := filepath.Join(a.env.StateDir, "agent-config", agent)
	var done []string
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(a.env.Home, "."+agent, f))
		if err != nil {
			continue
		}
		if !dry {
			if err := os.MkdirAll(dst, 0o700); err != nil {
				a.die("%v", err)
			}
			if err := os.WriteFile(filepath.Join(dst, f), b, 0o600); err != nil {
				a.die("%v", err)
			}
		}
		done = append(done, f)
	}
	return done
}

// pushAgentToken seals an agent's token under ref, bound as b, and stores it in the VM's broker.
func (a *app) pushAgentToken(ep driver.SSHEndpoint, ref string, tok []byte, b brokerseal.Binding) {
	if a.env.BrokerKey == nil {
		a.die("this host has no place to keep the credential broker's key.")
	}
	k, err := a.brokerKey()
	if err != nil {
		a.die("%v", err)
	}
	defer brokerseal.Wipe(k)
	sealed, err := brokerseal.SealBound(k, ref, tok, b)
	if err != nil {
		a.die("%v", err)
	}
	if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", ref); err != nil {
		a.die("could not store the token in the sandbox VM: %v", err)
	}
}
