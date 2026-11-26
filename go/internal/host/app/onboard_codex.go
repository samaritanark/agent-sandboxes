package app

// Codex's login (owner decision, tenth round; personal ChatGPT login). Codex keeps a ChatGPT
// login in auth.json: an access token (a JWT), an id token, and a rotating refresh token. Onboard
// runs Codex's own device login into a throwaway CODEX_HOME, so the sandbox holds a login family
// of its own (refreshing it can never sign out the operator's own Codex), and seals the tokens
// into the VM's broker: agent.codex (the access token, bound to chatgpt.com) and
// agent.codex.refresh (withheld; only sandboxd's refresh helper opens it). The account's
// non-secret identity goes to ~/.sandbox/agent-config/codex/identity.json, from which each launch
// writes the guest's auth.json with placeholders. Nothing of the login stays on the host.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
)

// codexStaged are the files of ~/.codex onboard copies (settings and global instructions; never
// auth.json or history).
var codexStaged = []string{"config.toml", "AGENTS.md"}

// codexAuth is what onboard reads from a Codex auth.json.
type codexAuth struct {
	Tokens *struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		AccountID    string `json:"account_id"`
	} `json:"tokens"`
}

// CodexIdentity is the non-secret account information a guest auth.json carries.
type CodexIdentity struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email,omitempty"`
	Plan      string `json:"plan,omitempty"`
	UserID    string `json:"user_id,omitempty"`
}

// jwtPayload decodes a JWT's payload (no signature check: the claims are only copied).
func jwtPayload(tok string, into any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// codexIdentity reads the account from the tokens' claims.
func codexIdentity(idToken, accountID string) (CodexIdentity, error) {
	var c struct {
		Email string `json:"email"`
		Auth  struct {
			AccountID string `json:"chatgpt_account_id"`
			Plan      string `json:"chatgpt_plan_type"`
			UserID    string `json:"chatgpt_user_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := jwtPayload(idToken, &c); err != nil {
		return CodexIdentity{}, fmt.Errorf("the id token: %v", err)
	}
	id := CodexIdentity{AccountID: accountID, Email: c.Email, Plan: c.Auth.Plan, UserID: c.Auth.UserID}
	if id.AccountID == "" {
		id.AccountID = c.Auth.AccountID
	}
	if id.AccountID == "" {
		return CodexIdentity{}, errors.New("the login names no ChatGPT account")
	}
	return id, nil
}

// codexLogin runs `codex login --device-auth` into a fresh CODEX_HOME (file storage) and returns
// its auth.json; the directory is removed.
func (a *app) codexLogin() []byte {
	codex, err := exec.LookPath("codex")
	if err != nil {
		a.die("Codex is not installed on this machine (it runs the login). Install it, or pass --from-auth-json FILE.")
	}
	dir, err := os.MkdirTemp("", "sandbox-codex-login-")
	if err != nil {
		a.die("%v", err)
	}
	defer os.RemoveAll(dir)
	fmt.Fprintln(a.env.Stdout, "    Signing in to Codex for the sandbox (its own login; your Codex on this machine is not touched).")
	cmd := exec.CommandContext(a.ctx, codex, "-c", `cli_auth_credentials_store="file"`, "login", "--device-auth")
	cmd.Env = append(os.Environ(), "CODEX_HOME="+dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.env.Stdin, a.env.Stdout, a.env.Stderr
	if err := cmd.Run(); err != nil {
		a.die("the Codex login did not complete: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		a.die("the Codex login wrote no auth.json: %v", err)
	}
	return b
}

func (a *app) onboardCodex(fromFile string, dry bool) {
	fmt.Fprintln(a.env.Stdout, "==> Codex")
	for _, f := range a.stageAgentConfig("codex", codexStaged, dry) {
		fmt.Fprintf(a.env.Stdout, "    Copied ~/.codex/%s to ~/.sandbox/agent-config/codex/\n", f)
	}
	if dry {
		fmt.Fprintln(a.env.Stdout, "    Would sign in to Codex and seal the login into the sandbox VM's broker.")
		return
	}
	var raw []byte
	if fromFile != "" {
		b, err := os.ReadFile(fromFile)
		if err != nil {
			a.die("%v", err)
		}
		raw = b
		fmt.Fprintln(a.env.Stderr, "WARNING: the sandbox refreshes this login from now on, which signs out any other copy of it. Use a login made for the sandbox.")
	} else if a.env.CodexLogin != nil {
		b, err := a.env.CodexLogin()
		if err != nil {
			a.die("the Codex login did not complete: %v", err)
		}
		raw = b
	} else {
		raw = a.codexLogin()
	}
	defer brokerseal.Wipe(raw)
	var auth codexAuth
	if err := json.Unmarshal(raw, &auth); err != nil || auth.Tokens == nil || auth.Tokens.AccessToken == "" || auth.Tokens.RefreshToken == "" {
		a.die("that is not a Codex ChatGPT login (auth.json with an access and a refresh token).")
	}
	t := auth.Tokens
	id, err := codexIdentity(t.IDToken, t.AccountID)
	if err != nil {
		a.die("%v", err)
	}
	var exp struct {
		Exp int64 `json:"exp"`
	}
	if jwtPayload(t.AccessToken, &exp) != nil || exp.Exp == 0 {
		a.die("the Codex access token is not a JWT with an expiry.")
	}
	ep := a.running()
	access, refresh := []byte(t.AccessToken), []byte(t.RefreshToken)
	defer brokerseal.Wipe(access)
	defer brokerseal.Wipe(refresh)
	a.pushAgentToken(ep, "agent.codex", access, brokerseal.Binding{Hosts: []string{"chatgpt.com"}, Inject: "bearer"})
	a.pushAgentToken(ep, "agent.codex.refresh", refresh, brokerseal.Binding{})
	dst := filepath.Join(a.env.StateDir, "agent-config", "codex")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		a.die("%v", err)
	}
	b, _ := json.MarshalIndent(id, "", "  ")
	if err := os.WriteFile(filepath.Join(dst, "identity.json"), append(b, '\n'), 0o600); err != nil {
		a.die("%v", err)
	}
	fmt.Fprintf(a.env.Stdout, "    Sealed the login of %s into the sandbox VM's credential broker (bound to chatgpt.com).\n", or(id.Email, id.AccountID))
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
