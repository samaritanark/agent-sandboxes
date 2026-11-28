package app

// `sandbox vet --repo` signing (design 5.1.3, D-20). The operator's signing key never enters the
// VM, and the host binary never runs git against the repository (its config, hooks, and filters
// would run code the repository chose): the VM checks the synced copy and builds the exact tag
// payload `git tag -s` signs (__vet-prepare); the host reads HEAD itself, shows what it signs (with
// the commits at or below HEAD that a session made), and signs with ssh-keygen (or gpg); the VM
// assembles the tag with git mktag and verifies it against the trust roots (__vet-finish); the
// host writes the tag object and refs/tags/<tag> itself. `vet --status` runs in the VM as before.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/gitobj"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/gitref"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

// The VM's halves (cli.VetPrepare, cli.VetFinish).
const (
	VetPrepareCmd = "__vet-prepare"
	VetFinishCmd  = "__vet-finish"
)

// vetPlan is vetting.Plan as the VM prints it.
type vetPlan struct {
	Head       string   `json:"head"`
	Tag        string   `json:"tag"`
	Already    bool     `json:"already"`
	Exceptions []string `json:"exceptions"`
	Format     string   `json:"format"`
	SigningKey string   `json:"signing_key"`
	Payload    string   `json:"payload"`
	Warnings   []string `json:"warnings"`
}

// vet runs `sandbox vet`: signing here, everything else (status, usage, errors) in the VM.
func (a *app) vet(args []string) int {
	repo, msg, yes := "", "", false
	for i := 0; i < len(args); i++ {
		switch v := args[i]; {
		case (v == "--repo" || v == "--message") && i+1 < len(args):
			if v == "--repo" {
				repo = args[i+1]
			} else {
				msg = args[i+1]
			}
			i++
		case strings.HasPrefix(v, "--repo="):
			repo = v[len("--repo="):]
		case strings.HasPrefix(v, "--message="):
			msg = v[len("--message="):]
		case v == "--yes" || v == "-y":
			yes = true
		default: // --status, --help, and anything the VM refuses with v2's message
			return a.proxy(append([]string{"vet"}, args...))
		}
	}
	if repo == "" {
		return a.proxy(append([]string{"vet"}, args...))
	}
	repo = a.expandTilde(repo)
	if !filepath.IsAbs(repo) {
		wd, err := os.Getwd()
		if err != nil {
			a.die("%v", err)
		}
		repo = filepath.Join(wd, repo)
	}
	repo = filepath.Clean(repo)
	r, err := gitref.Open(repo)
	if err != nil {
		a.die("%s is not a git repository — nothing to attest. (%v)", repo, err)
	}
	tagger := a.tagger()
	ep := a.running()
	a.handshake(ep)
	a.pushState(ep)
	a.syncAndMirror(ep, []string{repo})

	var out bytes.Buffer
	argv := []string{VetPrepareCmd, repo, tagger}
	if msg != "" {
		argv = append(argv, msg)
	}
	rc, err := a.env.Transport.Run(a.ctx, ep, a.vmArgvEnv(nil, argv...), nil, &out, a.env.Stderr, false)
	if err != nil {
		a.die("cannot run the vetting check in the sandbox VM: %v", err)
	}
	if rc != 0 {
		return rc
	}
	var p vetPlan
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		a.die("the sandbox VM's attestation plan is malformed: %v", err)
	}
	head, err := r.Head()
	if err != nil {
		a.die("cannot read %s's HEAD: %v", repo, err)
	}
	if p.Head != head {
		a.die("the sandbox VM's copy of %s is at %s, but HEAD here is %s; nothing was signed. Run 'sandbox sync once --repo %s' and try again.", repo, short(p.Head), short(head), repo)
	}
	if p.Already {
		fmt.Fprintf(a.env.Stdout, "  %s: already attested — tag %s exists.\n", repo, p.Tag)
		return 0
	}
	if p.Tag != "agent-vetted/"+head || !strings.HasPrefix(p.Payload, gitref.TagHeader(head, p.Tag)+tagger+"\n\n") {
		a.die("the sandbox VM's tag payload is not for HEAD %s with this identity; nothing was signed.", short(head))
	}
	for _, w := range p.Warnings {
		fmt.Fprintf(a.env.Stderr, "WARN: %s\n", w)
	}
	fmt.Fprintf(a.env.Stdout, "==> Attesting %s\n    HEAD:    %s\n    tag:     %s\n    message: %s\n", repo, head, p.Tag,
		strings.TrimSpace(p.Payload[strings.Index(p.Payload, "\n\n")+2:]))
	ack := false
	if len(p.Exceptions) > 0 {
		fmt.Fprintf(a.env.Stderr, "\n  This repo records %d secret exception(s). Signing this attestation\n", len(p.Exceptions))
		fmt.Fprintln(a.env.Stderr, "  vouches that they are reviewed false positives — the agent WILL be able to")
		fmt.Fprintln(a.env.Stderr, "  read these values once the repo is vetted:")
		for _, x := range p.Exceptions {
			fmt.Fprintf(a.env.Stderr, "      %s\n", x)
		}
		ack = true
	}
	if made := a.sessionCommits(r, repo, head); len(made) > 0 {
		fmt.Fprintln(a.env.Stderr, "\n  These commits at or below HEAD were made in a sandbox session (the sync's ledger);")
		fmt.Fprintln(a.env.Stderr, "  review them before you sign:")
		for _, l := range made {
			fmt.Fprintf(a.env.Stderr, "      %s\n", l)
		}
		ack = true
	}
	if ack {
		fmt.Fprintln(a.env.Stderr)
		switch {
		case yes:
			fmt.Fprintln(a.env.Stderr, "  Acknowledged via --yes.")
		case !a.env.StdinTTY:
			a.die("not an interactive terminal, so these cannot be acknowledged\n       interactively. Re-run with --yes to sign off on them explicitly.")
		default:
			fmt.Fprint(a.env.Stderr, "  Acknowledge and sign? [y/N] ")
			line, _ := bufio.NewReader(a.env.Stdin).ReadString('\n')
			if l := strings.ToLower(strings.TrimSpace(line)); l != "y" && l != "yes" {
				fmt.Fprintln(a.env.Stderr, "  Aborted; no attestation created.")
				return 1
			}
		}
	}
	sig, err := a.signPayload([]byte(p.Payload), p.Format, p.SigningKey)
	if err != nil {
		a.die("failed to sign the attestation: %v\n       Configure a signing key: vetting_signing_key: ~/.ssh/id_ed25519.pub in\n       ~/.sandbox/config.yaml, or git config --global user.signingkey (with gpg.format ssh),\n       and make sure its public key is in the trust root.", err)
	}
	tag := append([]byte(p.Payload), sig...)
	in, _ := json.Marshal(map[string]string{"tag": string(tag)})
	out.Reset()
	rc, err = a.env.Transport.Run(a.ctx, ep, a.vmArgvEnv(nil, VetFinishCmd, repo), bytes.NewReader(in), &out, a.env.Stderr, false)
	if err != nil {
		a.die("cannot check the signed attestation in the sandbox VM: %v", err)
	}
	if rc != 0 {
		return rc
	}
	var fin struct {
		Warnings []string `json:"warnings"`
	}
	json.Unmarshal(out.Bytes(), &fin)
	for _, w := range fin.Warnings {
		fmt.Fprintf(a.env.Stderr, "WARN: %s\n", w)
	}
	if _, err := r.WriteTag(tag, p.Tag, head); err != nil {
		a.die("could not write the attestation tag into %s: %v", repo, err)
	}
	fmt.Fprintf(a.env.Stdout, "  %s: created signed attestation tag %s\n", repo, p.Tag)
	fmt.Fprintln(a.env.Stdout, "  Push it so other operators can verify:")
	fmt.Fprintf(a.env.Stdout, "        git -C %s push origin %s\n", repo, p.Tag)
	a.syncAndMirror(ep, []string{repo}) // the VM's copy gets the tag for the next launch
	return 0
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// tagger is the operator's git identity and the time, as a tag's tagger line has them.
func (a *app) tagger() string {
	get := func(key string) string {
		if a.env.GitConfig != nil {
			return a.env.GitConfig(key)
		}
		cmd := exec.CommandContext(a.ctx, "git", "config", "--global", "--get", key)
		cmd.Dir = os.TempDir() // never a repository's own configuration
		out, _ := cmd.Output()
		return strings.TrimSpace(string(out))
	}
	name, email := get("user.name"), get("user.email")
	if name == "" || email == "" || strings.ContainsAny(name+email, "<>\n") {
		a.die("set your git identity first: git config --global user.name \"Your Name\"; git config --global user.email you@example.com")
	}
	now := a.env.Now()
	return fmt.Sprintf("%s <%s> %d %s", name, email, now.Unix(), now.Format("-0700"))
}

// signPayload signs payload as `git tag -s` does: ssh-keygen -Y sign -n git with the key (a file,
// or a public key given inline, whose private half the agent holds), or gpg --detach-sign.
func (a *app) signPayload(payload []byte, format, key string) ([]byte, error) {
	get := func(k string) string {
		if a.env.GitConfig != nil {
			return a.env.GitConfig(k)
		}
		cmd := exec.CommandContext(a.ctx, "git", "config", "--global", "--get", k)
		cmd.Dir = os.TempDir()
		out, _ := cmd.Output()
		return strings.TrimSpace(string(out))
	}
	if key == "" {
		key = get("user.signingkey")
	}
	if format == "gpg" {
		args := []string{"--detach-sign", "--armor"}
		if key != "" {
			args = append(args, "--local-user", key)
		}
		return a.runSigner("gpg", args, payload)
	}
	if key == "" {
		return nil, fmt.Errorf("no SSH signing key is configured")
	}
	file := ""
	switch lit := strings.TrimPrefix(key, "key::"); {
	case strings.HasPrefix(lit, "ssh-") || strings.HasPrefix(lit, "ecdsa-") || strings.HasPrefix(lit, "sk-"):
		f, err := os.CreateTemp("", "sandbox-vet-key-")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		f.WriteString(lit + "\n")
		f.Close()
		file = f.Name()
	default:
		file = a.expandTilde(key)
		if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("the signing key %s is not a file", key)
		}
	}
	return a.runSigner("ssh-keygen", []string{"-Y", "sign", "-n", "git", "-f", file}, payload)
}

func (a *app) runSigner(prog string, args []string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute) // a hardware key or pinentry may wait for the operator
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Dir = os.TempDir()
	cmd.Stdin = bytes.NewReader(payload)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, a.env.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %v", prog, err)
	}
	sig := out.Bytes()
	if !bytes.Contains(sig, []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("%s printed no signature", prog)
	}
	if !bytes.HasSuffix(sig, []byte("\n")) {
		sig = append(sig, '\n')
	}
	return sig, nil
}

// sessionCommits is the sync ledger's commits for repo that are HEAD or below it (rule 6: commits
// a session made and the host took).
func (a *app) sessionCommits(r *gitref.Repo, repo, head string) []string {
	id, err := syncgate.RepoID(repo)
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(a.env.StateDir, "sync", id, LedgerFile))
	if err != nil {
		return nil
	}
	st, err := gitobj.Open(filepath.Join(r.CommonDir, "objects"), r.HashLen)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		i := strings.LastIndex(l, "-> ")
		if i < 0 {
			continue
		}
		f := strings.Fields(l[i+3:])
		if len(f) == 0 || len(f[0]) != r.HashLen || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		if ok, err := st.IsAncestor(f[0], head); err == nil && ok {
			out = append(out, l)
		}
	}
	return out
}

// LedgerFile is where in a repository's sync state the host keeps the ledger of the VM's ref and
// HEAD updates it took (syncengine.Report.Ledger), one line each with its time.
const LedgerFile = "ledger.log"

// recordLedger appends a sync pass's ledger lines.
func (a *app) recordLedger(id string, lines []string) {
	if len(lines) == 0 || a.env.StateDir == "" {
		return
	}
	dir := filepath.Join(a.env.StateDir, "sync", id)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, LedgerFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintf(f, "%s %s\n", a.env.Now().UTC().Format(time.RFC3339), l)
	}
}
