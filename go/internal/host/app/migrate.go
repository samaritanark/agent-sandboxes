package app

// v2 to v3 (design 11, step 12). `sandbox install` runs it when it finds a v2 install, and
// `sandbox migrate` runs it again. v3 reads ~/.sandbox in v2's formats, so profiles, secrets,
// config.yaml, overlays, vetting, and logs carry over as they are; what changes is reported. Agent
// logins are not taken from v2's agent homes: v3 holds them in the broker (sandbox onboard), and
// reusing a v2 copy would share a login with another client. Claude Code's conversations are
// imported where v2's session records attribute them to a tier above 1 and to repositories on this
// machine; the rest stays in v2's agent home. Removing v2 (its Lima VM; its agent homes, archived
// without their tokens) happens only with --remove-v2, after a confirmation.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
	"github.com/samaritanark/agent-sandboxes/go/internal/secrets"
)

// V2LimaInstance is v2's Lima VM on macOS.
const V2LimaInstance = "sandbox-vm"

// ImportHistory is the in-VM command that adds imported history.
const ImportHistory = "__import-history"

// MigrationDeps is what the migration reads of the machine; zero values use the real one.
type MigrationDeps struct {
	Limactl func(ctx context.Context, args ...string) ([]byte, error)
	K3sPath string // v2's cluster on Linux
	GOOS    string
}

const migrateUsage = `Usage: sandbox migrate [--remove-v2] [--yes]

Carry a v2 install over to v3 (sandbox install does this when it finds one):
report what carries over, what to redo (agent sign-in, secret bindings), and
import Claude Code's conversations into v3's per-tier, per-repository history.

  --remove-v2  Then remove v2: its Lima VM (macOS), and its agent homes, moved
               to ~/.sandbox/v2-archive/ without their login tokens. Asks first.
  --yes        Do not ask.
`

// v2Install is what was found of v2.
type v2Install struct {
	agentHome string   // ~/.sandbox/agent-home, if it exists
	signedIn  []string // agents with a login there
	limaVM    bool
	k3s       bool
}

// v2TokenFiles are the login files of v2's agent homes (lib/onboard.sh).
var v2TokenFiles = map[string][]string{
	"claude":  {".credentials.json"},
	"codex":   {"auth.json"},
	"copilot": {"config.json"},
	"grok":    {"auth.json"},
}

func (a *app) migrationDeps() MigrationDeps {
	d := a.env.Migration
	if d.GOOS == "" {
		d.GOOS = runtime.GOOS
	}
	if d.K3sPath == "" {
		d.K3sPath = "/usr/local/bin/k3s"
	}
	if d.Limactl == nil {
		d.Limactl = func(ctx context.Context, args ...string) ([]byte, error) {
			p, err := exec.LookPath("limactl")
			if err != nil {
				return nil, err
			}
			return exec.CommandContext(ctx, p, args...).Output()
		}
	}
	return d
}

func (a *app) findV2() (v2Install, bool) {
	d := a.migrationDeps()
	var v v2Install
	if st, err := os.Stat(filepath.Join(a.env.StateDir, "agent-home")); err == nil && st.IsDir() {
		v.agentHome = filepath.Join(a.env.StateDir, "agent-home")
		agents := make([]string, 0, len(v2TokenFiles))
		for agent := range v2TokenFiles {
			agents = append(agents, agent)
		}
		sort.Strings(agents)
		for _, agent := range agents {
			for _, f := range v2TokenFiles[agent] {
				if _, err := os.Stat(filepath.Join(v.agentHome, agent, f)); err == nil {
					v.signedIn = append(v.signedIn, agent)
					break
				}
			}
		}
	}
	if d.GOOS == "darwin" {
		if out, err := d.Limactl(a.ctx, "list", "--format", "{{.Name}}"); err == nil {
			for _, n := range strings.Fields(string(out)) {
				v.limaVM = v.limaVM || n == V2LimaInstance
			}
		}
	}
	if d.GOOS == "linux" {
		_, err := os.Stat(d.K3sPath)
		v.k3s = err == nil
	}
	return v, v.agentHome != "" || v.limaVM || v.k3s
}

func (a *app) migrate(args []string) int {
	remove, yes := false, false
	for _, v := range args {
		switch v {
		case "--help", "-h":
			io.WriteString(a.env.Stdout, migrateUsage)
			return 0
		case "--remove-v2":
			remove = true
		case "--yes", "-y":
			yes = true
		default:
			a.die("Unknown option: %s. Run 'sandbox migrate --help' for usage.", v)
		}
	}
	v, found := a.findV2()
	if !found {
		fmt.Fprintln(a.env.Stdout, "No v2 install found (no ~/.sandbox/agent-home, v2 Lima VM, or k3s).")
		return 0
	}
	a.migrateV2(v)
	if remove {
		a.removeV2(v, yes)
	} else {
		fmt.Fprintln(a.env.Stdout, "v2 is still installed. When you no longer need it: sandbox migrate --remove-v2")
	}
	return 0
}

// migrateV2 reports what carries over and imports Claude Code's history (when the VM is running).
func (a *app) migrateV2(v v2Install) {
	var found []string
	if v.agentHome != "" {
		found = append(found, "agent homes in ~/.sandbox/agent-home")
	}
	if v.limaVM {
		found = append(found, "the Lima VM "+V2LimaInstance)
	}
	if v.k3s {
		found = append(found, "its k3s cluster")
	}
	out := a.env.Stdout
	fmt.Fprintf(out, "==> Found a v2 install (%s)\n", strings.Join(found, "; "))
	count := func(dir string) int {
		ents, _ := os.ReadDir(filepath.Join(a.env.StateDir, dir))
		n := 0
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), ".") {
				n++
			}
		}
		return n
	}
	fmt.Fprintf(out, "    Carried over as they are: %d profile(s), %d secret(s), config.yaml, overlays, vetting, logs.\n",
		count("profiles"), len(a.unboundSecrets(false)))
	if un := a.unboundSecrets(true); len(un) > 0 {
		fmt.Fprintf(out, "    In v3 a secret reaches a session only through a binding; these have none and are withheld:\n      %s\n", strings.Join(un, " "))
		fmt.Fprintf(out, "      Bind each to the hosts it is for, e.g.: sandbox secret bind %s --bind api.example.com\n", un[0])
	}
	if len(v.signedIn) > 0 {
		fmt.Fprintln(out, "    Agents signed in under v2. v3 keeps logins in its credential broker; sign in again:")
		for _, agent := range v.signedIn {
			switch agent {
			case "claude":
				fmt.Fprintln(out, "      claude: run 'claude setup-token', then: sandbox onboard --agent claude")
			case "codex":
				fmt.Fprintln(out, "      codex:  sandbox onboard --agent codex")
			default:
				fmt.Fprintf(out, "      %s: not yet available in v3\n", agent)
			}
		}
	}
	if v.agentHome != "" {
		a.importClaudeHistory(v.agentHome)
	}
}

// unboundSecrets are the store's secrets (only those without a binding when unbound is set).
func (a *app) unboundSecrets(unbound bool) []string {
	st := secrets.Store{Dir: a.secretsDir()}
	ents, _ := os.ReadDir(st.Dir)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") || !e.Type().IsRegular() || secrets.ValidateName(e.Name()) != nil {
			continue
		}
		if unbound {
			if b, err := st.Binding(e.Name()); err != nil || len(b.Hosts) > 0 || b.Readable {
				continue
			}
		}
		out = append(out, e.Name())
	}
	return out
}

// v2Session is what the import reads of a v2 session record.
type v2Session struct {
	Agent          string   `json:"agent"`
	Tier           any      `json:"tier"`
	Repos          []string `json:"repos"`
	AgentSessionID string   `json:"agent_session_id"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// historyKey is v3's repository-set key (the CLI's historyKey over the VM copies' IDs).
func historyKey(repos []string) (string, bool) {
	var ids []string
	for _, r := range repos {
		if st, err := os.Stat(r); err != nil || !st.IsDir() {
			return "", false
		}
		id, err := syncgate.RepoID(r)
		if err != nil {
			return "", false
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return "", false
	}
	if len(ids) == 1 {
		return ids[0], true
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return hex.EncodeToString(h[:16]), true
}

// importClaudeHistory adds Claude Code's v2 conversations to v3's history: each transcript
// (projects/-workspace/<session>.jsonl, and its <session>/ directory) whose v2 session record
// names a tier above 1 and repositories that are on this machine, into that tier and repository
// set. The rest stays in v2's agent home.
func (a *app) importClaudeHistory(agentHome string) {
	proj := filepath.Join(agentHome, "claude", "projects", "-workspace")
	if _, err := os.Stat(proj); err != nil {
		return
	}
	type dest struct {
		tier int
		key  string
	}
	where := map[string]dest{}
	logs, _ := filepath.Glob(filepath.Join(a.env.StateDir, "logs", "*", "session.json"))
	for _, l := range logs {
		b, err := os.ReadFile(l)
		if err != nil {
			continue
		}
		var s v2Session
		if json.Unmarshal(b, &s) != nil || s.Agent != "claude" || !uuidRE.MatchString(s.AgentSessionID) {
			continue
		}
		tier, _ := strconv.Atoi(strings.Trim(fmt.Sprint(s.Tier), `"`))
		if tier < 2 || tier > 3 {
			continue
		}
		if key, ok := historyKey(s.Repos); ok {
			where[s.AgentSessionID] = dest{tier, key}
		}
	}
	files, _ := filepath.Glob(filepath.Join(proj, "*.jsonl"))
	groups := map[dest][]string{}
	left := 0
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		d, ok := where[id]
		if !ok {
			left++
			continue
		}
		groups[d] = append(groups[d], id)
	}
	if len(groups) == 0 {
		if left > 0 {
			fmt.Fprintf(a.env.Stdout, "    Claude Code's %d v2 conversation(s) stay in ~/.sandbox/agent-home (tier 1, or repositories not on this machine).\n", left)
		}
		return
	}
	st, err := a.env.Driver.Status(a.ctx)
	if err != nil || st != driver.Running {
		fmt.Fprintln(a.env.Stdout, "    Claude Code's v2 conversations are imported once the sandbox VM runs: sandbox migrate")
		return
	}
	ep := a.running()
	fmt.Fprintln(a.env.Stdout, "==> Importing Claude Code's v2 conversations into v3's per-tier, per-repository history")
	imported := 0
	for d, ids := range groups {
		var buf bytes.Buffer
		if err := tarHistory(&buf, proj, ids); err != nil {
			a.die("%v", err)
		}
		var errb strings.Builder
		var outb bytes.Buffer
		rc, err := a.env.Transport.Run(a.ctx, ep, []string{VMCommand, ImportHistory, "claude", strconv.Itoa(d.tier), d.key}, &buf, &outb, &errb, false)
		if err == nil && rc != 0 {
			err = fmt.Errorf("%s", strings.TrimSpace(errb.String()))
		}
		if err != nil {
			fmt.Fprintf(a.env.Stderr, "WARNING: could not import %d conversation(s) for tier %d: %v\n", len(ids), d.tier, err)
			continue
		}
		imported += len(ids)
	}
	fmt.Fprintf(a.env.Stdout, "    %d conversation(s) imported; %d stay in ~/.sandbox/agent-home (tier 1, or repositories not on this machine).\n", imported, left)
}

// tarHistory writes the transcripts ids of dir (each <id>.jsonl and its <id>/ tree) as a tar
// under -workspace/, regular files and directories only.
func tarHistory(w io.Writer, dir string, ids []string) error {
	tw := tar.NewWriter(w)
	add := func(p string, fi os.FileInfo) error {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		name := "-workspace/" + filepath.ToSlash(rel)
		switch {
		case fi.IsDir():
			return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700})
		case fi.Mode().IsRegular():
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: fi.Size()}); err != nil {
				return err
			}
			_, err = io.Copy(tw, io.LimitReader(f, fi.Size()))
			return err
		}
		return nil // links and the rest are not history
	}
	for _, id := range ids {
		if fi, err := os.Lstat(filepath.Join(dir, id+".jsonl")); err == nil {
			if err := add(filepath.Join(dir, id+".jsonl"), fi); err != nil {
				return err
			}
		}
		sub := filepath.Join(dir, id)
		if fi, err := os.Lstat(sub); err == nil && fi.IsDir() {
			err := filepath.Walk(sub, func(p string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				return add(p, fi)
			})
			if err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

// removeV2 removes v2 after a confirmation: its Lima VM, and its agent homes, archived to
// ~/.sandbox/v2-archive without their login tokens. v2's cluster on Linux is removed by v2's own
// uninstall.sh.
func (a *app) removeV2(v v2Install, yes bool) {
	out := a.env.Stdout
	var what []string
	if v.limaVM {
		what = append(what, "delete the Lima VM "+V2LimaInstance+" (v2's cluster and anything left in it)")
	}
	if v.agentHome != "" {
		what = append(what, "move ~/.sandbox/agent-home to ~/.sandbox/v2-archive/ after deleting its login tokens")
	}
	if len(what) == 0 && !v.k3s {
		return
	}
	if len(what) > 0 {
		fmt.Fprintf(out, "==> Removing v2 will %s.\n", strings.Join(what, ", and "))
		fmt.Fprintln(out, "    v2's sandbox command stops working; v3 is unaffected.")
		if !yes {
			if !a.env.StdinTTY {
				a.die("not removing v2 without a terminal to confirm on; add --yes to remove it anyway.")
			}
			fmt.Fprint(out, "    Remove v2? [y/N] ")
			reply, _ := bufio.NewReader(a.env.Stdin).ReadString('\n')
			if r := strings.TrimSpace(reply); r != "y" && r != "Y" && r != "yes" {
				fmt.Fprintln(out, "    v2 kept.")
				return
			}
		}
	}
	if v.limaVM {
		d := a.migrationDeps()
		if _, err := d.Limactl(a.ctx, "delete", "--force", V2LimaInstance); err != nil {
			a.die("could not delete the Lima VM %s: %v", V2LimaInstance, err)
		}
		fmt.Fprintf(out, "    Deleted the Lima VM %s.\n", V2LimaInstance)
	}
	if v.agentHome != "" {
		for agent, files := range v2TokenFiles {
			for _, f := range files {
				os.Remove(filepath.Join(v.agentHome, agent, f))
			}
		}
		archive := filepath.Join(a.env.StateDir, "v2-archive")
		if err := os.MkdirAll(archive, 0o700); err != nil {
			a.die("%v", err)
		}
		dst := filepath.Join(archive, "agent-home")
		if _, err := os.Lstat(dst); err == nil {
			dst += "-" + a.env.Now().UTC().Format("20060102T150405")
		}
		if err := os.Rename(v.agentHome, dst); err != nil {
			a.die("could not archive ~/.sandbox/agent-home: %v", err)
		}
		for _, f := range []string{"lima-sandbox-vm.yaml", "kubeconfig", "infra-versions"} {
			if _, err := os.Lstat(filepath.Join(a.env.StateDir, f)); err == nil {
				os.Rename(filepath.Join(a.env.StateDir, f), filepath.Join(archive, f))
			}
		}
		fmt.Fprintf(out, "    Archived v2's agent homes (without their login tokens) in %s.\n", a.tildeHome(dst))
	}
	if v.k3s {
		fmt.Fprintln(out, "    v2's cluster (k3s, Cilium, gVisor) is installed on this machine; remove it with uninstall.sh from your v2 checkout.")
	}
}

// tildeHome shows a path under the operator's home with ~.
func (a *app) tildeHome(p string) string {
	if h := a.env.Home; h != "" && strings.HasPrefix(p, h+"/") {
		return "~" + p[len(h):]
	}
	return p
}
