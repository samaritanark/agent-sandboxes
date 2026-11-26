package app

// The host's pre-pass before `sandbox run` (design 5.1.4, owner decision, eighth round): the host
// asks the VM which of the operator's secrets the launch binds, shows the operator the names,
// refuses a name that neither the command line nor the profile files the host pushed mention,
// and seals and pushes the rest into the VM's broker store. The host keeps no policy: the VM
// decides which secrets a launch binds; the host only refuses to hand over one the operator did
// not name, so a compromised VM cannot ask for the whole store.

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/secrets"
)

// RunBindings is the in-VM pre-pass: `sandbox __run-bindings ARGS` prints the launch's secret
// names as {"secrets":[...]}, or nothing (with a failure status) when run would stop first.
const RunBindings = "__run-bindings"

// Limits on the pre-pass.
const (
	maxBindingsOutput = 16 << 10
	maxBoundSecrets   = 64
	// MaxSecretSize bounds one pushed secret, as __broker-put does.
	MaxSecretSize = 64 << 10
)

// secretName is v2's secret name rule (lib/secrets.sh): also the variable the agent sees.
var secretName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// maxRepos bounds the repositories one launch syncs.
const maxRepos = 16

// parseRunBindings reads the pre-pass's output strictly: one JSON object with exactly the secrets
// and repos fields; valid secret names, no more than maxBoundSecrets, no duplicates; clean
// absolute repository paths, no more than maxRepos, no duplicates.
func parseRunBindings(b []byte) (names, repos []string, err error) {
	p, err := parsePrepass(b)
	return p.Secrets, p.Repos, err
}

// prepass is the VM's answer to the pre-pass (cli.Prepass).
type prepass struct {
	Secrets, Repos []string
	InfraTokens    []infraToken
	InfraHosts     []string
	// OpencodeBaseURL is set for an opencode launch: the endpoint its key goes to.
	OpencodeBaseURL string
}

// infraToken is one --infra-token the VM says the launch fills: its variable and its file on the
// host.
type infraToken struct {
	Env  string `json:"env"`
	Path string `json:"path"`
}

// infraEnv is an infra token's variable: INFRA_TOKEN, or INFRA_TOKEN_<NAME> (v2's naming).
var infraEnv = regexp.MustCompile(`^INFRA_TOKEN(_[A-Za-z_][A-Za-z0-9_]{0,63})?$`)

// hostName is a destination host as the pre-pass gives it: lower-case DNS labels.
var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// maxInfra bounds a launch's infra tokens and their hosts.
const maxInfra = 16

// parsePrepass is parseRunBindings with the infra tokens and their hosts (optional fields): clean
// absolute token paths, v2's variable names, no repeats, at most maxInfra of each.
func parsePrepass(b []byte) (prepass, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out struct {
		Secrets     *[]string    `json:"secrets"`
		Repos       *[]string    `json:"repos"`
		InfraTokens []infraToken `json:"infra_tokens"`
		InfraHosts  []string     `json:"infra_hosts"`
		Opencode    string       `json:"opencode_base_url"`
	}
	fail := func(e error) (prepass, error) { return prepass{}, e }
	if err := dec.Decode(&out); err != nil {
		return fail(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail(errors.New("trailing data"))
	}
	if out.Secrets == nil || out.Repos == nil {
		return fail(errors.New("a field is missing"))
	}
	names, repos := *out.Secrets, *out.Repos
	if len(names) > maxBoundSecrets {
		return fail(fmt.Errorf("%d secrets, more than %d", len(names), maxBoundSecrets))
	}
	if len(repos) > maxRepos {
		return fail(fmt.Errorf("%d repositories, more than %d", len(repos), maxRepos))
	}
	if len(out.InfraTokens) > maxInfra || len(out.InfraHosts) > maxInfra {
		return fail(fmt.Errorf("more than %d infra tokens or hosts", maxInfra))
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !secretName.MatchString(n) {
			return fail(fmt.Errorf("%q is not a secret name", n))
		}
		if seen[n] {
			return fail(fmt.Errorf("%s named twice", n))
		}
		seen[n] = true
	}
	for _, r := range repos {
		if !strings.HasPrefix(r, "/") || path.Clean(r) != r || r == "/" || strings.ContainsAny(r, "\x00\n") {
			return fail(fmt.Errorf("%q is not a clean absolute path", r))
		}
		if seen["\x00"+r] {
			return fail(fmt.Errorf("%s named twice", r))
		}
		seen["\x00"+r] = true
	}
	for _, t := range out.InfraTokens {
		if !infraEnv.MatchString(t.Env) || seen["\x01"+t.Env] {
			return fail(fmt.Errorf("%q is not an infra token variable, or is repeated", t.Env))
		}
		seen["\x01"+t.Env] = true
		if !strings.HasPrefix(t.Path, "/") || path.Clean(t.Path) != t.Path || strings.ContainsAny(t.Path, "\x00\n") {
			return fail(fmt.Errorf("%q is not a clean absolute path", t.Path))
		}
	}
	for _, h := range out.InfraHosts {
		if !hostName.MatchString(h) || len(h) > 253 || seen["\x02"+h] {
			return fail(fmt.Errorf("%q is not a host name, or is repeated", h))
		}
		seen["\x02"+h] = true
	}
	if len(out.Opencode) > 2048 || strings.ContainsAny(out.Opencode, "\x00\n\r") {
		return fail(errors.New("not a URL for opencode"))
	}
	return prepass{Secrets: names, Repos: repos, InfraTokens: out.InfraTokens, InfraHosts: out.InfraHosts, OpencodeBaseURL: out.Opencode}, nil
}

// words are the identifier-like words in b: a secret name is mentioned only as a whole word.
func words(b []byte, into map[string]bool) {
	for _, w := range strings.FieldsFunc(string(b), func(r rune) bool {
		return !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		into[w] = true
	}
}

// profileTexts are config.yaml and the profile files in the operator state the host pushed: with
// the command line, the only places a launch's secrets and repositories can come from.
func profileTexts(archive []byte) ([][]byte, error) {
	var out [][]byte
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Name != "config.yaml" && !strings.HasPrefix(h.Name, "profiles/") {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
}

// mentioned is every word of the command line and of the profile texts.
func mentioned(args []string, texts [][]byte) map[string]bool {
	m := map[string]bool{}
	for _, a := range args {
		words([]byte(a), m)
	}
	for _, b := range texts {
		words(b, m)
	}
	return m
}

// repoValues are the values of run's --repo options in args (both spellings).
func repoValues(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--repo" && i+1 < len(args):
			out = append(out, args[i+1])
			i++
		case strings.HasPrefix(a, "--repo="):
			out = append(out, a[len("--repo="):])
		}
	}
	return out
}

// absRepos makes run's relative --repo (and --infra-token) values absolute against the host's working directory
// (design 5.1.1 item 3): the VM cannot resolve them. "~" stays for the VM, which expands it
// against the mirrored home.
func absRepos(args []string, wd string) []string {
	out := append([]string(nil), args...)
	fix := func(v string) string {
		if v == "" || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") {
			return v
		}
		return filepath.Join(wd, v)
	}
	// an --infra-token's path follows its NAME= when it has one
	token := func(v string) string {
		if i := strings.Index(v, "="); i >= 0 && envNameRE.MatchString(v[:i]) {
			return v[:i+1] + fix(v[i+1:])
		}
		return fix(v)
	}
	for i := 0; i < len(out); i++ {
		switch a := out[i]; {
		case a == "--repo" && i+1 < len(out):
			out[i+1] = fix(out[i+1])
			i++
		case strings.HasPrefix(a, "--repo="):
			out[i] = "--repo=" + fix(a[len("--repo="):])
		case a == "--infra-token" && i+1 < len(out):
			out[i+1] = token(out[i+1])
			i++
		case strings.HasPrefix(a, "--infra-token="):
			out[i] = "--infra-token=" + token(a[len("--infra-token="):])
		}
	}
	return out
}

// repoNamed is whether repository path p comes from the command line or a profile: a --repo value
// (with "~" as the operator's home), or a profile text holding p or its "~/" form.
func repoNamed(p string, args []string, texts [][]byte, home string) bool {
	for _, v := range repoValues(args) {
		if home != "" && (v == "~" || strings.HasPrefix(v, "~/")) {
			v = home + v[1:]
		}
		if path.Clean(v) == p {
			return true
		}
	}
	forms := []string{p}
	if home != "" && strings.HasPrefix(p, home+"/") {
		forms = append(forms, "~"+p[len(home):])
	}
	for _, b := range texts {
		for _, f := range forms {
			if bytes.Contains(b, []byte(f)) {
				return true
			}
		}
	}
	return false
}

// secretsDir is the host-side store (SANDBOX_SECRETS_DIR, as v2).
func (a *app) secretsDir() string {
	if a.env.SecretsDir != "" {
		return a.env.SecretsDir
	}
	return filepath.Join(a.env.StateDir, "secrets")
}

// readSecret reads one secret from the store, following a symlink as v2's store does. absent is
// true when the store has no such secret.
func (a *app) readSecret(name string) (v []byte, absent bool, err error) {
	p := filepath.Join(a.secretsDir(), name)
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("~/.sandbox/secrets/%s is not a regular file", name)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	v, err = io.ReadAll(io.LimitReader(f, MaxSecretSize+1))
	if err == nil && len(v) > MaxSecretSize {
		brokerseal.Wipe(v)
		return nil, false, fmt.Errorf("~/.sandbox/secrets/%s is larger than %d bytes", name, MaxSecretSize)
	}
	return v, false, err
}

// prepareRun runs the pre-pass for `sandbox run args` and prepares what it names: it pushes the
// secrets, and syncs each repository and mirrors its host path to the VM copy. A secret missing
// from the host store is removed from the VM's, so the run stops with v2's message instead of
// binding a stale copy. When the pre-pass fails, nothing is pushed or synced: the run that follows
// stops the same way and says why.
func (a *app) prepareRun(ep driver.SSHEndpoint, args []string, archive []byte) (synced []string, opencodeConfig string) {
	out, err := a.env.Transport.Output(a.ctx, ep, a.vmArgv(append([]string{RunBindings}, args...)...), maxBindingsOutput)
	if err != nil {
		return nil, ""
	}
	pp, err := parsePrepass(out)
	names, repos, tokens, infraHosts := pp.Secrets, pp.Repos, pp.InfraTokens, pp.InfraHosts
	if err != nil {
		a.die("the sandbox VM's list of secrets and repositories for this launch is invalid (%v); nothing was pushed.", err)
	}
	texts, err := profileTexts(archive)
	if err != nil {
		a.die("cannot read the operator state: %v", err)
	}
	m := mentioned(args, texts)
	for _, n := range names {
		if !m[n] {
			a.die("the sandbox VM asked for secret '%s', which neither this command line nor your profiles in ~/.sandbox/profiles name.\n"+
				"  Nothing was pushed. If you did not expect this, the sandbox VM may be compromised: see 'sandbox doctor'.", n)
		}
	}
	for _, r := range repos {
		if !repoNamed(r, args, texts, a.mirrorHome()) {
			a.die("the sandbox VM asked to sync %s, which neither this command line nor your profiles in ~/.sandbox/profiles name.\n"+
				"  Nothing was synced. If you did not expect this, the sandbox VM may be compromised: see 'sandbox doctor'.", r)
		}
	}
	for _, t := range tokens {
		if !infraTokenNamed(t, args, a.mirrorHome()) {
			a.die("the sandbox VM asked for infra token %s from %s, which this command line does not name.\n"+
				"  Nothing was pushed. If you did not expect this, the sandbox VM may be compromised: see 'sandbox doctor'.", t.Env, t.Path)
		}
	}
	for _, h := range infraHosts {
		if !infraHostNamed(h, args) {
			a.die("the sandbox VM asked to bind infra tokens to %s, which no --infra-endpoint on this command line names.\n"+
				"  Nothing was pushed. If you did not expect this, the sandbox VM may be compromised: see 'sandbox doctor'.", h)
		}
	}
	a.pushSecrets(ep, names)
	a.pushInfraTokens(ep, tokens, infraHosts)
	if pp.OpencodeBaseURL != "" {
		opencodeConfig = a.prepareOpencode(ep, pp.OpencodeBaseURL, args)
	}
	for _, r := range repos {
		fmt.Fprintf(a.env.Stdout, "==> Syncing %s into the sandbox VM...\n", r)
		ws, rep, err := a.syncRepo(ep, r)
		if err != nil {
			a.die("%v", err)
		}
		if n := len(rep.Quarantined) + len(rep.Conflicts); n > 0 {
			fmt.Fprintf(a.env.Stdout, "    %d change(s) withheld or in conflict; see: sandbox sync review\n", n)
		}
		if a.mirrorHome() != "" {
			if err := a.vmRun(ep, MirrorPath, r, ws); err != nil {
				a.die("could not make %s the sandbox VM's path to its copy: %v", r, err)
			}
		}
		synced = append(synced, r)
	}
	return synced, opencodeConfig
}

// pushSecrets seals and pushes the named secrets from the host store, each with its binding.
func (a *app) pushSecrets(ep driver.SSHEndpoint, names []string) {
	if len(names) == 0 {
		return
	}
	if a.env.BrokerKey == nil {
		a.die("this launch binds secrets (%s), but this host has no place to keep the credential broker's key.", strings.Join(names, " "))
	}
	fmt.Fprintf(a.env.Stdout, "==> Sealing this launch's secrets for the sandbox VM: %s\n", strings.Join(names, " "))
	k, err := a.brokerKey()
	if err != nil {
		a.die("%v", err)
	}
	defer brokerseal.Wipe(k)
	for _, n := range names {
		ref := brokerseal.SecretRef(n)
		v, absent, err := a.readSecret(n)
		if err != nil {
			a.die("%v", err)
		}
		if absent {
			if err := a.sandboxd(ep, strings.NewReader(""), "broker-delete", ref); err != nil {
				a.die("could not remove %s from the sandbox VM: %v", n, err)
			}
			continue
		}
		// the binding goes with the value, sealed with it, so the VM can use the value only as bound
		b, err := secrets.Store{Dir: a.secretsDir()}.Binding(n)
		if err != nil {
			brokerseal.Wipe(v)
			a.die("the binding of secret '%s': %v", n, err)
		}
		sealed, err := brokerseal.SealBound(k, ref, v, b)
		brokerseal.Wipe(v)
		if err != nil {
			a.die("%v", err)
		}
		if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", ref); err != nil {
			a.die("could not store %s in the sandbox VM: %v", n, err)
		}
	}
}

// MirrorPath is the in-VM command that links a host path to its VM counterpart.
const MirrorPath = "__mirror-path"

// mirrorHome is the operator's home as the VM mirrors it, or "" when it cannot be mirrored (not a
// clean absolute POSIX path, as on Windows): then proxied commands keep the VM's own HOME.
func (a *app) mirrorHome() string {
	h := a.env.Home
	if h == "" || !strings.HasPrefix(h, "/") || path.Clean(h) != h || h == "/" {
		return ""
	}
	return h
}

// vmArgv is an in-VM CLI command line, run with HOME set to the mirrored home.
func (a *app) vmArgv(args ...string) []string {
	return a.vmArgvEnv(nil, args...)
}

// forwarded are the host environment variables proxied commands get (not secrets: opencode's
// endpoint, which run reads as v2 did).
var forwarded = []string{"OPENCODE_BASE_URL"}

// vmArgvEnv is vmArgv with extra NAME=VALUE settings.
func (a *app) vmArgvEnv(extra []string, args ...string) []string {
	env := []string{}
	if h := a.mirrorHome(); h != "" {
		env = append(env, "HOME="+h)
	}
	for _, k := range forwarded {
		if v := a.getenv(k); v != "" && len(v) <= 2048 && !strings.ContainsAny(v, "\x00\n\r") {
			env = append(env, k+"="+v)
		}
	}
	env = append(env, extra...)
	if len(env) == 0 {
		return append([]string{VMCommand}, args...)
	}
	return append(append(append([]string{"env"}, env...), VMCommand), args...)
}

// vmRun runs an in-VM CLI helper with no input and fails with its stderr.
func (a *app) vmRun(ep driver.SSHEndpoint, args ...string) error {
	var errb strings.Builder
	rc, err := a.env.Transport.Run(a.ctx, ep, append([]string{VMCommand}, args...), strings.NewReader(""), io.Discard, &errb, false)
	if err == nil && rc != 0 {
		err = errors.New(strings.TrimSpace(errb.String()))
	}
	return err
}

// optionValues are the values of option flag in args (both spellings).
func optionValues(args []string, flag string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == flag && i+1 < len(args):
			out = append(out, args[i+1])
			i++
		case strings.HasPrefix(a, flag+"="):
			out = append(out, a[len(flag)+1:])
		}
	}
	return out
}

// infraTokenNamed is whether an --infra-token on the command line is t: a bare PATH for
// INFRA_TOKEN, or NAME=PATH for INFRA_TOKEN_NAME, with "~" as the operator's home.
func infraTokenNamed(t infraToken, args []string, home string) bool {
	for _, v := range optionValues(args, "--infra-token") {
		env, p := "INFRA_TOKEN", v
		if i := strings.Index(v, "="); i >= 0 && envNameRE.MatchString(v[:i]) {
			env, p = "INFRA_TOKEN_"+v[:i], v[i+1:]
		}
		if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
			p = home + p[1:]
		}
		if env == t.Env && path.Clean(p) == t.Path {
			return true
		}
	}
	return false
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// infraHostNamed is whether an --infra-endpoint on the command line has host h.
func infraHostNamed(h string, args []string) bool {
	for _, v := range optionValues(args, "--infra-endpoint") {
		r := v
		if i := strings.Index(r, "://"); i >= 0 {
			r = r[i+3:]
		}
		if i := strings.IndexAny(r, "/?#"); i >= 0 {
			r = r[:i]
		}
		if i := strings.LastIndex(r, "@"); i >= 0 {
			r = r[i+1:]
		}
		if i := strings.LastIndex(r, ":"); i >= 0 {
			r = r[:i]
		}
		if strings.EqualFold(r, h) {
			return true
		}
	}
	return false
}

// pushInfraTokens seals each infra token from its file, bound as a bearer token to the launch's
// --infra-endpoint hosts (withheld when there are none), and pushes it.
func (a *app) pushInfraTokens(ep driver.SSHEndpoint, tokens []infraToken, hosts []string) {
	if len(tokens) == 0 {
		return
	}
	if a.env.BrokerKey == nil {
		a.die("this launch binds infra tokens, but this host has no place to keep the credential broker's key.")
	}
	var envs []string
	for _, t := range tokens {
		envs = append(envs, t.Env)
	}
	fmt.Fprintf(a.env.Stdout, "==> Sealing this launch's infra tokens for the sandbox VM: %s\n", strings.Join(envs, " "))
	k, err := a.brokerKey()
	if err != nil {
		a.die("%v", err)
	}
	defer brokerseal.Wipe(k)
	b := brokerseal.Binding{}
	if len(hosts) > 0 {
		b = brokerseal.Binding{Hosts: hosts, Inject: "bearer"}
	}
	for _, t := range tokens {
		v, err := readLimited(t.Path)
		if err != nil {
			a.die("infra token %s: %v", t.Path, err)
		}
		ref := "infra." + t.Env
		sealed, err := brokerseal.SealBound(k, ref, []byte(strings.TrimRight(string(v), "\r\n")), b)
		brokerseal.Wipe(v)
		if err != nil {
			a.die("%v", err)
		}
		if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", ref); err != nil {
			a.die("could not store infra token %s in the sandbox VM: %v", t.Env, err)
		}
	}
}

// readLimited reads a regular file of at most MaxSecretSize bytes, following a link.
func readLimited(p string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := io.ReadAll(io.LimitReader(f, MaxSecretSize+1))
	if err == nil && len(v) > MaxSecretSize {
		brokerseal.Wipe(v)
		return nil, fmt.Errorf("larger than %d bytes", MaxSecretSize)
	}
	return v, err
}
