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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
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

// parseRunBindings reads the pre-pass's output strictly: one JSON object, only the secrets field,
// valid names, no more than maxBoundSecrets, no duplicates.
func parseRunBindings(b []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out struct {
		Secrets *[]string `json:"secrets"`
	}
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	if out.Secrets == nil {
		return nil, errors.New("no secrets field")
	}
	names := *out.Secrets
	if len(names) > maxBoundSecrets {
		return nil, fmt.Errorf("%d secrets, more than %d", len(names), maxBoundSecrets)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !secretName.MatchString(n) {
			return nil, fmt.Errorf("%q is not a secret name", n)
		}
		if seen[n] {
			return nil, fmt.Errorf("%s named twice", n)
		}
		seen[n] = true
	}
	return names, nil
}

// words are the identifier-like words in b: a secret name is mentioned only as a whole word.
func words(b []byte, into map[string]bool) {
	for _, w := range strings.FieldsFunc(string(b), func(r rune) bool {
		return !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		into[w] = true
	}
}

// mentioned is every word of the command line and of the profile files and config.yaml in the
// operator state the host pushed: the only places a launch's secret names can come from.
func mentioned(args []string, archive []byte) (map[string]bool, error) {
	m := map[string]bool{}
	for _, a := range args {
		words([]byte(a), m)
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return m, nil
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
		words(b, m)
	}
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

// pushRunSecrets runs the pre-pass for `sandbox run args` and pushes the secrets it names. A
// secret missing from the host store is removed from the VM's, so the run stops with v2's
// message instead of binding a stale copy. When the pre-pass fails, nothing is pushed: the run
// that follows stops the same way and says why.
func (a *app) pushRunSecrets(ep driver.SSHEndpoint, args []string, archive []byte) {
	out, err := a.env.Transport.Output(a.ctx, ep, append([]string{VMCommand, RunBindings}, args...), maxBindingsOutput)
	if err != nil {
		return
	}
	names, err := parseRunBindings(out)
	if err != nil {
		a.die("the sandbox VM's list of secrets for this launch is invalid (%v); nothing was pushed.", err)
	}
	if len(names) == 0 {
		return
	}
	m, err := mentioned(args, archive)
	if err != nil {
		a.die("cannot read the operator state: %v", err)
	}
	for _, n := range names {
		if !m[n] {
			a.die("the sandbox VM asked for secret '%s', which neither this command line nor your profiles in ~/.sandbox/profiles name.\n"+
				"  Nothing was pushed. If you did not expect this, the sandbox VM may be compromised: see 'sandbox doctor'.", n)
		}
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
		sealed, err := brokerseal.Seal(k, ref, v)
		brokerseal.Wipe(v)
		if err != nil {
			a.die("%v", err)
		}
		if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", ref); err != nil {
			a.die("could not store %s in the sandbox VM: %v", n, err)
		}
	}
}
