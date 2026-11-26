package daemon

// Readable secrets (design 5.9.3, `--allow-readable`; owner decision, eighth round). The one
// audited exception to "no credential readable in the guest" is delivered without the value
// passing through sandboxd or containerd: the broker's short-lived helper writes each value to a
// file in the session's directory on a tmpfs (ReadableRoot), which is mounted read-only into the
// agent's microVM at sessionspec.ReadableDir. The agent's environment names each file
// (<VAR>_FILE), and an attached command runs under a shell wrapper that exports <VAR> from it
// first; an image without /bin/sh gets the file only.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

func (d *Daemon) readableDir(id string) string { return filepath.Join(d.ReadableRoot, id) }

// readableSecrets writes spec's readable secrets for its agent and returns their mount and the
// environment that names their files.
func (d *Daemon) readableSecrets(ctx context.Context, spec *sessionspec.Spec) (runtime.Mount, []string, error) {
	id := spec.ID
	if d.Broker == nil || d.ReadableRoot == "" {
		return runtime.Mount{}, nil, errors.New("the session has readable secrets, but sandboxd has no broker store or tmpfs for them")
	}
	dir := d.readableDir(id)
	if err := d.step(id, KindReadable, "readable", func() error {
		if err := os.MkdirAll(d.ReadableRoot, 0o711); err != nil {
			return err
		}
		return os.Mkdir(dir, 0o700)
	}); err != nil {
		return runtime.Mount{}, nil, err
	}
	files := map[string]string{}
	var env []string
	for _, r := range spec.Readable {
		files[r.EnvVar] = r.Ref
		env = append(env, r.EnvVar+"_FILE="+sessionspec.ReadableDir+"/"+r.EnvVar)
	}
	if err := d.Broker.WriteReadable(ctx, dir, AgentUID, files); err != nil {
		return runtime.Mount{}, nil, fmt.Errorf("readable secrets: %w", err)
	}
	for _, r := range spec.Readable {
		d.audit(id, auditlog.Events, "secret_readable", map[string]any{"ref": r.Ref, "env_var": r.EnvVar})
	}
	return runtime.Mount{Source: dir, Target: sessionspec.ReadableDir, ReadOnly: true}, env, nil
}

// Shell is the wrapper's shell in the agent's image.
const Shell = "/bin/sh"

// readableWrap is args under a shell that first exports each variable from its file, byte for
// byte (a command substitution drops trailing newlines, so a sentinel keeps them). A file that
// cannot be read stops the command before it runs. names are checked variable names
// (sessionspec), so they need no quoting.
func readableWrap(names []string, args []string) []string {
	var b strings.Builder
	for _, n := range names {
		f := sessionspec.ReadableDir + "/" + n
		fmt.Fprintf(&b, "%s=$(cat %s && printf x) || { echo 'sandbox: cannot read the readable secret %s' >&2; exit 126; }; %s=${%s%%x}; export %s; ",
			n, f, n, n, n, n)
	}
	b.WriteString(`exec "$@"`)
	return append([]string{Shell, "-c", b.String(), "sh"}, args...)
}

// noShell is whether an exec failed because the image has no shell to run.
func noShell(err error) bool {
	s := err.Error()
	return strings.Contains(s, Shell) && (strings.Contains(s, "no such file") || strings.Contains(s, "not found"))
}
