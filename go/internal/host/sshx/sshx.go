// Package sshx is the host binary's transport into the VM (design 5.2.1): the system OpenSSH
// client, run with a pinned host key and every option that could widen the connection set on the
// command line. Using the system client keeps the module free of third-party dependencies and
// gives TTY handling, window-size changes, and signal forwarding (in a terminal, Ctrl-C reaches
// the remote process) on all three host OSes.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// HostKeyAlias names the VM in the pinned known_hosts file, whatever port Lima forwards.
const HostKeyAlias = "sandbox-vm"

// Client runs commands in the VM.
type Client struct {
	SSH        string // the ssh binary
	Identity   string // the per-install client private key
	KnownHosts string // written from the endpoint's pinned key before each connection
}

// DefaultSSH is the OS's own client when it is there, otherwise ssh from PATH.
func DefaultSSH() (string, error) {
	for _, p := range []string{"/usr/bin/ssh", `C:\Windows\System32\OpenSSH\ssh.exe`} {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	p, err := exec.LookPath("ssh")
	if err != nil {
		return "", errors.New("no ssh client found (install OpenSSH)")
	}
	return filepath.Abs(p)
}

// Quote is one argument for the remote POSIX shell: single quotes, each embedded quote closed,
// escaped, and reopened. The VM's root login shell is sh-compatible.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Command is the remote command line for argv.
func Command(argv []string) (string, error) {
	q := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsRune(a, 0) {
			return "", errors.New("an argument holds a NUL byte")
		}
		q[i] = Quote(a)
	}
	return strings.Join(q, " "), nil
}

func validKey(k string) bool {
	f := strings.Fields(k)
	return len(f) >= 2 && strings.HasPrefix(f[0], "ssh-") || len(f) >= 2 && strings.HasPrefix(f[0], "ecdsa-")
}

// pin writes the known_hosts file for ep: the alias and the pinned key, nothing else. Many
// connections start at once (a session's sync has one per repository), each with its own ssh
// reading the file, so the file is never rewritten in place: a reader that caught it truncated
// saw no key, failed host key verification, and exited 255 like a dropped connection. It is
// left alone when it already holds the key, and otherwise replaced whole by a rename. Writers are
// serialized in this process. On Windows a rename over a file another process has open is refused,
// so it is tried again for a while; an ssh opening the file during the rename itself can still
// fail there, which happens only when the pinned key changes (a VM reinstall).
func (c *Client) pin(ep driver.SSHEndpoint) error {
	if !validKey(ep.HostKey) || strings.ContainsAny(ep.HostKey, "\r\n") {
		return errors.New("the VM has no valid pinned host key")
	}
	f := strings.Fields(ep.HostKey)
	want := HostKeyAlias + " " + f[0] + " " + f[1] + "\n"
	if b, err := os.ReadFile(c.KnownHosts); err == nil && string(b) == want {
		return nil
	}
	pinMu.Lock()
	defer pinMu.Unlock()
	if b, err := os.ReadFile(c.KnownHosts); err == nil && string(b) == want {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.KnownHosts), ".known_hosts-*") // mode 0600
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(want); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	err = os.Rename(tmp.Name(), c.KnownHosts)
	for wait := time.Millisecond; err != nil && runtime.GOOS == "windows" && wait < 2*time.Second; wait *= 2 {
		time.Sleep(wait) // a reader has the file open
		err = os.Rename(tmp.Name(), c.KnownHosts)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// pinMu serializes pin's writes.
var pinMu sync.Mutex

// Args is the ssh command line for ep: tty forces a terminal (-tt) or refuses one (-T), and remote
// is the already-quoted command ("" for a login shell).
func (c *Client) Args(ep driver.SSHEndpoint, tty bool, remote string) ([]string, error) {
	if ep.Port <= 0 || ep.Port > 65535 || ep.Host == "" || ep.User == "" ||
		strings.HasPrefix(ep.Host, "-") || strings.HasPrefix(ep.User, "-") {
		return nil, fmt.Errorf("invalid SSH endpoint %+v", ep)
	}
	opts := []string{
		"StrictHostKeyChecking=yes", "UserKnownHostsFile=" + c.KnownHosts, "GlobalKnownHostsFile=" + os.DevNull,
		"HostKeyAlias=" + HostKeyAlias, "CheckHostIP=no", "UpdateHostKeys=no",
		"IdentityFile=" + c.Identity, "IdentitiesOnly=yes", "IdentityAgent=none",
		"PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
		"BatchMode=yes", "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes", "Tunnel=no",
		"PermitLocalCommand=no", "ControlMaster=no", "ControlPath=none", "ProxyCommand=none",
		"ServerAliveInterval=15", "ServerAliveCountMax=4", "LogLevel=ERROR",
	}
	args := []string{"-F", os.DevNull}
	for _, o := range opts {
		args = append(args, "-o", o)
	}
	if tty {
		args = append(args, "-tt")
	} else {
		args = append(args, "-T")
	}
	args = append(args, "-p", strconv.Itoa(ep.Port), "-l", ep.User, ep.Host)
	if remote != "" {
		args = append(args, "--", remote)
	}
	return args, nil
}

// ErrTransport marks a failure of ssh itself (exit 255), as opposed to the remote command's exit.
var ErrTransport = errors.New("ssh connection failed")

func (c *Client) command(ctx context.Context, ep driver.SSHEndpoint, argv []string, tty bool) (*exec.Cmd, error) {
	if err := c.pin(ep); err != nil {
		return nil, err
	}
	remote, err := Command(argv)
	if err != nil {
		return nil, err
	}
	args, err := c.Args(ep, tty, remote)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, c.SSH, args...)
	// No SSH_AUTH_SOCK or similar reaches ssh: IdentityAgent=none already ignores it, and the
	// environment is cut down to what ssh needs to run.
	cmd.Env = minimalEnv()
	cmd.WaitDelay = 2 * time.Second // ssh's own output pipes, should a child keep them open
	return cmd, nil
}

func minimalEnv() []string {
	keep := []string{"HOME", "USER", "LOGNAME", "PATH", "TERM", "SystemRoot", "USERPROFILE", "TMPDIR", "TMP", "TEMP"}
	var env []string
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if runtime.GOOS != "windows" {
		env = append(env, "LC_ALL=C") // SendEnv is off with -F /dev/null; this only affects ssh's own messages
	}
	return env
}

// Run implements app.Transport.
func (c *Client) Run(ctx context.Context, ep driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) (int, error) {
	cmd, err := c.command(ctx, ep, argv, tty)
	if err != nil {
		return 1, err
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if f, ok := stdin.(*os.File); ok || stdin == nil {
		cmd.Stdin = f
		if stdin == nil {
			cmd.Stdin = nil
		}
		err = cmd.Run()
	} else {
		// os/exec's Wait would wait for its own stdin copy, which blocks for as long as the
		// caller's reader does (a long-lived pipe): copy here instead, so Run returns when ssh
		// ends; the copy ends when the caller closes its reader.
		var w io.WriteCloser
		if w, err = cmd.StdinPipe(); err == nil {
			if err = cmd.Start(); err == nil {
				go func() {
					io.Copy(w, stdin)
					w.Close()
				}()
				err = cmd.Wait()
			}
		}
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee) && ee.ExitCode() == 255:
		return 255, ErrTransport
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode(), nil
	}
	return 1, err
}

// Output implements app.Transport: stdout, at most max bytes; stderr is kept for the error.
func (c *Client) Output(ctx context.Context, ep driver.SSHEndpoint, argv []string, max int) ([]byte, error) {
	cmd, err := c.command(ctx, ep, argv, false)
	if err != nil {
		return nil, err
	}
	out := &capped{max: max}
	errb := capped{max: 4096}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, out, &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 255 {
			return nil, fmt.Errorf("%w: %s", ErrTransport, strings.TrimSpace(errb.buf.String()))
		}
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.buf.String()))
	}
	if out.over {
		return nil, fmt.Errorf("output larger than %d bytes", max)
	}
	return out.buf.Bytes(), nil
}

// capped keeps at most max bytes and notes whether more came. The buffer is a field, not
// embedded: an embedded bytes.Buffer would give capped a ReadFrom method, which io.Copy (and so
// os/exec) calls instead of Write, bypassing the cap.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		if room > 0 {
			c.buf.Write(p[:room])
		}
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}
