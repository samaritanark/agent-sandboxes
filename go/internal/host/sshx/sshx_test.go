package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

var tricky = []string{"", "plain", "a b", "it's", `"dq"`, "$(touch /tmp/pwned)", "`id`", "a\nb", "tab\there", `back\slash`, "*", "~", "-n", "--", ";", "|", "&&", "'", "''", "é"}

func TestQuoteRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	cmd, err := Command(append([]string{"printf", `%s\000`}, tricky...))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", cmd).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if !reflect.DeepEqual(got, tricky) {
		t.Fatalf("round trip:\n got %q\nwant %q", got, tricky)
	}
	if _, err := Command([]string{"a\x00b"}); err == nil {
		t.Error("NUL accepted")
	}
}

var ep = driver.SSHEndpoint{Host: "127.0.0.1", Port: 60022, User: "root", HostKey: "ssh-ed25519 AAAAguest comment"}

func TestArgs(t *testing.T) {
	c := &Client{SSH: "ssh", Identity: "/k/id", KnownHosts: "/k/known_hosts"}
	a, err := c.Args(ep, false, "'sandbox' 'list'")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(a, " ")
	for _, want := range []string{"-F " + os.DevNull, "StrictHostKeyChecking=yes", "UserKnownHostsFile=/k/known_hosts",
		"HostKeyAlias=sandbox-vm", "IdentitiesOnly=yes", "IdentityAgent=none", "ForwardAgent=no", "ClearAllForwardings=yes",
		"BatchMode=yes", "ControlPath=none", " -T ", "-p 60022 -l root 127.0.0.1 -- 'sandbox' 'list'"} {
		if !strings.Contains(s, want) {
			t.Errorf("args lack %q: %s", want, s)
		}
	}
	if a, _ := c.Args(ep, true, ""); a[len(a)-1] != "127.0.0.1" || !strings.Contains(strings.Join(a, " "), " -tt ") {
		t.Errorf("login shell args %q", a)
	}
	for _, bad := range []driver.SSHEndpoint{{Host: "h", Port: 0, User: "u"}, {Host: "-oProxyCommand=x", Port: 22, User: "u"},
		{Host: "h", Port: 22, User: "-u"}, {Host: "", Port: 22, User: "u"}, {Host: "h", Port: 65536, User: "u"}} {
		if _, err := c.Args(bad, false, ""); err == nil {
			t.Errorf("endpoint %+v accepted", bad)
		}
	}
}

// fakeSSH is a script standing in for ssh: it records its arguments and exits with $FAKE_RC.
func fakeSSH(t *testing.T, rc int, out string) (*Client, string) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "argv")
	script := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do printf '%%s\\n' \"$a\"; done > %s\nprintf '%%s' %s\nprintf 'err' >&2\nexit %d\n", Quote(log), Quote(out), rc)
	os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755)
	return &Client{SSH: filepath.Join(dir, "ssh"), Identity: filepath.Join(dir, "id"), KnownHosts: filepath.Join(dir, "known_hosts")}, log
}

func TestRunExitCodes(t *testing.T) {
	ctx := context.Background()
	c, log := fakeSSH(t, 3, "hi")
	var out bytes.Buffer
	rc, err := c.Run(ctx, ep, []string{"sandbox", "run", "--name", "it's"}, nil, &out, &bytes.Buffer{}, true)
	if rc != 3 || err != nil || out.String() != "hi" {
		t.Fatalf("rc=%d err=%v out=%q", rc, err, out.String())
	}
	b, _ := os.ReadFile(log)
	if !strings.HasSuffix(string(b), "--\n'sandbox' 'run' '--name' 'it'\\''s'\n") {
		t.Errorf("argv %q", b)
	}
	if k, _ := os.ReadFile(c.KnownHosts); string(k) != "sandbox-vm ssh-ed25519 AAAAguest\n" {
		t.Errorf("known_hosts %q", k)
	}
	c, _ = fakeSSH(t, 255, "")
	if rc, err := c.Run(ctx, ep, []string{"x"}, nil, &out, &out, false); rc != 255 || !errors.Is(err, ErrTransport) {
		t.Errorf("255: rc=%d err=%v", rc, err)
	}
	bad := ep
	bad.HostKey = "nonsense"
	if _, err := c.Run(ctx, bad, []string{"x"}, nil, &out, &out, false); err == nil {
		t.Error("an endpoint without a valid pinned key was used")
	}
}

func TestOutputCap(t *testing.T) {
	c, _ := fakeSSH(t, 0, "IMAGE_VERSION=3\n")
	if b, err := c.Output(context.Background(), ep, []string{"cat", "/etc/sandbox/release"}, 100); err != nil || string(b) != "IMAGE_VERSION=3\n" {
		t.Errorf("%q %v", b, err)
	}
	if _, err := c.Output(context.Background(), ep, []string{"cat"}, 4); err == nil {
		t.Error("oversized output accepted")
	}
	c, _ = fakeSSH(t, 1, "")
	if _, err := c.Output(context.Background(), ep, []string{"cat"}, 4); err == nil || !strings.Contains(err.Error(), "err") {
		t.Errorf("failed command: %v", err)
	}
}

// TestEndToEnd runs a real sshd as the current user on a loopback port, then checks that the
// pinned key connects and runs a command with tricky arguments, and that a different pinned key
// is refused.
func TestEndToEnd(t *testing.T) {
	sshd, err1 := exec.LookPath("sshd")
	if err1 != nil {
		for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
			if _, err := os.Stat(p); err == nil {
				sshd, err1 = p, nil
			}
		}
	}
	ssh, err2 := DefaultSSH()
	if err1 != nil || err2 != nil || runtime.GOOS == "windows" {
		t.Skip("needs OpenSSH's sshd and ssh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keygen := DefaultKeygen(ssh)
	hostKey, err := GenerateKey(ctx, keygen, "guest")
	if err != nil {
		t.Fatal(err)
	}
	client, _ := GenerateKey(ctx, keygen, "client")
	other, _ := GenerateKey(ctx, keygen, "other")
	dir, err := os.MkdirTemp("", "sx") // short: sshd's paths
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.WriteFile(filepath.Join(dir, "hostkey"), []byte(hostKey.Private), 0o600)
	os.WriteFile(filepath.Join(dir, "id"), []byte(client.Private), 0o600)
	os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(client.Public+"\n"), 0o600)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s\nStrictModes no\nPidFile %s\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
		port, filepath.Join(dir, "hostkey"), filepath.Join(dir, "authorized_keys"), filepath.Join(dir, "pid"))
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(cfg), 0o600)
	srv := exec.CommandContext(ctx, sshd, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	var srvLog bytes.Buffer
	srv.Stderr = &srvLog
	if err := srv.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	defer srv.Process.Kill()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	u, _ := user.Current()
	c := &Client{SSH: ssh, Identity: filepath.Join(dir, "id"), KnownHosts: filepath.Join(dir, "known_hosts")}
	good := driver.SSHEndpoint{Host: "127.0.0.1", Port: port, User: u.Username, HostKey: hostKey.Public}
	args := []string{"$(echo x)", "it's", "a b"}
	cmd := append([]string{"printf", `%s\n`}, args...)
	out, err := c.Output(ctx, good, cmd, 1000)
	if err != nil {
		if strings.Contains(srvLog.String(), "not allowed") || strings.Contains(err.Error(), "Permission denied") {
			t.Skipf("sshd refused the test login on this host: %v %s", err, srvLog.String())
		}
		t.Fatalf("pinned key: %v\nsshd: %s", err, srvLog.String())
	}
	if string(out) != strings.Join(args, "\n")+"\n" {
		t.Errorf("output %q", out)
	}
	var stdout, stderr bytes.Buffer
	if rc, err := c.Run(ctx, good, []string{"sh", "-c", "exit 7"}, nil, &stdout, &stderr, false); rc != 7 || err != nil {
		t.Errorf("exit code: %d %v", rc, err)
	}
	wrong := good
	wrong.HostKey = other.Public
	if _, err := c.Output(ctx, wrong, []string{"true"}, 10); !errors.Is(err, ErrTransport) {
		t.Errorf("a different pinned key connected: %v", err)
	}
}

func TestCappedIsNotAReaderFrom(t *testing.T) {
	var w interface{} = &capped{max: 1}
	if _, ok := w.(interface {
		ReadFrom(r io.Reader) (int64, error)
	}); ok {
		t.Fatal("capped has ReadFrom, so io.Copy would bypass its cap")
	}
	c := &capped{max: 3}
	io.Copy(c, strings.NewReader("abcdef"))
	if c.buf.String() != "abc" || !c.over {
		t.Errorf("%q over=%v", c.buf.String(), c.over)
	}
}

// TestPinConcurrent: many connections start at once, each pinning the host key while other ssh
// processes read the file; no reader may ever see it empty or partial (it used to be truncated and
// rewritten for each connection, and a reader in between failed host key verification). The
// writers alternate two keys so that the file really is rewritten.
func TestPinConcurrent(t *testing.T) {
	dir := t.TempDir()
	c := &Client{KnownHosts: filepath.Join(dir, "known_hosts")}
	keys := []string{"AAAAC3NzaC1lZDI1NTE5AAAAIOm7dummydummydummydummydummydummydummydummy0",
		"AAAAC3NzaC1lZDI1NTE5AAAAIOm7otherotherotherotherotherotherotherother1"}
	eps := []driver.SSHEndpoint{{HostKey: "ssh-ed25519 " + keys[0] + " x"}, {HostKey: "ssh-ed25519 " + keys[1] + " y"}}
	ok := map[string]bool{HostKeyAlias + " ssh-ed25519 " + keys[0] + "\n": true, HostKeyAlias + " ssh-ed25519 " + keys[1] + "\n": true}
	if err := c.pin(eps[0]); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	bad := make(chan string, 1)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if runtime.GOOS == "windows" {
					// Windows refuses a rename over an open file: read the way ssh does (once per
					// connection), not in a loop that keeps the file open, and allow the sharing
					// violation a read gets during the rename itself
					time.Sleep(time.Millisecond)
				}
				b, err := os.ReadFile(c.KnownHosts)
				if err != nil && runtime.GOOS == "windows" {
					continue
				}
				if err != nil || !ok[string(b)] {
					select {
					case bad <- fmt.Sprintf("read %q, %v", b, err):
					default:
					}
					return
				}
			}
		}()
	}
	var writers sync.WaitGroup
	for i := 0; i < 32; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 50; j++ {
				if err := c.pin(eps[(i+j)%2]); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	select {
	case m := <-bad:
		t.Fatal(m)
	default:
	}
	if fi, err := os.Stat(c.KnownHosts); err != nil || fi.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("known_hosts %v %v", fi, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".known_hosts-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
