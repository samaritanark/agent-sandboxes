//go:build !windows

package netdvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/netd"
)

const maxLog = 8 << 20

// openLog opens netd's log for appending, keeping one previous log once it grows past maxLog.
func openLog(p string) (*os.File, error) {
	if st, err := os.Stat(p); err == nil && st.Size() > maxLog {
		os.Rename(p, p+".1")
	}
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}

func tail(p string, n int) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Start launches `sandbox __netd DIR` in its own session, detached from the CLI, and waits until
// the guest's sshd answers through netd's forward (as `limactl start` waits for boot), so the
// caller's handshake can follow at once.
func (d *Driver) Start(ctx context.Context) error {
	st, err := d.Status(ctx)
	if err != nil {
		return err
	}
	switch st {
	case driver.Running:
		return nil
	case driver.NotCreated:
		return driver.ErrNotCreated
	case driver.Broken:
		return errors.New("the sandbox VM's files are incomplete (run 'sandbox uninstall', then 'sandbox install')")
	}
	dir := d.dir()
	lf, err := openLog(filepath.Join(dir, netdLog))
	if err != nil {
		return err
	}
	defer lf.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()
	cmd := exec.Command(d.Self, "__netd", dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.After(bootTimeout)
	for {
		if port, err := netd.SSHPort(dir); err == nil && sshAnswers(port) {
			return nil
		}
		select {
		case err := <-exited:
			return fmt.Errorf("sandbox netd exited (%v):\n%s", err, tail(filepath.Join(dir, netdLog), 10))
		case <-deadline:
			return fmt.Errorf("the sandbox VM did not answer within %v (its console log: %s):\n%s", bootTimeout,
				filepath.Join(dir, console), tail(filepath.Join(dir, netdLog), 10))
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

const bootTimeout = 3 * time.Minute

// sshAnswers reports whether an SSH server greets on the forwarded port. Authentication, with
// the pinned host key, is the caller's handshake.
func sshAnswers(port int) bool {
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 8)
	n, _ := io.ReadFull(c, b)
	return n == 8 && string(b) == "SSH-2.0-"
}

// Stop asks netd to shut the guest down (netd stops it by force after Grace) and waits. If netd
// is gone (killed), it asks the hypervisor itself; whatever is still running after that is killed. Every
// recorded process id is checked against its command line first, since an id may have been reused.
func (d *Driver) Stop(ctx context.Context) error {
	dir := d.dir()
	running, err := netd.Running(dir)
	if err != nil || !running {
		return err
	}
	sup := d.ours(netd.PIDFile, "__netd "+dir)
	vm := d.ours(netd.VMPIDFile, filepath.Join(dir, diskFile))
	switch {
	case sup > 0:
		syscall.Kill(sup, syscall.SIGTERM)
		if waitStopped(ctx, dir, Grace+15*time.Second) {
			return nil
		}
	case vm > 0 && d.hv.requestStop(d) == nil:
		if waitStopped(ctx, dir, Grace) {
			return nil
		}
	}
	for _, pid := range []int{d.ours(netd.PIDFile, "__netd "+dir), d.ours(netd.VMPIDFile, filepath.Join(dir, diskFile))} {
		if pid > 0 {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	if waitStopped(ctx, dir, 10*time.Second) {
		return nil
	}
	return errors.New("the sandbox VM did not stop")
}

// ours is the process id recorded in name if that process is still the one recorded: its command
// line holds want. Otherwise 0.
func (d *Driver) ours(name, want string) int {
	pid, err := netd.PID(d.dir(), name)
	if err != nil {
		return 0
	}
	out, err := exec.Command("/bin/ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil || !strings.Contains(string(out), want) {
		return 0
	}
	return pid
}

func waitStopped(ctx context.Context, dir string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) && ctx.Err() == nil {
		if r, err := netd.Running(dir); err == nil && !r {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func (d *Driver) Delete(ctx context.Context) error {
	if err := d.Stop(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(d.dir()); err != nil {
		return err
	}
	for _, f := range []string{keyRecord, toolRecord(d.hv.kind())} {
		if err := os.Remove(filepath.Join(d.StateDir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// NetdMain is `sandbox __netd DIR`: the supervisor of design D-31 for the VM in DIR
// (~/.sandbox/vm/<kind>). It re-verifies the hypervisor, starts it with the VM's link, and serves
// the link until the VM exits.
func NetdMain(args []string) int {
	l := log.New(os.Stderr, "netd: ", log.LstdFlags)
	if len(args) != 1 || !filepath.IsAbs(args[0]) {
		l.Print("usage: __netd DIR")
		return 2
	}
	dir := filepath.Clean(args[0])
	d, err := Open(filepath.Dir(dir), filepath.Base(dir))
	if err != nil {
		l.Print(err)
		return 1
	}
	if d.dir() != dir {
		l.Printf("%s is not this install's VM directory", dir)
		return 2
	}
	spec, err := d.spec()
	if err != nil {
		l.Print(err)
		return 1
	}
	argv := d.hv.command(d, spec)
	s := &netd.Supervisor{
		Dir: dir, Self: d.Self, GuestMAC: spec.MAC, Grace: Grace, Log: l,
		RequestStop: func() error { return d.hv.requestStop(d) },
		StartVM: func(link, lock *os.File) (*exec.Cmd, error) {
			for _, f := range []string{restSock, qmpSock} {
				os.Remove(filepath.Join(dir, f))
			}
			// The console log is the operator's alone, whatever the hypervisor's umask.
			if f, err := os.OpenFile(filepath.Join(dir, console), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
				f.Chmod(0o600)
				f.Close()
			}
			c := exec.Command(argv[0], argv[1:]...)
			c.ExtraFiles = []*os.File{link, lock} // fd 3, fd 4
			c.Env = append(os.Environ(), d.hv.env(dir)...)
			c.Stdout, c.Stderr = os.Stderr, os.Stderr
			return c, c.Start()
		},
	}
	err = s.Run(context.Background())
	// vfkit leaves its cloud-init ISO behind; the next start makes a new one.
	if m, _ := filepath.Glob(filepath.Join(dir, "vfkit-cloudinit*")); len(m) > 0 {
		for _, p := range m {
			os.RemoveAll(p)
		}
	}
	if err != nil {
		l.Print(err)
		return 1
	}
	return 0
}
