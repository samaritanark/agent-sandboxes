//go:build !windows

package netd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The supervisor's files in its state directory.
const (
	LockFile      = "netd.lock" // held (flock) by the supervisor and the hypervisor while the VM lives
	PIDFile       = "netd.pid"
	SSHPortFile   = "ssh.port"
	EndpointsName = "endpoints" // declared host endpoints, one ip:port per line
)

// Supervisor owns one VM's link and SSH listener for the VM's whole life.
type Supervisor struct {
	Dir      string // state directory (0700)
	Self     string // this binary, run as `Self __netd-worker` for each worker
	GuestMAC string
	// StartVM starts the hypervisor with link as its network device and lock as an inherited
	// file it never uses (so the lock is held while the hypervisor lives, even if this process
	// is killed). The command's ExtraFiles are set by StartVM.
	StartVM func(link, lock *os.File) (*exec.Cmd, error)
	// RequestStop asks the guest to shut down; Grace is how long it gets before the VM is killed.
	RequestStop func() error
	Grace       time.Duration
	Log         *log.Logger
}

// ErrRunning is returned when the VM already has a supervisor.
var ErrRunning = errors.New("the sandbox VM is already running")

// lock takes the directory's lock without waiting.
func lock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	return f, nil
}

// Running reports whether a VM is alive under dir (its supervisor or hypervisor holds the lock).
func Running(dir string) (bool, error) {
	f, err := lock(dir)
	if errors.Is(err, ErrRunning) {
		return true, nil
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	f.Close()
	return false, nil
}

// SSHPort is the host loopback port forwarded to the guest's sshd.
func SSHPort(dir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dir, SSHPortFile))
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("bad %s", SSHPortFile)
	}
	return p, nil
}

// PID is the supervisor's process id, as it recorded it.
func PID(dir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dir, PIDFile))
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || p <= 1 {
		return 0, fmt.Errorf("bad %s", PIDFile)
	}
	return p, nil
}

func writeFile(dir, name, content string) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// Run starts the VM and keeps a worker serving its link until the VM exits. SIGTERM and SIGINT
// ask the guest to shut down, and kill the VM after Grace.
func (s *Supervisor) Run(ctx context.Context) error {
	if s.Log == nil {
		s.Log = log.New(os.Stderr, "netd: ", log.LstdFlags)
	}
	lk, err := lock(s.Dir)
	if err != nil {
		return err
	}
	defer lk.Close()
	for _, f := range []string{SSHPortFile, PIDFile} {
		os.Remove(filepath.Join(s.Dir, f))
	}
	if err := writeFile(s.Dir, PIDFile, strconv.Itoa(os.Getpid())+"\n"); err != nil {
		return err
	}

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
		// Room for bursts of full-size frames; vz's own default buffers drop under load.
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1<<20)
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	}
	vmEnd, ourEnd := os.NewFile(uintptr(fds[0]), "vm-link"), os.NewFile(uintptr(fds[1]), "netd-link")
	defer ourEnd.Close()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		vmEnd.Close()
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	lnFile, err := ln.(*net.TCPListener).File()
	ln.Close() // the duplicate in lnFile keeps the socket
	if err != nil {
		vmEnd.Close()
		return err
	}
	defer lnFile.Close()

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)

	vm, err := s.StartVM(vmEnd, lk)
	vmEnd.Close()
	if err != nil {
		return fmt.Errorf("starting the VM: %w", err)
	}
	vmDone := make(chan error, 1)
	go func() { vmDone <- vm.Wait() }()
	if err := writeFile(s.Dir, SSHPortFile, strconv.Itoa(port)+"\n"); err != nil {
		vm.Process.Kill()
		return err
	}
	defer os.Remove(filepath.Join(s.Dir, SSHPortFile))
	s.Log.Printf("VM started (pid %d)", vm.Process.Pid)

	backoff := time.Second
	stopping := false
	var killAt <-chan time.Time
	for {
		w := exec.Command(s.Self, "__netd-worker", "--mac", s.GuestMAC, "--endpoints", filepath.Join(s.Dir, EndpointsName))
		w.ExtraFiles = []*os.File{ourEnd, lnFile} // fd 3 and fd 4
		w.Stdout, w.Stderr = s.Log.Writer(), s.Log.Writer()
		started := time.Now()
		if err := w.Start(); err != nil {
			s.Log.Printf("cannot start a worker: %v", err)
		}
		wDone := make(chan struct{})
		go func() {
			if w.Process != nil {
				w.Wait()
			}
			close(wDone)
		}()
	wait:
		for {
			select {
			case err := <-vmDone:
				if w.Process != nil {
					w.Process.Kill()
					<-wDone
				}
				s.Log.Printf("VM exited (%v)", err)
				return nil
			case <-sigs:
				if stopping {
					vm.Process.Kill()
					continue
				}
				stopping = true
				s.Log.Printf("stopping the VM")
				if s.RequestStop == nil || s.RequestStop() != nil {
					vm.Process.Kill()
				} else {
					killAt = time.After(s.Grace)
				}
			case <-killAt:
				s.Log.Printf("the guest did not shut down within %v; stopping it by force", s.Grace)
				vm.Process.Kill()
			case <-ctx.Done():
				vm.Process.Kill()
			case <-wDone:
				if time.Since(started) > time.Minute {
					backoff = time.Second
				}
				s.Log.Printf("worker exited (%v); restarting in %v", w.ProcessState, backoff)
				select {
				case <-time.After(backoff):
				case err := <-vmDone:
					s.Log.Printf("VM exited (%v)", err)
					return nil
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				break wait
			}
		}
	}
}

// WorkerMain is `sandbox __netd-worker`: it serves the link inherited as fd 3 with the SSH
// listener inherited as fd 4, and exits when the link fails or its supervisor is gone.
func WorkerMain(args []string) int {
	fs := flag.NewFlagSet("__netd-worker", flag.ContinueOnError)
	mac := fs.String("mac", "", "the guest's MAC address")
	endpoints := fs.String("endpoints", "", "the declared endpoints file")
	if err := fs.Parse(args); err != nil || *mac == "" || *endpoints == "" {
		fmt.Fprintln(os.Stderr, "usage: __netd-worker --mac MAC --endpoints FILE (fds 3 and 4 inherited)")
		return 2
	}
	l := log.New(os.Stderr, fmt.Sprintf("netd worker %d: ", os.Getpid()), log.LstdFlags)
	link, err := net.FileConn(os.NewFile(3, "link"))
	if err != nil {
		l.Print(err)
		return 1
	}
	ssh, err := net.FileListener(os.NewFile(4, "ssh"))
	if err != nil {
		l.Print(err)
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	parent := os.Getppid()
	go func() { // a worker never outlives its supervisor
		for range time.Tick(time.Second) {
			if os.Getppid() != parent {
				cancel()
				link.Close()
				ssh.Close()
				return
			}
		}
	}()
	ef := &EndpointsFile{Path: *endpoints}
	st := &Stack{Policy: Policy{HostPrefixes: HostPrefixes, Declared: ef.Read}, GuestMAC: *mac, Log: l}
	l.Print("serving")
	err = st.Serve(ctx, link, ssh)
	l.Printf("stopped: %v", err)
	return 1
}
