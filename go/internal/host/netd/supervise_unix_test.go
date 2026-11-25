//go:build !windows

package netd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__netd-worker" {
		os.Exit(WorkerMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A stand-in hypervisor: it holds the link and the lock, as vfkit does, and never exits by itself.
func fakeVM(link, lock *os.File) (*exec.Cmd, error) {
	c := exec.Command("sleep", "60")
	c.ExtraFiles = []*os.File{link, lock}
	return c, c.Start()
}

func TestSupervisor(t *testing.T) {
	dir := t.TempDir()
	if r, err := Running(dir); err != nil || r {
		t.Fatalf("before start: %v %v", r, err)
	}
	var out syncBuf
	stopAsked := make(chan struct{}, 1)
	s := &Supervisor{Dir: dir, Self: os.Args[0], GuestMAC: "5a:94:ef:e4:0c:ee", StartVM: fakeVM,
		RequestStop: func() error { stopAsked <- struct{}{}; return nil }, Grace: 300 * time.Millisecond,
		Log: log.New(&out, "", 0)}
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()

	waitFor(t, "the SSH port", func() bool { _, err := SSHPort(dir); return err == nil })
	if r, _ := Running(dir); !r {
		t.Error("not running while the VM lives")
	}
	if err := (&Supervisor{Dir: dir, StartVM: fakeVM}).Run(context.Background()); err != ErrRunning {
		t.Errorf("a second supervisor: %v", err)
	}
	if pid, err := PID(dir); err != nil || pid != os.Getpid() {
		t.Errorf("pid %d %v", pid, err)
	}

	// The worker comes up; killed, it is replaced.
	waitFor(t, "a worker", func() bool { return strings.Contains(out.String(), "serving") })
	first := workerPID(t, out.String())
	syscall.Kill(first, syscall.SIGKILL)
	waitFor(t, "a second worker", func() bool { return strings.Count(out.String(), "serving") >= 2 })
	if strings.Count(out.String(), "worker exited") != 1 {
		t.Errorf("log:\n%s", out.String())
	}

	// SIGTERM asks the guest to stop; a guest that does not is killed after the grace period.
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case <-stopAsked:
	case <-time.After(5 * time.Second):
		t.Fatal("the guest was not asked to stop")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not exit")
	}
	if !strings.Contains(out.String(), "by force") {
		t.Errorf("log:\n%s", out.String())
	}
	if r, _ := Running(dir); r {
		t.Error("still running after stop")
	}
	if _, err := SSHPort(dir); err == nil {
		t.Error("the SSH port file outlived the VM")
	}
}

func workerPID(t *testing.T, logText string) int {
	t.Helper()
	for _, l := range strings.Split(logText, "\n") {
		var pid int
		if i := strings.Index(l, "netd worker "); i >= 0 {
			if _, err := fmt.Sscanf(l[i:], "netd worker %d:", &pid); err == nil && pid > 0 {
				return pid
			}
		}
	}
	t.Fatalf("no worker pid in:\n%s", logText)
	return 0
}
