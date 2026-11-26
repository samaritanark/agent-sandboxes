package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
)

// fakeProc is an attached command: it says "started", then answers lines on its stdin: "size"
// prints the last window size, "exit" ends it with status 3. SIGHUP ends it with 129.
type fakeProc struct {
	mu    sync.Mutex
	size  [2]uint32
	sigs  []syscall.Signal
	done  chan int
	once  sync.Once
	args  []string
	tty   bool
	where string
}

func (p *fakeProc) finish(code int) { p.once.Do(func() { p.done <- code }) }

func (p *fakeProc) Resize(_ context.Context, c, r uint32) error {
	p.mu.Lock()
	p.size = [2]uint32{c, r}
	p.mu.Unlock()
	return nil
}

func (p *fakeProc) Kill(_ context.Context, s syscall.Signal) error {
	p.mu.Lock()
	p.sigs = append(p.sigs, s)
	p.mu.Unlock()
	if s == syscall.SIGHUP {
		p.finish(129)
	}
	return nil
}

func (p *fakeProc) Wait(ctx context.Context) (int, error) {
	select {
	case c := <-p.done:
		return c, nil
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// execer adds Exec to the rig's runtime.
type execer struct {
	*fakeRuntime
	mu    sync.Mutex
	procs []*fakeProc
}

func (e *execer) Exec(_ context.Context, id, execID string, args []string, tty bool, stdin io.Reader, stdout, stderr io.Writer) (runtime.Process, error) {
	if !e.started[id] {
		return nil, errors.New("no such task")
	}
	p := &fakeProc{done: make(chan int, 1), args: args, tty: tty, where: id + "/" + execID}
	e.mu.Lock()
	e.procs = append(e.procs, p)
	e.mu.Unlock()
	fmt.Fprintln(stdout, "started")
	go func() {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			switch sc.Text() {
			case "size":
				p.mu.Lock()
				fmt.Fprintf(stdout, "%dx%d\n", p.size[0], p.size[1])
				p.mu.Unlock()
			case "exit":
				p.finish(3)
				return
			}
		}
	}()
	return p, nil
}

func (e *execer) list() []*fakeProc {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*fakeProc(nil), e.procs...)
}

func attachRig(t *testing.T) (*rig, *execer, string) {
	r := newRig(t)
	ex := &execer{fakeRuntime: r.rt}
	r.d.Runtime = ex
	id, err := r.d.Start(context.Background(), spec("s-att", 2048))
	if err != nil {
		t.Fatal(err)
	}
	return r, ex, id
}

// TestAttachOverSocket: the client's own descriptors reach the command, window sizes follow, and
// the exit status comes back; the session is attached meanwhile and its grace starts after.
func TestAttachOverSocket(t *testing.T) {
	r, ex, id := attachRig(t)
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.d.Serve(ctx, ln, nil)

	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	resize := make(chan [2]uint16, 1)
	type res struct {
		code int
		err  error
	}
	got := make(chan res, 1)
	go func() {
		c, err := AttachCall(ctx, sock, Request{Op: "attach", ID: id, Args: []string{"claude", "--resume"}, TTY: true, Size: [2]uint16{80, 24}},
			[3]*os.File{inR, outW, outW}, resize)
		got <- res{c, err}
	}()
	out := bufio.NewReader(outR)
	line := func() string {
		outR.SetReadDeadline(time.Now().Add(5 * time.Second))
		s, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the command's output: %v", err)
		}
		return strings.TrimSpace(s)
	}
	if l := line(); l != "started" {
		t.Fatalf("%q", l)
	}
	fmt.Fprintln(inW, "size")
	if l := line(); l != "80x24" {
		t.Errorf("first size %q", l)
	}
	resize <- [2]uint16{132, 40}
	time.Sleep(100 * time.Millisecond)
	fmt.Fprintln(inW, "size")
	if l := line(); l != "132x40" {
		t.Errorf("after a resize %q", l)
	}
	r.d.mu.Lock()
	attached := r.d.live[id].Attached
	r.d.mu.Unlock()
	if !attached {
		t.Error("not attached while the command runs")
	}
	// long past the lease grace, an attached session stays
	*r.now = r.now.Add(time.Hour)
	r.d.Reap(ctx)
	if _, ok := r.d.live[id]; !ok {
		t.Fatal("an attached session was reaped")
	}
	fmt.Fprintln(inW, "exit")
	g := <-got
	if g.err != nil || g.code != 3 {
		t.Fatalf("exit %d %v", g.code, g.err)
	}
	p := ex.list()[0]
	if strings.Join(p.args, " ") != "claude --resume" || !p.tty || !strings.HasPrefix(p.where, id+"/attach-") {
		t.Errorf("ran %q tty=%v in %s", p.args, p.tty, p.where)
	}
	r.d.mu.Lock()
	lt := *r.d.live[id]
	r.d.mu.Unlock()
	if lt.Attached || !lt.LastHeartbeat.Equal(*r.now) {
		t.Errorf("after the attach: %+v", lt)
	}
	// the grace counts from the detach
	*r.now = r.now.Add(119 * time.Second)
	r.d.Reap(ctx)
	if _, ok := r.d.live[id]; !ok {
		t.Fatal("reaped within the grace after detaching")
	}
	*r.now = r.now.Add(2 * time.Second)
	r.d.Reap(ctx)
	if _, ok := r.d.live[id]; ok {
		t.Error("not reaped after the grace")
	}
	ev := strings.Join(auditTypes(t, r.d.AuditRoot, id, "events.jsonl"), ",")
	if !strings.Contains(ev, "attached,detached") {
		t.Errorf("events %s", ev)
	}
}

// TestAttachClientGone: when the client goes away, the command is hung up on, then killed.
func TestAttachClientGone(t *testing.T) {
	r, ex, id := attachRig(t)
	inR, _, _ := os.Pipe()
	gone := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		c, _ := r.d.Attach(context.Background(), id, []string{"sh"}, true, AttachIO{Stdin: inR, Stdout: io.Discard, Stderr: io.Discard}, [2]uint16{}, nil, gone)
		done <- c
	}()
	for len(ex.list()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	close(gone)
	select {
	case c := <-done:
		p := ex.list()[0]
		p.mu.Lock()
		defer p.mu.Unlock()
		if c != 129 || p.sigs[0] != syscall.SIGHUP {
			t.Errorf("exit %d signals %v", c, p.sigs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the attach did not end when the client went away")
	}
}

func TestAttachRefuses(t *testing.T) {
	r, _, id := attachRig(t)
	io3 := AttachIO{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard}
	if _, err := r.d.Attach(context.Background(), "s-nope", []string{"sh"}, false, io3, [2]uint16{}, nil, nil); err == nil {
		t.Error("attached to a session that is not running")
	}
	if _, err := r.d.Attach(context.Background(), id, nil, false, io3, [2]uint16{}, nil, nil); err == nil {
		t.Error("attached with no command")
	}
	// a request without the three descriptors
	if resp := r.d.serveAttach(context.Background(), Request{Op: "attach", ID: id, Args: []string{"sh"}}, nil, nil); resp.OK {
		t.Error("attached without stdio")
	}
	a, b, _ := os.Pipe()
	defer a.Close()
	defer b.Close()
	if resp := r.d.serveAttach(context.Background(), Request{Op: "attach", ID: id, Args: []string{"sh"}}, []*os.File{a, b}, nil); resp.OK || resp.Error == "" {
		t.Error("attached with two descriptors")
	}
	r.d.mu.Lock()
	defer r.d.mu.Unlock()
	if r.d.live[id].Attached {
		t.Error("a refused attach left the session attached")
	}
}

// TestAttachTwo: the session stays attached until its last terminal goes.
func TestAttachTwo(t *testing.T) {
	r, ex, id := attachRig(t)
	gone := []chan struct{}{make(chan struct{}), make(chan struct{})}
	done := make(chan int, 2)
	for i := range gone {
		inR, _, _ := os.Pipe()
		go func() {
			c, _ := r.d.Attach(context.Background(), id, []string{"sh"}, true, AttachIO{Stdin: inR, Stdout: io.Discard, Stderr: io.Discard}, [2]uint16{}, nil, gone[i])
			done <- c
		}()
	}
	for len(ex.list()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	attached := func() bool {
		r.d.mu.Lock()
		defer r.d.mu.Unlock()
		return r.d.live[id].Attached
	}
	close(gone[0])
	<-done
	if !attached() {
		t.Error("detached while a terminal is still attached")
	}
	close(gone[1])
	<-done
	if attached() {
		t.Error("attached after both terminals went")
	}
}
