package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// diskDriver is a driver whose VM keeps its state on a disk of its own; replacing the system disk
// changes the image the fake VM reports.
type diskDriver struct {
	*driver.Mock
	tr       *fakeTransport
	next     string // the release the replacement image reports ("" for one that never answers)
	current  string
	prev     string
	replaced []string
	rolled   int
}

func (d *diskDriver) ReplaceSystemDisk(_ context.Context, img driver.ImageRef) error {
	if d.State != driver.Stopped {
		return errors.New("not stopped")
	}
	d.replaced = append(d.replaced, img.Path)
	d.prev, d.current = d.current, d.next
	d.apply()
	return nil
}

func (d *diskDriver) RollBack(context.Context) error {
	if d.prev == "" {
		return errors.New("no previous disk")
	}
	d.rolled++
	d.current, d.prev = d.prev, ""
	d.apply()
	return nil
}

func (d *diskDriver) CanRollBack(context.Context) bool { return d.prev != "" }

func (d *diskDriver) apply() {
	d.tr.release, d.tr.relErr = d.current, nil
	if d.current == "" {
		d.tr.relErr = errors.New("connection refused")
	}
}

// TestUpgrade (design 10): the system disk is replaced and the VM boots the new image, keeping its
// state disk; running sessions refuse it; an image that does not answer, or is older without
// --allow-downgrade, is rolled back; --rollback puts the previous disk back; a driver without a
// state disk refuses. Each is recorded in upgrades.log.
func TestUpgrade(t *testing.T) {
	state := t.TempDir()
	img := filepath.Join(state, "new.raw")
	head := make([]byte, 1024)
	copy(head[512:], "EFI PART")
	os.WriteFile(img, head, 0o644)
	rel := func(v string) string { return "IMAGE_VERSION=" + v + "\nCONTROL_API=1\n" }
	setup := func(next string) (*diskDriver, *fakeTransport, Env, *bytes.Buffer, *bytes.Buffer) {
		tr := &fakeTransport{}
		d := &diskDriver{Mock: &driver.Mock{State: driver.Running}, tr: tr, current: rel("3.0.0-dev.28"), next: next}
		d.apply()
		var out, errb bytes.Buffer
		clock := time.Unix(1800000000, 0)
		env := Env{Driver: d, Transport: tr, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state,
			Now:     func() time.Time { clock = clock.Add(10 * time.Millisecond); return clock }, // so waitReady's deadline passes
			Install: InstallDeps{ReadyTimeout: 30 * time.Millisecond, Poll: 5 * time.Millisecond}}
		return d, tr, env, &out, &errb
	}
	logOf := func() string { b, _ := os.ReadFile(filepath.Join(state, "logs", "upgrades.log")); return string(b) }

	d, _, env, out, errb := setup(rel("3.0.0-dev.29"))
	if rc := Run(context.Background(), []string{"upgrade", "--image", img}, env); rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	if len(d.replaced) != 1 || d.replaced[0] != img || d.State != driver.Running || d.rolled != 0 ||
		!strings.Contains(out.String(), "image 3.0.0-dev.28 → 3.0.0-dev.29") || !strings.Contains(logOf(), "upgrade from=3.0.0-dev.28 to=3.0.0-dev.29") {
		t.Errorf("upgrade: %+v\n%s\n%s", d.replaced, out.String(), logOf())
	}
	// --rollback puts the previous disk back
	out.Reset()
	if rc := Run(context.Background(), []string{"upgrade", "--rollback"}, env); rc != 0 || d.rolled != 1 || !strings.Contains(out.String(), "rolled back: image 3.0.0-dev.29 → 3.0.0-dev.28") {
		t.Errorf("rollback: %d %s %s", rc, out.String(), errb.String())
	}
	errb.Reset()
	stops := strings.Count(strings.Join(d.Calls, " "), "Stop")
	if rc := Run(context.Background(), []string{"upgrade", "--rollback"}, env); rc != 1 || !strings.Contains(errb.String(), "nothing to roll back to") ||
		strings.Count(strings.Join(d.Calls, " "), "Stop") != stops {
		t.Errorf("a second rollback with no previous disk: %d %s", rc, errb.String())
	}

	// an older image is rolled back unless allowed
	d, _, env, _, errb = setup(rel("3.0.0-dev.9"))
	if rc := Run(context.Background(), []string{"upgrade", "--image", img}, env); rc != 1 || d.rolled != 1 ||
		!strings.Contains(errb.String(), "older than the installed 3.0.0-dev.28") || !strings.Contains(logOf(), "rolled-back from=3.0.0-dev.28 to=3.0.0-dev.9") {
		t.Errorf("older: %d %s", rc, errb.String())
	}
	d, _, env, out, _ = setup(rel("3.0.0-dev.9"))
	if rc := Run(context.Background(), []string{"upgrade", "--image", img, "--allow-downgrade"}, env); rc != 0 || d.rolled != 0 ||
		!strings.Contains(logOf(), "upgrade from=3.0.0-dev.28 to=3.0.0-dev.9 downgrade allowed") {
		t.Errorf("allowed downgrade: %d %s", rc, out.String())
	}
	// an image that never answers is rolled back
	d, _, env, _, errb = setup("")
	if rc := Run(context.Background(), []string{"upgrade", "--image", img}, env); rc != 1 || d.rolled != 1 || d.State != driver.Running ||
		!strings.Contains(errb.String(), "the upgrade was rolled back (image 3.0.0-dev.28): it did not answer") {
		t.Errorf("no answer: %d %s", rc, errb.String())
	}
	// running sessions refuse it, before anything is touched
	d, tr, env, _, errb := setup(rel("3.0.0-dev.29"))
	tr.sessions = "ses-20270115-080000-beef\tx/claude\tRUNNING\t\n"
	if rc := Run(context.Background(), []string{"upgrade", "--image", img}, env); rc != 1 || len(d.replaced) != 0 || d.State != driver.Running ||
		!strings.Contains(errb.String(), "sessions are running (ses-20270115-080000-beef)") {
		t.Errorf("sessions: %d %s", rc, errb.String())
	}
	// a driver without a state disk, and a file that is not an image
	_, _, env, _, errb = setup(rel("3.0.0-dev.29"))
	env.Driver = &driver.Mock{State: driver.Running}
	if rc := Run(context.Background(), []string{"upgrade", "--image", img}, env); rc != 1 || !strings.Contains(errb.String(), "keeps the VM's state on its system disk") {
		t.Errorf("no state disk: %d %s", rc, errb.String())
	}
	d, _, env, _, _ = setup(rel("3.0.0-dev.29"))
	os.WriteFile(filepath.Join(state, "x.raw"), []byte("x"), 0o644)
	if rc := Run(context.Background(), []string{"upgrade", "--image", filepath.Join(state, "x.raw")}, env); rc != 1 || len(d.replaced) != 0 {
		t.Error("a file that is not an image was installed")
	}
}

func TestOlderVersion(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		older bool
	}{{"3.0.0-dev.9", "3.0.0-dev.10", true}, {"3.0.0-dev.10", "3.0.0-dev.9", false}, {"3.0.0-dev.29", "3.0.0", true},
		{"3.0.0", "3.0.0-dev.29", false}, {"3.0.1", "3.0.0", false}, {"2.9.9", "3.0.0", true}, {"3.0.0", "3.0.0", false}, {"", "3.0.0", false}} {
		if got := olderVersion(c.a, c.b); got != c.older {
			t.Errorf("%s < %s: %v", c.a, c.b, got)
		}
	}
}
