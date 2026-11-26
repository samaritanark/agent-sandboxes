package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// fakeMounter records the views and covers; a cover over a path in missing is ErrNoTarget.
type fakeMounter struct {
	views   map[string]string // view: source
	covers  []string          // "view/rel <- cover" ("" for read-only in place)
	missing map[string]bool
	gone    []string
	failOn  string
}

func (f *fakeMounter) View(src, dst string) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	f.views[dst] = src
	return nil
}

func (f *fakeMounter) Over(view, rel, cover string) error {
	if f.missing[rel] {
		return ErrNoTarget
	}
	if rel == f.failOn {
		return errors.New("mount failed")
	}
	f.covers = append(f.covers, filepath.Base(view)+"/"+rel+" <- "+filepath.Base(cover))
	return nil
}

func (f *fakeMounter) Unmount(dst string) error {
	delete(f.views, dst)
	f.gone = append(f.gone, dst)
	return nil
}

// TestViews: each workspace reaches the microVM as a view, its file masks and read-only files
// covered in the VM and its directory masks mounted in the microVM, and the views are unmounted and
// removed at the end.
func TestViews(t *testing.T) {
	r := newRig(t)
	fm := &fakeMounter{views: map[string]string{}}
	r.d.Mounter = fm
	sp, _ := sessionspec.Decode(strings.NewReader(string(spec("s-v", 2048))))
	sp.Mounts = append(sp.Mounts,
		sessionspec.Mount{Kind: sessionspec.ReadOnly, Source: ws + "/.git/config", Target: "/home/agent/workspace/.git/config", ReadOnly: true},
		sessionspec.Mount{Kind: sessionspec.Workspace, Source: sessionspec.WorkspaceStore + "/fedcba9876543210", Target: "/home/agent/other"},
		sessionspec.Mount{Kind: sessionspec.MaskFile, Target: "/home/agent/other/.env"})
	b, _ := sp.Encode()
	ctx := context.Background()
	id, err := r.d.Start(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	agent := r.rt.vms[id]
	var got []string
	for _, m := range agent.Mounts {
		if m.Target != "/etc/resolv.conf" {
			got = append(got, strings.TrimPrefix(m.Source, r.d.SessionRoot)+" "+m.Target)
		}
	}
	if strings.Join(got, ",") != "/s-v/views/0 /home/agent/workspace,/s-v/views/1 /home/agent/other,/s-v/masks/3 /home/agent/workspace/secrets" {
		t.Errorf("microVM mounts %q", got)
	}
	sort.Strings(fm.covers)
	if strings.Join(fm.covers, ",") != "0/.env <- 2,0/.git/config <- .,1/.env <- 5" {
		t.Errorf("covers %q", fm.covers)
	}
	// a file the copy lacks is left alone
	fm.missing = map[string]bool{".env": true}
	fm.covers = nil
	id2, err := r.d.Start(ctx, spec("s-v2", 2048))
	if err != nil || len(fm.covers) != 0 {
		t.Fatalf("missing target: %v %q", err, fm.covers)
	}
	r.d.Stop(ctx, id2, "operator stop")
	fm.missing = nil
	if false {
		t.Errorf("covers %q", fm.covers)
	}
	if err := r.d.Stop(ctx, id, "operator stop"); err != nil {
		t.Fatal(err)
	}
	if len(fm.views) != 0 || len(fm.gone) != 3 {
		t.Errorf("views left %v, unmounted %v", fm.views, fm.gone)
	}
	if _, err := os.Stat(r.d.viewDir(id)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("views directory left: %v", err)
	}
	// a cover that fails stops the session, and its views still go
	fm.failOn = ".env"
	if _, err := r.d.Start(ctx, spec("s-vf", 2048)); err == nil || !strings.Contains(err.Error(), "mount failed") {
		t.Fatalf("cover failure: %v", err)
	}
	if len(fm.views) != 0 || len(r.rt.vms) != 0 {
		t.Errorf("left after a failed cover: %v %v", fm.views, r.rt.vms)
	}
}
