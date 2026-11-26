package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
)

// TestWriteReadable: the helper opens each reference into its own new file, readable only by the
// user, and closes the directory to everyone else; a name with a path in it, a reference the store
// lacks, and a file already there (a planted link) are refused.
func TestWriteReadable(t *testing.T) {
	key, _ := brokerseal.NewKey()
	st := brokerstore.Store{Dir: t.TempDir()}
	put := func(ref, v string, b *brokerseal.Binding) { t.Helper(); putEntry(t, st, key, ref, v, b) }
	put("secret.A", "value\n", &brokerseal.Binding{Readable: true})
	put("secret.U", "v", nil)
	put("secret.H", "v", &brokerseal.Binding{Hosts: []string{"api.x.com"}, Inject: "bearer"})
	put("secret.W", "v", &brokerseal.Binding{})
	mk := func() string {
		d := filepath.Join(t.TempDir(), "s")
		os.Mkdir(d, 0o700)
		t.Cleanup(func() { os.Chmod(d, 0o700) }) // runs before TempDir's own cleanup
		return d
	}
	uid := os.Getuid()
	dir := mk()
	if err := writeReadable(readableJob{Key: key, Store: st.Dir, Dir: dir, UID: uid, Files: map[string]string{"A": "secret.A"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "A"))
	fi, _ := os.Stat(filepath.Join(dir, "A"))
	di, _ := os.Stat(dir)
	if string(b) != "value\n" || fi.Mode().Perm() != 0o400 || di.Mode().Perm() != 0o500 {
		t.Errorf("%q %v %v", b, fi.Mode(), di.Mode())
	}
	for name, files := range map[string]map[string]string{
		"a path":        {"../A": "secret.A"},
		"missing":       {"A": "secret.B"},
		"dot":           {".": "secret.A"},
		"existing file": {"L": "secret.A"},
		"unbound":       {"U": "secret.U"},
		"brokered only": {"H": "secret.H"},
		"withheld":      {"W": "secret.W"},
	} {
		d := mk()
		os.Symlink("/etc/passwd", filepath.Join(d, "L"))
		if err := writeReadable(readableJob{Key: key, Store: st.Dir, Dir: d, UID: uid, Files: files}); err == nil {
			t.Errorf("%s: written", name)
		}
	}
}

// TestOpenLinks: each credential the gateway gets is checked against the binding sealed with it.
func TestOpenLinks(t *testing.T) {
	key, _ := brokerseal.NewKey()
	st := brokerstore.Store{Dir: t.TempDir()}
	put := func(ref, v string, b *brokerseal.Binding) { t.Helper(); putEntry(t, st, key, ref, v, b) }
	put("secret.GH", "gh", &brokerseal.Binding{Hosts: []string{"api.github.com", "uploads.github.com"}, Inject: "bearer"})
	put("secret.OLD", "old", nil)
	put("secret.R", "r", &brokerseal.Binding{Readable: true})
	put("anthropic", "tok", nil)
	use := func(ref, inject string, hosts ...string) daemon.Use {
		return daemon.Use{Ref: ref, Hosts: hosts, Inject: inject}
	}
	h, opened, err := openLinks(st, key, [][]daemon.Use{{use("secret.GH", "bearer", "api.github.com"), use("anthropic", "header:x-api-key", "api.anthropic.com")}, {use("secret.GH", "bearer", "API.github.com", "uploads.github.com")}})
	if err != nil || len(h.Links) != 2 || string(h.Links[0]["secret.GH"]) != "gh" || string(h.Links[0]["anthropic"]) != "tok" || string(h.Links[1]["secret.GH"]) != "gh" || len(opened) != 3 {
		t.Fatalf("%v %v %d", err, h, len(opened))
	}
	for name, u := range map[string]daemon.Use{
		"another host":      use("secret.GH", "bearer", "evil.example.com"),
		"another injection": use("secret.GH", "query:token", "api.github.com"),
		"no binding sealed": use("secret.OLD", "bearer", "api.github.com"),
		"readable only":     use("secret.R", "bearer", "api.github.com"),
		"missing":           use("secret.NO", "bearer", "api.github.com"),
	} {
		_, opened, err := openLinks(st, key, [][]daemon.Use{{u}})
		if err == nil {
			t.Errorf("%s: handed over", name)
		}
		if name != "missing" && len(opened) != 1 {
			t.Errorf("%s: %d opened values to wipe", name, len(opened))
		}
	}
}

// putEntry stores ref's value sealed with binding b, or in the first form when b is nil.
func putEntry(t *testing.T, st brokerstore.Store, key []byte, ref, v string, b *brokerseal.Binding) {
	t.Helper()
	var sealed []byte
	var err error
	if b == nil {
		sealed, err = brokerseal.Seal(key, ref, []byte(v))
	} else {
		sealed, err = brokerseal.SealBound(key, ref, []byte(v), *b)
	}
	if err == nil {
		err = st.Put(ref, sealed)
	}
	if err != nil {
		t.Fatal(err)
	}
}
