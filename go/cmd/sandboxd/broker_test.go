package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
)

// TestWriteReadable: the helper opens each reference into its own new file, readable only by the
// user, and closes the directory to everyone else; a name with a path in it, a reference the store
// lacks, and a file already there (a planted link) are refused.
func TestWriteReadable(t *testing.T) {
	key, _ := brokerseal.NewKey()
	st := brokerstore.Store{Dir: t.TempDir()}
	sealed, _ := brokerseal.Seal(key, "secret.A", []byte("value\n"))
	if err := st.Put("secret.A", sealed); err != nil {
		t.Fatal(err)
	}
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
	} {
		d := mk()
		os.Symlink("/etc/passwd", filepath.Join(d, "L"))
		if err := writeReadable(readableJob{Key: key, Store: st.Dir, Dir: d, UID: uid, Files: files}); err == nil {
			t.Errorf("%s: written", name)
		}
	}
}
