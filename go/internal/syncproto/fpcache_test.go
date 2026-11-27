package syncproto

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFPCacheRacy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("aaaa"), 0o644)
	st, _ := os.Stat(p)
	now := st.ModTime()
	c := &FPCache{now: func() time.Time { return now }}

	c.Put(p, st, "fp1") // written this instant: not trusted
	if _, ok := c.Get(p, st); ok {
		t.Error("a file changed within the racy window was cached")
	}
	now = st.ModTime().Add(RacyWindow)
	c.Put(p, st, "fp1")
	if fp, ok := c.Get(p, st); !ok || fp != "fp1" {
		t.Errorf("a settled file was not cached: %q %v", fp, ok)
	}
	// A same-size rewrite that kept every stat field: the entry was taken after the window, so
	// the stat data would have changed on any later write. A rewrite seen while racy drops the
	// entry instead.
	now = st.ModTime().Add(time.Second)
	c.Put(p, st, "fp2")
	if _, ok := c.Get(p, st); ok {
		t.Error("a racy Put kept the older entry")
	}
	// A modification time in the future is never trusted.
	now = st.ModTime().Add(-time.Hour)
	c.Put(p, st, "fp3")
	if _, ok := c.Get(p, st); ok {
		t.Error("a file from the future was cached")
	}
}

// TestFPCacheFile: a saved cache is trusted in the next run only for files whose stat data did not
// change; a file changed in between (same size, even with its old modification time put back) is
// read again; entries for files gone are dropped at the next save; a bad file is an empty cache.
func TestFPCacheFile(t *testing.T) {
	if !identKnown {
		t.Skip("no inode or change time here, so a cache is never kept across runs")
	}
	dir := t.TempDir()
	a, b, gone := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "gone")
	for _, p := range []string{a, b, gone} {
		os.WriteFile(p, []byte("1234"), 0o644)
	}
	old := time.Now().Add(-time.Hour)
	for _, p := range []string{a, b, gone} {
		os.Chtimes(p, old, old)
	}
	stat := func(p string) os.FileInfo { st, _ := os.Lstat(p); return st }
	file := filepath.Join(t.TempDir(), "cache.json")
	c := &FPCache{}
	for _, p := range []string{a, b, gone} {
		c.Put(p, stat(p), "fp-"+filepath.Base(p))
	}
	if err := c.SaveFile(file); err != nil {
		t.Fatal(err)
	}
	// b is rewritten in place with the same size and its old times put back: only its change
	// time (and so its identity) differs
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(b, []byte("5678"), 0o644)
	os.Chtimes(b, old, old)
	os.Remove(gone)
	c2 := &FPCache{}
	c2.LoadFile(file)
	if fp, ok := c2.Get(a, stat(a)); !ok || fp != "fp-a" {
		t.Errorf("an unchanged file missed the saved cache: %q %v", fp, ok)
	}
	if _, ok := c2.Get(b, stat(b)); ok {
		t.Error("a file rewritten with its times put back matched the saved cache")
	}
	c2.Put(b, stat(b), "fp-b2")
	if err := c2.SaveFile(file); err != nil {
		t.Fatal(err)
	}
	c3 := &FPCache{}
	c3.LoadFile(file)
	if len(c3.m) != 2 {
		t.Errorf("entries after the second save: %v", c3.m)
	}
	// nothing scanned: a save keeps the file as it is
	c4 := &FPCache{}
	c4.LoadFile(file)
	c4.SaveFile(file)
	c3.LoadFile(file)
	if len(c3.m) != 2 {
		t.Errorf("a run that scanned nothing changed the file: %v", c3.m)
	}
	for _, bad := range []string{"", "{", `{"v":"other","e":{"x":{"s":4,"f":"fp"}}}`, `[]`} {
		os.WriteFile(file, []byte(bad), 0o600)
		c5 := &FPCache{}
		c5.LoadFile(file)
		if len(c5.m) != 0 {
			t.Errorf("%q loaded %v", bad, c5.m)
		}
	}
	c5 := &FPCache{}
	c5.LoadFile(filepath.Join(dir, "missing"))
	if len(c5.m) != 0 {
		t.Error("a missing file loaded entries")
	}
}
