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
