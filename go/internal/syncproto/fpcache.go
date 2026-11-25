package syncproto

import (
	"io/fs"
	"sync"
	"time"
)

// RacyWindow is how recently modified a file may be and still not be cached. File systems stamp
// times from a clock coarser than their nanosecond fields (Linux's tick, HFS+'s second, FAT's two
// seconds), so a file rewritten in place with the same size within one tick keeps all its stat
// data. A fingerprint taken that close to the file's last change is not trusted: the file is read
// again on the next scan (git's "racily clean" rule).
const RacyWindow = 3 * time.Second

// FPCache remembers file fingerprints by their stat data, so a scan reads only files whose size,
// modification time, mode, or identity changed. Files changed within RacyWindow of being read
// are never cached, so a same-size rewrite within one timestamp tick is still seen. The cache is
// per process and never trusted across restarts.
type FPCache struct {
	mu  sync.Mutex
	m   map[string]cacheEntry
	now func() time.Time // for tests; time.Now otherwise
}

type cacheEntry struct {
	size  int64
	mtime int64
	mode  fs.FileMode
	ident uint64
	fp    string
}

// Get returns the cached fingerprint of p if st still matches.
func (c *FPCache) Get(p string, st fs.FileInfo) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[p]
	if !ok || e.size != st.Size() || e.mtime != st.ModTime().UnixNano() || e.mode != st.Mode() || e.ident != fileIdent(st) {
		return "", false
	}
	return e.fp, true
}

// Put records p's fingerprint for st, unless st's file changed too recently to be trusted (or
// claims a modification time in the future), in which case any older entry is dropped.
func (c *FPCache) Put(p string, st fs.FileInfo, fp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cacheEntry{}
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if now().Sub(st.ModTime()) < RacyWindow {
		delete(c.m, p)
		return
	}
	c.m[p] = cacheEntry{st.Size(), st.ModTime().UnixNano(), st.Mode(), fileIdent(st), fp}
}
