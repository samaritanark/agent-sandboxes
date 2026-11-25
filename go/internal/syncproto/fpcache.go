package syncproto

import (
	"io/fs"
	"sync"
)

// FPCache remembers file fingerprints by their stat data, so a scan reads only files whose size,
// modification time, mode, or identity changed. A false hit needs a file rewritten in place with
// the same size within the same nanosecond timestamp, which a sync pass then sees on the next
// change; the cache is per process and never trusted across restarts.
type FPCache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
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

// Put records p's fingerprint for st.
func (c *FPCache) Put(p string, st fs.FileInfo, fp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cacheEntry{}
	}
	c.m[p] = cacheEntry{st.Size(), st.ModTime().UnixNano(), st.Mode(), fileIdent(st), fp}
}
