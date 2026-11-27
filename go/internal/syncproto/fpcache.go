package syncproto

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
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
// modification time, mode, or identity (inode and change time, which no program can set) changed.
// Files changed within RacyWindow of being read are never cached, so a same-size rewrite within
// one timestamp tick is still seen. SaveFile and LoadFile keep it across runs in a file the
// scanned tree cannot reach: an entry is trusted only while the file's stat data is unchanged,
// which holds as well across runs as within one.
type FPCache struct {
	mu    sync.Mutex
	m     map[string]cacheEntry
	used  map[string]bool  // the entries this run's scans matched or made, the ones a save keeps
	dirty bool             // changed since loaded or saved
	now   func() time.Time // for tests; time.Now otherwise
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
	c.use(p)
	return e.fp, true
}

func (c *FPCache) use(p string) {
	if c.used == nil {
		c.used = map[string]bool{}
	}
	c.used[p] = true
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
		if _, ok := c.m[p]; ok {
			delete(c.m, p)
			c.dirty = true
		}
		return
	}
	c.m[p] = cacheEntry{st.Size(), st.ModTime().UnixNano(), st.Mode(), fileIdent(st), fp}
	c.use(p)
	c.dirty = true
}

// Dirty says the cache changed since it was loaded or last saved.
func (c *FPCache) Dirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dirty
}

// cacheFileVersion names the file form; a file of any other form is ignored.
const cacheFileVersion = "sandbox-fpcache-1"

// cacheFile is the file form: the entries by path.
type cacheFile struct {
	V string               `json:"v"`
	E map[string]cacheJSON `json:"e"`
}

type cacheJSON struct {
	S int64  `json:"s"`
	T int64  `json:"t"`
	M uint32 `json:"m"`
	I uint64 `json:"i"`
	F string `json:"f"`
}

// maxCacheFile bounds what LoadFile reads (MaxEntries entries of a few hundred bytes each).
const maxCacheFile = 256 << 20

// LoadFile replaces the cache's entries with those saved in file. A missing, unreadable, or
// malformed file leaves the cache empty: every file is fingerprinted again, as on a first run.
func (c *FPCache) LoadFile(file string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m, c.used, c.dirty = map[string]cacheEntry{}, nil, false
	if !identKnown {
		return // without an inode and change time, only this run's entries are trusted
	}
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	var cf cacheFile
	if json.NewDecoder(io.LimitReader(f, maxCacheFile)).Decode(&cf) != nil || cf.V != cacheFileVersion || len(cf.E) > MaxEntries {
		return
	}
	for p, e := range cf.E {
		c.m[p] = cacheEntry{e.S, e.T, fs.FileMode(e.M), e.I, e.F}
	}
}

// SaveFile writes the entries this run used to file (mode 0600, replaced whole), so that files
// gone since are dropped. It writes nothing when nothing changed.
func (c *FPCache) SaveFile(file string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !identKnown || len(c.used) == 0 || !c.dirty && len(c.used) == len(c.m) {
		return nil // nothing scanned this run, or nothing to change
	}
	cf := cacheFile{V: cacheFileVersion, E: make(map[string]cacheJSON, len(c.used))}
	for p := range c.used {
		if e, ok := c.m[p]; ok {
			cf.E[p] = cacheJSON{e.size, e.mtime, uint32(e.mode), e.ident, e.fp}
		}
	}
	b, err := json.Marshal(cf)
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		os.Remove(tmp)
		return err
	}
	c.dirty = false
	return nil
}
