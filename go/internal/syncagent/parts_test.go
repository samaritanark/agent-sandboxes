package syncagent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

func rig(t *testing.T) (string, *os.Root, *syncproto.FPCache, *partial) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return dir, root, &syncproto.FPCache{}, &partial{}
}

// TestWritePart: a file sent in parts is put in place only whole and as fingerprinted; parts out
// of order, a size that is not a large file's, a whole that does not match, and a path changed
// since the base are refused, and nothing partial is left behind.
func TestWritePart(t *testing.T) {
	dir, root, cache, parts := rig(t)
	data := bytes.Repeat([]byte("x"), syncproto.MaxBody+10)
	fp, _, _ := syncproto.FingerprintReader(bytes.NewReader(data), false)
	half := syncproto.MaxBody / 2
	send := func(h syncproto.Header, body []byte) syncproto.Header {
		h.Op, h.Path, h.FP, h.Size = syncproto.OpWritePart, "d/big.bin", fp, int64(len(data))
		r, _ := handle(root, cache, parts, h, body)
		return r
	}
	leftovers := func() {
		t.Helper()
		if l, _ := filepath.Glob(filepath.Join(dir, "d", ".sandbox-sync-*")); len(l) != 0 {
			t.Errorf("left behind: %v", l)
		}
	}
	// in order: written whole
	if r := send(syncproto.Header{}, data[:half]); r.Err != "" || r.FP != "" {
		t.Fatalf("first part: %+v", r)
	}
	if r := send(syncproto.Header{Offset: int64(half)}, data[half:]); r.Err != "" || r.FP != fp {
		t.Fatalf("last part: %+v", r)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "d/big.bin")); !bytes.Equal(got, data) {
		t.Fatal("not written whole")
	}
	leftovers()
	// out of order: refused, dropped
	send(syncproto.Header{Base: fp}, data[:half])
	if r := send(syncproto.Header{Offset: int64(half) + 1}, data[half+1:]); r.Err == "" {
		t.Error("a part out of order was taken")
	}
	leftovers()
	// a whole that does not match the fingerprint: refused, the old file kept
	bad := append([]byte(nil), data...)
	bad[len(bad)-1] = 'y'
	send(syncproto.Header{Base: fp}, bad[:half])
	if r := send(syncproto.Header{Base: fp, Offset: int64(half)}, bad[half:]); !strings.Contains(r.Err, "do not make the file") {
		t.Errorf("a mismatched whole: %+v", r)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "d/big.bin")); !bytes.Equal(got, data) {
		t.Error("the mismatched file replaced the old one")
	}
	leftovers()
	// the path changed since the base: a conflict, at the first part
	if r := send(syncproto.Header{Base: "file:00"}, data[:half]); !r.Conflict || r.FP != fp {
		t.Errorf("stale base: %+v", r)
	}
	// a size that is not sent in parts, or more than the limit
	for _, size := range []int64{10, syncproto.MaxLarge + 1} {
		h := syncproto.Header{Op: syncproto.OpWritePart, Path: "e.bin", FP: fp, Size: size}
		if r, _ := handle(root, cache, parts, h, []byte("x")); r.Err == "" {
			t.Errorf("size %d taken", size)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "e.bin")); err == nil {
		t.Error("e.bin written")
	}
}

// TestLargeScanAndRead: a scan reports a large file's fingerprint only when asked (Large), as
// "other" otherwise; reading it returns TooLarge and no bytes.
func TestLargeScanAndRead(t *testing.T) {
	dir, root, cache, parts := rig(t)
	data := bytes.Repeat([]byte("z"), syncproto.MaxBody+1)
	os.WriteFile(filepath.Join(dir, "big"), data, 0o644)
	fp, _, _ := syncproto.FingerprintReader(bytes.NewReader(data), false)
	for large, want := range map[bool]string{false: "other", true: fp} {
		r, _ := handle(root, cache, parts, syncproto.Header{Op: syncproto.OpScan, Large: large}, nil)
		if len(r.Entries) != 1 || r.Entries[0].FP != want {
			t.Errorf("large %v: %+v", large, r.Entries)
		}
	}
	r, body := handle(root, cache, parts, syncproto.Header{Op: syncproto.OpRead, Path: "big"}, nil)
	if !r.TooLarge || r.FP != fp || len(body) != 0 {
		t.Errorf("read: %+v, %d bytes", r, len(body))
	}
}
