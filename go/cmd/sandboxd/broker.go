package main

// The broker store and the credential handover (design 5.9.2, D-32). sandboxd keeps the store key
// in memory only (the host pushes it from its keychain at VM start) and never decrypts a value
// itself: a long-lived Go process cannot wipe what it decrypted. At a session's start it runs a
// short-lived copy of itself (__broker-handover) and writes the key and the session's bound
// references to its stdin, synchronously; the helper decrypts only those, writes them to the
// gateway's handover socket, wipes its buffers, and exits.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
)

type brokerStore struct {
	store brokerstore.Store
	mu    sync.Mutex
	key   []byte
}

func (b *brokerStore) SetKey(k []byte) error {
	if len(k) != brokerstore.KeySize {
		return errors.New("the broker key must be 32 bytes")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	brokerstore.Wipe(b.key)
	b.key = append([]byte(nil), k...)
	return nil
}

func (b *brokerStore) Put(ref string, sealed []byte) error { return b.store.Put(ref, sealed) }
func (b *brokerStore) Bindings() (map[string]brokerseal.Binding, error) {
	return b.store.Bindings()
}
func (b *brokerStore) Delete(ref string) error { return b.store.Delete(ref) }
func (b *brokerStore) List() ([]string, error) { return b.store.List() }

// handoverJob is what the helper reads on its stdin.
type handoverJob struct {
	Key    []byte         `json:"key"`
	Store  string         `json:"store"`
	Socket string         `json:"socket"`
	Links  [][]daemon.Use `json:"links"`
}

func (b *brokerStore) HandOver(ctx context.Context, session, socket string, refs [][]daemon.Use) error {
	b.mu.Lock()
	if b.key == nil {
		b.mu.Unlock()
		return errors.New("the broker key has not been pushed from the host (run 'sandbox vm start' there)")
	}
	job, err := json.Marshal(handoverJob{Key: b.key, Store: b.store.Dir, Socket: socket, Links: refs})
	b.mu.Unlock()
	if err != nil {
		return err
	}
	defer brokerstore.Wipe(job)
	return runHelper(ctx, "__broker-handover", "handover helper", job)
}

// readableJob is what the readable helper reads on its stdin.
type readableJob struct {
	Key   []byte            `json:"key"`
	Store string            `json:"store"`
	Dir   string            `json:"dir"`
	UID   int               `json:"uid"`
	Files map[string]string `json:"files"` // file name: reference
}

func (b *brokerStore) WriteReadable(ctx context.Context, dir string, uid int, files map[string]string) error {
	b.mu.Lock()
	if b.key == nil {
		b.mu.Unlock()
		return errors.New("the broker key has not been pushed from the host (run 'sandbox vm start' there)")
	}
	job, err := json.Marshal(readableJob{Key: b.key, Store: b.store.Dir, Dir: dir, UID: uid, Files: files})
	b.mu.Unlock()
	if err != nil {
		return err
	}
	defer brokerstore.Wipe(job)
	return runHelper(ctx, "__readable-handover", "readable-secrets helper", job)
}

// runHelper runs a short-lived copy of sandboxd with job on its stdin, written synchronously.
func runHelper(ctx context.Context, mode, what string, job []byte) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, mode)
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return err
	}
	// written synchronously, and only then wiped (S5: exec's own copy is asynchronous)
	_, werr := in.Write(job)
	in.Close()
	if err := cmd.Wait(); err != nil || werr != nil {
		return fmt.Errorf("the %s failed: %s", what, strings.TrimSpace(out.String()))
	}
	return nil
}

// readableHandover is the readable helper: decrypt each file's reference into its own file,
// readable only by the agent's user, wipe, exit.
func readableHandover() int {
	fail := func(err error) int { fmt.Fprintln(os.Stderr, err); return 1 }
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fail(err)
	}
	defer brokerstore.Wipe(raw)
	var job readableJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return fail(fmt.Errorf("unreadable job: %w", err))
	}
	defer brokerstore.Wipe(job.Key)
	if err := writeReadable(job); err != nil {
		return fail(err)
	}
	return 0
}

// writeReadable does the helper's work.
func writeReadable(job readableJob) error {
	st := brokerstore.Store{Dir: job.Store}
	for name, ref := range job.Files {
		if !validFileName(name) {
			return fmt.Errorf("readable secret: bad file name %q", name)
		}
		sealed, err := st.Get(ref)
		if err != nil {
			return fmt.Errorf("credential %s is not in the broker store", ref)
		}
		v, b, bound, err := brokerseal.OpenBound(job.Key, ref, sealed)
		if err != nil {
			return err
		}
		if err = b.Allows(nil, "", true); !bound {
			err = errors.New("it was sealed without a binding")
		}
		if err != nil {
			brokerstore.Wipe(v)
			return fmt.Errorf("credential %s may not be read by the agent: %w", ref, err)
		}
		err = writeOwned(filepath.Join(job.Dir, name), v, job.UID)
		brokerstore.Wipe(v)
		if err != nil {
			return err
		}
	}
	if err := os.Chown(job.Dir, job.UID, -1); err != nil {
		return err
	}
	return os.Chmod(job.Dir, 0o500)
}

// validFileName: one path component, as a variable name is.
func validFileName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\x00")
}

// writeOwned creates p afresh (never through a link), readable only by uid.
func writeOwned(p string, v []byte, uid int) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o400)
	if err != nil {
		return err
	}
	_, err = f.Write(v)
	if err == nil {
		err = f.Chown(uid, -1) // the mode leaves the group nothing
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// brokerHandover is the helper: decrypt the job's references, hand them over, wipe, exit.
func brokerHandover() int {
	fail := func(err error) int { fmt.Fprintln(os.Stderr, err); return 1 }
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fail(err)
	}
	defer brokerstore.Wipe(raw)
	var job handoverJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return fail(fmt.Errorf("unreadable job: %w", err))
	}
	defer brokerstore.Wipe(job.Key)
	h, opened, err := openLinks(brokerstore.Store{Dir: job.Store}, job.Key, job.Links)
	defer func() {
		for _, v := range opened {
			brokerstore.Wipe(v)
		}
	}()
	if err != nil {
		return fail(err)
	}
	msg, err := json.Marshal(h)
	if err != nil {
		return fail(err)
	}
	defer brokerstore.Wipe(msg)
	var c net.Conn
	for i := 0; ; i++ {
		if c, err = net.DialTimeout("unix", job.Socket, 2*time.Second); err == nil {
			break
		}
		if i > 50 {
			return fail(fmt.Errorf("the gateway's handover socket: %w", err))
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(msg); err != nil {
		return fail(err)
	}
	c.(*net.UnixConn).CloseWrite()
	reply, _ := bufio.NewReader(c).ReadString('\n')
	if strings.TrimSpace(reply) != "ok" {
		return fail(fmt.Errorf("the gateway refused the handover: %s", strings.TrimSpace(reply)))
	}
	return 0
}

// openLinks opens each link's credentials for the gateway, each checked against the binding the
// host sealed with it: an operator secret must carry one, and every binding of it in the spec must
// be one its binding allows. opened is every value opened, for the caller to wipe, error or not.
func openLinks(st brokerstore.Store, key []byte, links [][]daemon.Use) (h gwpolicy.Handover, opened [][]byte, err error) {
	for _, uses := range links {
		m := map[string][]byte{}
		for _, u := range uses {
			sealed, err := st.Get(u.Ref)
			if err != nil {
				return h, opened, fmt.Errorf("credential %s is not in the broker store", u.Ref)
			}
			v, b, bound, err := brokerseal.OpenBound(key, u.Ref, sealed)
			if err != nil {
				return h, opened, err
			}
			opened = append(opened, v)
			if _, secret := brokerseal.SecretName(u.Ref); secret && !bound {
				return h, opened, fmt.Errorf("credential %s was sealed without a binding", u.Ref)
			}
			if bound {
				if err := b.Allows(u.Hosts, u.Inject, false); err != nil {
					return h, opened, fmt.Errorf("credential %s: %w", u.Ref, err)
				}
			}
			m[u.Ref] = v
		}
		h.Links = append(h.Links, m)
	}
	return h, opened, nil
}
