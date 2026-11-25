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
	"strings"
	"sync"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
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
func (b *brokerStore) Delete(ref string) error             { return b.store.Delete(ref) }
func (b *brokerStore) List() ([]string, error)             { return b.store.List() }

// handoverJob is what the helper reads on its stdin.
type handoverJob struct {
	Key    []byte     `json:"key"`
	Store  string     `json:"store"`
	Socket string     `json:"socket"`
	Links  [][]string `json:"links"`
}

func (b *brokerStore) HandOver(ctx context.Context, session, socket string, refs [][]string) error {
	b.mu.Lock()
	if b.key == nil {
		b.mu.Unlock()
		return errors.New("the broker key has not been pushed from the host")
	}
	job, err := json.Marshal(handoverJob{Key: b.key, Store: b.store.Dir, Socket: socket, Links: refs})
	b.mu.Unlock()
	if err != nil {
		return err
	}
	defer brokerstore.Wipe(job)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "__broker-handover")
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
		return fmt.Errorf("the handover helper failed: %s", strings.TrimSpace(out.String()))
	}
	return nil
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
	st := brokerstore.Store{Dir: job.Store}
	h := gwpolicy.Handover{}
	var opened [][]byte
	defer func() {
		for _, v := range opened {
			brokerstore.Wipe(v)
		}
	}()
	for _, refs := range job.Links {
		m := map[string][]byte{}
		for _, ref := range refs {
			sealed, err := st.Get(ref)
			if err != nil {
				return fail(fmt.Errorf("credential %s is not in the broker store", ref))
			}
			v, err := brokerstore.Open(job.Key, ref, sealed)
			if err != nil {
				return fail(err)
			}
			opened = append(opened, v)
			m[ref] = v
		}
		h.Links = append(h.Links, m)
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
