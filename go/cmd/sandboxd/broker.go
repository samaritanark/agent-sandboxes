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
	"encoding/pem"
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

// kubeJob is the kube helper's job: each cluster's client certificate to write (file base name:
// its reference and gateway name).
type kubeJob struct {
	Key   []byte                       `json:"key"`
	Store string                       `json:"store"`
	Dir   string                       `json:"dir"`
	UID   int                          `json:"uid"`
	Certs map[string]daemon.ClientCert `json:"certs"`
}

func (b *brokerStore) WriteClientCerts(ctx context.Context, dir string, uid int, certs map[string]daemon.ClientCert) error {
	b.mu.Lock()
	if b.key == nil {
		b.mu.Unlock()
		return errors.New("the broker key has not been pushed from the host (run 'sandbox vm start' there)")
	}
	job, err := json.Marshal(kubeJob{Key: b.key, Store: b.store.Dir, Dir: dir, UID: uid, Certs: certs})
	b.mu.Unlock()
	if err != nil {
		return err
	}
	defer brokerstore.Wipe(job)
	return runHelper(ctx, "__kube-handover", "client-certificate helper", job)
}

// kubeHandover is the kube helper: decrypt each cluster's client certificate and key into files
// readable only by the gateway's user, wipe, exit.
func kubeHandover() int {
	fail := func(err error) int { fmt.Fprintln(os.Stderr, err); return 1 }
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fail(err)
	}
	defer brokerstore.Wipe(raw)
	var job kubeJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return fail(fmt.Errorf("unreadable job: %w", err))
	}
	defer brokerstore.Wipe(job.Key)
	if err := writeClientCerts(job); err != nil {
		return fail(err)
	}
	return 0
}

// writeClientCerts does the kube helper's work: an entry is used only if it was sealed with an
// mtls binding to the cluster's gateway name, and only as its certificate and key.
func writeClientCerts(job kubeJob) error {
	st := brokerstore.Store{Dir: job.Store}
	for name, c := range job.Certs {
		if !validFileName(name) {
			return fmt.Errorf("client certificate: bad file name %q", name)
		}
		sealed, err := st.Get(c.Ref)
		if err != nil {
			return fmt.Errorf("credential %s is not in the broker store", c.Ref)
		}
		v, b, bound, err := brokerseal.OpenBound(job.Key, c.Ref, sealed)
		if err != nil {
			return err
		}
		if err = b.Allows([]string{c.Host}, "mtls", false); !bound {
			err = errors.New("it was sealed without a binding")
		}
		if err == nil && (len(b.Hosts) != 1 || b.Hosts[0] != c.Host) {
			err = fmt.Errorf("it is bound to %v, not %s alone", b.Hosts, c.Host)
		}
		if err != nil {
			brokerstore.Wipe(v)
			return fmt.Errorf("credential %s is not %s's client certificate: %w", c.Ref, c.Host, err)
		}
		cert, key, err := splitCertKey(v)
		brokerstore.Wipe(v)
		if err == nil {
			err = writeOwned(filepath.Join(job.Dir, name+".crt"), cert, job.UID)
		}
		if err == nil {
			err = writeOwned(filepath.Join(job.Dir, name+".key"), key, job.UID)
		}
		brokerstore.Wipe(key)
		if err != nil {
			return err
		}
	}
	if err := os.Chown(job.Dir, job.UID, -1); err != nil {
		return err
	}
	return os.Chmod(job.Dir, 0o500)
}

// splitCertKey separates a client credential's PEM blocks: the certificates (the client's first,
// then any chain) and its one private key.
func splitCertKey(v []byte) (cert, key []byte, err error) {
	rest := v
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			cert = append(cert, pem.EncodeToMemory(blk)...)
		case strings.HasSuffix(blk.Type, "PRIVATE KEY"):
			if key != nil {
				return nil, nil, errors.New("more than one private key")
			}
			key = pem.EncodeToMemory(blk)
		}
	}
	if cert == nil || key == nil {
		return nil, nil, errors.New("not a PEM certificate and private key")
	}
	return cert, key, nil
}

// runHelper runs a short-lived copy of sandboxd with job on its stdin, written synchronously.
func runHelper(ctx context.Context, mode, what string, job []byte) error {
	_, err := runHelperOut(ctx, mode, what, job)
	return err
}

// runHelperOut is runHelper returning the helper's standard output (its result; never a value).
func runHelperOut(ctx context.Context, mode, what string, job []byte) ([]byte, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, mode)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// written synchronously, and only then wiped (S5: exec's own copy is asynchronous)
	_, werr := in.Write(job)
	in.Close()
	if err := cmd.Wait(); err != nil || werr != nil {
		return nil, fmt.Errorf("the %s failed: %s", what, strings.TrimSpace(errb.String()+out.String()))
	}
	return out.Bytes(), nil
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
// mtlsMarker is what the gateway's broker gets for a client-certificate binding: not the value.
const mtlsMarker = "client-certificate"

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
			if u.Inject == "mtls" {
				// the gateway's Envoy presents the certificate from its own files (kubeHandover);
				// the broker only checks and removes the placeholder, so it never holds the key
				m[u.Ref] = []byte(mtlsMarker)
				continue
			}
			m[u.Ref] = v
		}
		h.Links = append(h.Links, m)
	}
	return h, opened, nil
}
