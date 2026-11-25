// Package journal is sandboxd's persistent, reconciled state machine (design 5.4.3 item 10,
// D-23). Each session is one record: its spec, its state, and every resource it owns. A
// resource is journaled before it is created and marked released after it is removed, so after
// a crash or reboot sandboxd knows exactly what may exist and can finish or roll back a partial
// start and tear down orphans before it accepts new sessions.
//
// Records are JSON files written atomically (temporary file, fsync, rename, directory fsync).
package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// State is a session's lifecycle state.
type State string

const (
	Requested  State = "REQUESTED"
	Admitted   State = "ADMITTED"
	Starting   State = "STARTING"
	Running    State = "RUNNING"
	Stopping   State = "STOPPING"
	Terminated State = "TERMINATED"
	Failed     State = "FAILED"
)

// next are the allowed transitions; FAILED is reachable from every state but TERMINATED.
var next = map[State][]State{
	Requested: {Admitted, Stopping},
	Admitted:  {Starting, Stopping},
	Starting:  {Running, Stopping},
	Running:   {Stopping},
	Stopping:  {Terminated},
	Failed:    {Stopping}, // a failed session is torn down like any other
}

// CanTransition reports whether from may move to to.
func CanTransition(from, to State) bool {
	if to == Failed {
		return from != Terminated && from != Failed
	}
	for _, s := range next[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Ended reports whether a session in s holds nothing more to tear down once its resources are
// released.
func (s State) Ended() bool { return s == Terminated }

// ResourceState is where one owned resource is.
type ResourceState string

const (
	Intended   ResourceState = "intended"            // journaled; may or may not exist yet
	Created    ResourceState = "created"             // exists
	Released   ResourceState = "released"            // removed
	Incomplete ResourceState = "teardown-incomplete" // removal failed; recorded for the audit log
)

// Resource is one thing a session owns: a containerd container or task, a microVM, a network
// namespace, a link, an nftables set, a gateway or broker process, a binding, a mount, a
// directory. Kind and Name together identify it.
type Resource struct {
	Kind  string        `json:"kind"`
	Name  string        `json:"name"`
	State ResourceState `json:"state"`
	Note  string        `json:"note,omitempty"`
}

// Event is one line of a session's history.
type Event struct {
	At   time.Time `json:"at"`
	What string    `json:"what"`
}

// Session is one journaled session.
type Session struct {
	ID        string            `json:"id"`
	State     State             `json:"state"`
	Spec      *sessionspec.Spec `json:"spec"`
	EndReason string            `json:"end_reason,omitempty"`
	Resources []Resource        `json:"resources"`
	Events    []Event           `json:"events"`
	Created   time.Time         `json:"created"`
	Updated   time.Time         `json:"updated"`
}

// Live is every resource that may still exist (intended, created, or not removable).
func (s *Session) Live() []Resource {
	var out []Resource
	for _, r := range s.Resources {
		if r.State != Released {
			out = append(out, r)
		}
	}
	return out
}

// Store is the journal directory.
type Store struct {
	Dir string
	Now func() time.Time // for tests; time.Now otherwise

	mu sync.Mutex
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$`)

// ErrExists and ErrNotFound are returned by Create and the updates.
var (
	ErrExists   = errors.New("journal: session already exists")
	ErrNotFound = errors.New("journal: no such session")
)

func (st *Store) now() time.Time {
	if st.Now != nil {
		return st.Now()
	}
	return time.Now().UTC()
}

func (st *Store) path(id string) string { return filepath.Join(st.Dir, id+".json") }

// Create journals a new session in REQUESTED.
func (st *Store) Create(spec *sessionspec.Spec) (*Session, error) {
	if spec == nil || !idRE.MatchString(spec.ID) {
		return nil, errors.New("journal: invalid session id")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := os.MkdirAll(st.Dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(st.path(spec.ID)); err == nil {
		return nil, ErrExists
	}
	now := st.now()
	s := &Session{ID: spec.ID, State: Requested, Spec: spec, Created: now, Updated: now,
		Events: []Event{{now, "requested"}}}
	return s, st.write(s)
}

// Load reads one session.
func (st *Store) Load(id string) (*Session, error) {
	if !idRE.MatchString(id) {
		return nil, ErrNotFound
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.read(id)
}

func (st *Store) read(id string) (*Session, error) {
	b, err := os.ReadFile(st.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("journal %s: %w", id, err)
	}
	if s.ID != id {
		return nil, fmt.Errorf("journal %s: record names session %q", id, s.ID)
	}
	return &s, nil
}

// List reads every session, oldest first. A record that cannot be read is an error: reconciling
// around it would leave its resources unaccounted for.
func (st *Store) List() ([]*Session, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	ents, err := os.ReadDir(st.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Session
	for _, e := range ents {
		name := e.Name()
		if filepath.Ext(name) != ".json" || !e.Type().IsRegular() {
			continue
		}
		s, err := st.read(name[:len(name)-len(".json")])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// update applies f to session id and writes it back; f's error aborts without writing.
func (st *Store) update(id string, f func(*Session) error) (*Session, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, err := st.read(id)
	if err != nil {
		return nil, err
	}
	if err := f(s); err != nil {
		return nil, err
	}
	s.Updated = st.now()
	return s, st.write(s)
}

// Transition moves a session to to, recording why. Moving to TERMINATED needs every resource
// released or recorded as teardown-incomplete.
func (st *Store) Transition(id string, to State, why string) (*Session, error) {
	return st.update(id, func(s *Session) error {
		if !CanTransition(s.State, to) {
			return fmt.Errorf("journal %s: %s -> %s is not allowed", id, s.State, to)
		}
		if to == Terminated {
			for _, r := range s.Resources {
				if r.State == Intended || r.State == Created {
					return fmt.Errorf("journal %s: %s %s is still %s", id, r.Kind, r.Name, r.State)
				}
			}
		}
		if (to == Stopping || to == Failed) && s.EndReason == "" {
			s.EndReason = why
		}
		s.State = to
		s.Events = append(s.Events, Event{st.now(), fmt.Sprintf("%s: %s", to, why)})
		return nil
	})
}

func (s *Session) find(kind, name string) int {
	for i, r := range s.Resources {
		if r.Kind == kind && r.Name == name {
			return i
		}
	}
	return -1
}

func checkResource(kind, name string) error {
	if !nameRE.MatchString(kind) || !nameRE.MatchString(name) {
		return fmt.Errorf("journal: invalid resource %q %q", kind, name)
	}
	return nil
}

// Intend journals a resource before it is created. A session that is stopping, failed, or
// terminated takes no new resources.
func (st *Store) Intend(id, kind, name string) error {
	if err := checkResource(kind, name); err != nil {
		return err
	}
	_, err := st.update(id, func(s *Session) error {
		switch s.State {
		case Stopping, Terminated, Failed:
			return fmt.Errorf("journal %s: no new resources while %s", id, s.State)
		}
		if i := s.find(kind, name); i >= 0 && s.Resources[i].State != Released {
			return nil // already journaled (a retried step)
		} else if i >= 0 {
			s.Resources[i].State = Intended
			return nil
		}
		s.Resources = append(s.Resources, Resource{Kind: kind, Name: name, State: Intended})
		return nil
	})
	return err
}

// Mark records a resource's new state (Created, Released, or Incomplete with a note).
func (st *Store) Mark(id, kind, name string, to ResourceState, note string) error {
	if err := checkResource(kind, name); err != nil {
		return err
	}
	_, err := st.update(id, func(s *Session) error {
		i := s.find(kind, name)
		if i < 0 {
			return fmt.Errorf("journal %s: %s %s was never journaled", id, kind, name)
		}
		switch to {
		case Created, Released, Incomplete:
		default:
			return fmt.Errorf("journal: cannot mark a resource %s", to)
		}
		s.Resources[i].State, s.Resources[i].Note = to, note
		if to == Incomplete {
			s.Events = append(s.Events, Event{st.now(), fmt.Sprintf("teardown-incomplete: %s %s: %s", kind, name, note)})
		}
		return nil
	})
	return err
}

// write stores s atomically and durably.
func (st *Store) write(s *Session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(st.Dir, "."+s.ID+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), st.path(s.ID)); err != nil {
		return err
	}
	d, err := os.Open(st.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
