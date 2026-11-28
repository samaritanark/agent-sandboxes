package netd

// The host's half of declared endpoints (design 5.2.6): a launch declares the host endpoints its
// session may reach, under the session's ID and with an expiry no later than the session's longest
// possible life, and the host removes them once the session is no longer live. The worker re-reads
// the file on every decision.

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// Declare opens eps for session until expires, replacing what the session declared before.
func Declare(dir, session string, eps []netip.AddrPort, expires time.Time, now time.Time) error {
	if !sessionRE.MatchString(session) {
		return errors.New("not a session id: " + session)
	}
	for _, ep := range eps {
		if !ep.Addr().Is4() || ep.Port() == 0 {
			return errors.New("not an IPv4 address and port: " + ep.String())
		}
	}
	return editEndpoints(dir, func(es []Endpoint) []Endpoint {
		var out []Endpoint
		for _, e := range es {
			if e.Session != session && (e.Expires.IsZero() || now.Before(e.Expires)) {
				out = append(out, e)
			}
		}
		for _, ep := range eps {
			out = append(out, Endpoint{Addr: ep, Session: session, Expires: expires})
		}
		return out
	})
}

// Release closes the endpoints of every session live does not report as live, and every expired
// one; entries the operator wrote by hand (no session) stay.
func Release(dir string, live func(session string) bool, now time.Time) error {
	return editEndpoints(dir, func(es []Endpoint) []Endpoint {
		var out []Endpoint
		for _, e := range es {
			if (e.Expires.IsZero() || now.Before(e.Expires)) && (e.Session == "" || live(e.Session)) {
				out = append(out, e)
			}
		}
		return out
	})
}

// Declared is the sessions that hold declared endpoints.
func Declared(dir string) ([]string, error) {
	es, err := ReadEndpoints(filepath.Join(dir, EndpointsName))
	seen := map[string]bool{}
	var out []string
	for _, e := range es {
		if e.Session != "" && !seen[e.Session] {
			seen[e.Session] = true
			out = append(out, e.Session)
		}
	}
	return out, err
}

// editEndpoints rewrites the endpoints file whole under its lock; an unparseable file is not
// overwritten (the worker refuses everything until the operator fixes it).
func editEndpoints(dir string, edit func([]Endpoint) []Endpoint) error {
	unlock, err := lockEndpoints(filepath.Join(dir, EndpointsName+".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(dir, EndpointsName)
	es, err := ReadEndpoints(path)
	if err != nil {
		return err
	}
	out := edit(es)
	if len(out) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, formatEndpoints(out), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
