// Package broker is the credential broker's decision core (design 5.9, the credential-brokering
// design): which request earns which credential, how it is attached, and what is refused. A
// request earns a credential only when it is bound for one of the binding's destinations and
// presents that binding's placeholder in the binding's place; a request to a bound destination
// without it, and any request carrying one of the session's placeholders anywhere else, is refused
// (the latter recorded as credential_misuse). Unmatched traffic is never relayed with a
// credential. Pure functions over the session's bindings; the ext_proc service (extproc.go)
// applies them, and the scrubber (scrub.go) takes reflected values back out of responses.
//
// Nothing here logs or returns a credential value: decisions carry the binding's reference and
// the header or parameter name only.
package broker

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Binding is one brokered credential of the session, with its value.
type Binding struct {
	Ref         string
	Hosts       []string // exact destinations
	Inject      string   // "bearer", "header:<name>", "query:<name>", "basic"
	Placeholder string
	Value       string // for "basic", "user:password" (the whole pair) or a password alone
}

// Set is a session's bindings.
type Set struct{ bindings []Binding }

var injectRE = regexp.MustCompile(`^(bearer|basic|header:[A-Za-z0-9-]{1,64}|query:[A-Za-z0-9_.-]{1,64})$`)

// placeholderRE finds a placeholder anywhere (sessionspec.PlaceholderPattern, unanchored).
var placeholderRE = regexp.MustCompile(`sbxph_[A-Za-z0-9_-]{43}`)

// hopByHop are the headers a client may not pass through the broker (RFC 9110 7.6.1 and the
// proxy ones); any header a Connection header names is removed too.
var hopByHop = []string{"connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate",
	"te", "trailer", "transfer-encoding", "upgrade"}

// NewSet checks the bindings: exact hosts, a known injection, a well-formed placeholder used once,
// a value.
func NewSet(bs []Binding) (*Set, error) {
	seen := map[string]bool{}
	for _, b := range bs {
		if !injectRE.MatchString(b.Inject) || !placeholderRE.MatchString(b.Placeholder) || len(b.Placeholder) != 49 ||
			seen[b.Placeholder] || b.Value == "" || len(b.Hosts) == 0 {
			return nil, fmt.Errorf("broker: binding %q is malformed", b.Ref)
		}
		if strings.ContainsAny(b.Value, "\r\n\x00") {
			return nil, fmt.Errorf("broker: binding %q has a value no header can carry", b.Ref)
		}
		for _, h := range b.Hosts {
			if h == "" || strings.Contains(h, "*") || h != strings.ToLower(h) {
				return nil, fmt.Errorf("broker: binding %q has a non-exact destination %q", b.Ref, h)
			}
		}
		seen[b.Placeholder] = true
	}
	return &Set{bindings: append([]Binding(nil), bs...)}, nil
}

// Header is one request header as Envoy presents it (lower-case name).
type Header struct{ Name, Value string }

// Request is what the broker sees of a request: the authority it is bound for (the gateway has
// already held it to the connection's name), its ":path" (with the query), and its headers.
type Request struct {
	Host    string
	Path    string
	Headers []Header
}

// Outcome is the broker's answer.
type Outcome struct {
	Refuse bool
	Event  string // "credential_misuse" or "credential_missing" when refused; "" otherwise
	Reason string // for the audit record: never a value
	Ref    string // the binding used or misused, if any

	SetHeaders    []Header // to overwrite (never append)
	RemoveHeaders []string // hop-by-hop and duplicates
	Path          string   // the new ":path" when a query parameter was injected ("" to keep it)
	Injected      bool
}

func refuse(event, ref, reason string) Outcome {
	return Outcome{Refuse: true, Event: event, Ref: ref, Reason: reason}
}

// errAmbiguous is a request the broker will not interpret (duplicate credentials, smuggling).
var errAmbiguous = errors.New("ambiguous")

// Decide answers one request.
func (s *Set) Decide(r Request) Outcome {
	host := strings.TrimSuffix(strings.ToLower(r.Host), ".")
	if h, port, ok := strings.Cut(host, ":"); ok && port == "443" {
		host = h
	}
	// smuggling and header injection guards: no control characters anywhere, one length framing
	if strings.ContainsAny(r.Path, "\r\n\x00") {
		return refuse("", "", "a control character in the path")
	}
	var lengths, codings int
	for _, h := range r.Headers {
		if strings.ContainsAny(h.Value, "\r\n\x00") {
			return refuse("", "", "a control character in header "+h.Name)
		}
		switch h.Name {
		case "content-length":
			lengths++
		case "transfer-encoding":
			codings++
		}
	}
	if lengths > 1 || (lengths > 0 && codings > 0) {
		return refuse("", "", "conflicting message framing")
	}

	// which of the session's placeholders the request carries, and where
	found := map[string]bool{}
	note := func(v string) {
		for _, p := range placeholderRE.FindAllString(v, -1) {
			found[p] = true
		}
		if strings.Contains(v, "%") {
			if d, err := url.QueryUnescape(v); err == nil {
				for _, p := range placeholderRE.FindAllString(d, -1) {
					found[p] = true
				}
			}
		}
	}
	note(r.Path)
	for _, h := range r.Headers {
		note(h.Value)
		if h.Name == "authorization" {
			if rest, ok := cutFold(h.Value, "basic "); ok {
				if d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {
					note(string(d))
				}
			}
		}
	}

	var bound []Binding
	for _, b := range s.bindings {
		for _, h := range b.Hosts {
			if h == host {
				bound = append(bound, b)
				break
			}
		}
	}
	// a placeholder that belongs to no binding of this destination is misuse, whatever else
	for p := range found {
		mine := false
		for _, b := range bound {
			mine = mine || b.Placeholder == p
		}
		if !mine {
			ref := "unknown"
			for _, b := range s.bindings {
				if b.Placeholder == p {
					ref = b.Ref
				}
			}
			return refuse("credential_misuse", ref, "a placeholder sent toward a destination it is not bound to")
		}
	}
	if len(bound) == 0 {
		return Outcome{} // nothing brokered here; the request goes on as it is
	}

	out := Outcome{RemoveHeaders: removals(r.Headers)}
	for _, b := range bound {
		if !found[b.Placeholder] {
			// a bound destination without its placeholder: refused, never relayed bare
			return refuse("credential_missing", b.Ref, "a request to a bound destination without its placeholder")
		}
		set, path, err := inject(b, r)
		if err != nil {
			return refuse("credential_misuse", b.Ref, "the placeholder is not where the binding injects ("+err.Error()+")")
		}
		out.SetHeaders = append(out.SetHeaders, set...)
		if path != "" {
			out.Path = path
			r.Path = path
		}
		out.Ref = b.Ref
		out.Injected = true
	}
	// a header the broker sets is overwritten, never removed (a Connection header may name it)
	var keep []string
	for _, n := range out.RemoveHeaders {
		setting := false
		for _, h := range out.SetHeaders {
			setting = setting || h.Name == n
		}
		if !setting {
			keep = append(keep, n)
		}
	}
	out.RemoveHeaders = keep
	return out
}

// removals are the hop-by-hop headers a request carries and those its Connection header names.
func removals(hs []Header) []string {
	var out []string
	add := func(n string) {
		for _, o := range out {
			if o == n {
				return
			}
		}
		out = append(out, n)
	}
	for _, h := range hs {
		for _, hb := range hopByHop {
			if h.Name == hb && hb != "transfer-encoding" && hb != "te" && hb != "upgrade" {
				add(hb)
			}
		}
		if h.Name == "connection" {
			for _, n := range strings.Split(h.Value, ",") {
				n = strings.ToLower(strings.TrimSpace(n))
				// Envoy needs these to frame and upgrade the request; never let them name the credential
				if n != "" && n != "upgrade" && n != "keep-alive" && n != "close" {
					add(n)
				}
			}
		}
	}
	return out
}

func cutFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// inject places b's value where b's placeholder is: the request must carry the placeholder exactly
// where the binding injects, once.
func inject(b Binding, r Request) ([]Header, string, error) {
	values := func(name string) []string {
		var vs []string
		for _, h := range r.Headers {
			if h.Name == name {
				vs = append(vs, h.Value)
			}
		}
		return vs
	}
	switch {
	case b.Inject == "bearer":
		vs := values("authorization")
		if len(vs) != 1 {
			return nil, "", errAmbiguous
		}
		if rest, ok := cutFold(vs[0], "bearer "); !ok || strings.TrimSpace(rest) != b.Placeholder {
			return nil, "", errors.New("not a bearer placeholder")
		}
		return []Header{{"authorization", "Bearer " + b.Value}}, "", nil
	case b.Inject == "basic":
		vs := values("authorization")
		if len(vs) != 1 {
			return nil, "", errAmbiguous
		}
		rest, ok := cutFold(vs[0], "basic ")
		d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		user, pass, colon := strings.Cut(string(d), ":")
		if !ok || err != nil || !colon || pass != b.Placeholder {
			return nil, "", errors.New("not a basic-auth placeholder")
		}
		pair := b.Value
		if !strings.Contains(pair, ":") {
			pair = user + ":" + b.Value
		}
		return []Header{{"authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(pair))}}, "", nil
	case strings.HasPrefix(b.Inject, "header:"):
		name := strings.ToLower(strings.TrimPrefix(b.Inject, "header:"))
		vs := values(name)
		if len(vs) != 1 || strings.TrimSpace(vs[0]) != b.Placeholder {
			return nil, "", errors.New("not a header placeholder")
		}
		return []Header{{name, b.Value}}, "", nil
	case strings.HasPrefix(b.Inject, "query:"):
		name := strings.TrimPrefix(b.Inject, "query:")
		p, q, _ := strings.Cut(r.Path, "?")
		parts := strings.Split(q, "&")
		hits := 0
		for i, kv := range parts {
			k, v, _ := strings.Cut(kv, "=")
			dk, err1 := url.QueryUnescape(k)
			dv, err2 := url.QueryUnescape(v)
			if err1 == nil && err2 == nil && dk == name && dv == b.Placeholder {
				parts[i] = k + "=" + url.QueryEscape(b.Value)
				hits++
			}
		}
		if hits != 1 {
			return nil, "", errors.New("not a query placeholder")
		}
		return nil, p + "?" + strings.Join(parts, "&"), nil
	}
	return nil, "", errors.New("unknown injection")
}

// Reflections are the forms of a session's values the scrubber takes out of responses, each with
// the placeholder that replaces it: the value, its URL encodings, its base64 forms, and for basic
// auth the encoded pair. A form shorter than 8 bytes is left out (it would match ordinary text).
func (s *Set) Reflections() []Replacement {
	var out []Replacement
	seen := map[string]bool{}
	add := func(v, ph string) {
		if len(v) >= 8 && !seen[v] {
			seen[v] = true
			out = append(out, Replacement{From: []byte(v), To: []byte(ph)})
		}
	}
	for _, b := range s.bindings {
		forms := []string{b.Value, url.QueryEscape(b.Value), url.PathEscape(b.Value),
			base64.StdEncoding.EncodeToString([]byte(b.Value)), base64.RawStdEncoding.EncodeToString([]byte(b.Value)),
			base64.URLEncoding.EncodeToString([]byte(b.Value)), base64.RawURLEncoding.EncodeToString([]byte(b.Value))}
		for _, f := range forms {
			add(f, b.Placeholder)
		}
		if b.Inject == "basic" && strings.Contains(b.Value, ":") {
			add(base64.StdEncoding.EncodeToString([]byte(b.Value)), b.Placeholder)
		}
	}
	return out
}
