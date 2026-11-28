// Package gwpolicy is the policy sandboxd hands a session's gateway process (sandbox-gateway): one
// entry per microVM link (the agent's first) and the dependencies the agent may reach through the
// gateway (design 5.8.6). Data only.
package gwpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// Link is the gateway's side of one microVM's link.
type Link struct {
	Name         string      `json:"name"` // "agent" or the dependency's name
	Listen       netip.Addr  `json:"listen"`
	Ports        []int       `json:"ports"`
	Allow        []string    `json:"allow"`
	BlockDomains []string    `json:"block_domains"`
	Intercept    []Intercept `json:"intercept,omitempty"`
	L7           []l7.Rule   `json:"l7,omitempty"` // the org baseline and the microVM's own rules
	Bindings     []Binding   `json:"bindings,omitempty"`
}

// Binding is a brokered credential of the link's microVM, without its value: the value reaches
// the gateway only through the handover (Handover), from sandboxd's short-lived helper.
type Binding struct {
	Ref         string   `json:"ref"`
	Hosts       []string `json:"hosts"`
	Inject      string   `json:"inject"`
	Placeholder string   `json:"placeholder"`
	Prefix      string   `json:"prefix,omitempty"` // before the placeholder (sessionspec.Binding.Prefix)
	// the broker's limits (sessionspec.Binding)
	RatePerMinute int `json:"rate_per_minute,omitempty"`
	Burst         int `json:"burst,omitempty"`
	Quota         int `json:"quota,omitempty"`
}

// HandoverSocket is the socket in the gateway's directory the helper writes the values to; only
// root may write it.
const HandoverSocket = "handover.sock"

// Handover carries the session's credential values, by link and reference ([]byte, so the sender
// can wipe them).
type Handover struct {
	Links []map[string][]byte `json:"links"`
}

// Intercept is an intercepted name and its leaf's files (in the gateway's directory).
type Intercept struct {
	Name       string `json:"name"`
	CertChain  string `json:"cert_chain"`
	PrivateKey string `json:"private_key"`
	SDS        string `json:"sds,omitempty"`  // the gateway writes the leaf's SDS file here (envoyconf.Intercept)
	Kube       *Kube  `json:"kube,omitempty"` // a tier 3 cluster's gateway name: its API server
}

// Kube is a cluster's API server (envoyconf.Kube): files are absolute paths the gateway may read.
type Kube struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	PathPrefix string `json:"path_prefix,omitempty"`
	SNI        string `json:"sni"`
	CAFile     string `json:"ca_file,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

// Dep is a dependency the agent reaches at <name>.deps.sandbox.internal:<port>.
type Dep struct {
	Name string     `json:"name"`
	Port int        `json:"port"`
	Addr netip.Addr `json:"addr"`
}

// Policy is the whole file.
type Policy struct {
	Links     []Link       `json:"links"`
	Deps      []Dep        `json:"deps"`
	Resolvers []netip.Addr `json:"resolvers"`
	// UpstreamCAs is the roots intercepted upstreams are verified against
	UpstreamCAs string `json:"upstream_cas,omitempty"`
	// Generation counts the policy's versions: a running gateway reloads its policy on SIGHUP
	// (`sandbox allow`) and then writes the generation it serves to ReloadedFile in its directory
	Generation int `json:"generation,omitempty"`
}

// ReloadedFile is where, in its directory, a gateway writes the generation of the policy it
// serves after a reload.
const ReloadedFile = "reloaded"

// SameShape reports whether q differs from p only in what a running gateway can take on a
// reload: each link's allowlist and blocked names, and the generation. Its links, their
// addresses, ports, bindings, interception, and rules, the dependencies, and the resolvers stay.
func (p *Policy) SameShape(q *Policy) error {
	a, b := *p, *q
	a.Generation, b.Generation = 0, 0
	if len(a.Links) != len(b.Links) {
		return errors.New("the links changed")
	}
	al, bl := append([]Link(nil), a.Links...), append([]Link(nil), b.Links...)
	for i := range al {
		al[i].Allow, al[i].BlockDomains = nil, nil
		bl[i].Allow, bl[i].BlockDomains = nil, nil
	}
	a.Links, b.Links = al, bl
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		return errors.New("more than the allowlists changed")
	}
	return nil
}

// Decode reads a policy strictly.
func Decode(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if len(p.Links) == 0 || len(p.Resolvers) == 0 {
		return nil, errors.New("gateway policy: links and resolvers are required")
	}
	for _, l := range p.Links {
		if !l.Listen.IsValid() || len(l.Ports) == 0 {
			return nil, errors.New("gateway policy: every link needs an address and ports")
		}
		for _, r := range l.L7 {
			if err := r.Validate(); err != nil {
				return nil, fmt.Errorf("gateway policy: %w", err)
			}
		}
		if len(l.Intercept) > 0 && p.UpstreamCAs == "" {
			return nil, errors.New("gateway policy: interception needs the upstream roots")
		}
	}
	return &p, nil
}
