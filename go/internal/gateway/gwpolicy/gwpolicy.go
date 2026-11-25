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
}

// Intercept is an intercepted name and its leaf's files (in the gateway's directory).
type Intercept struct {
	Name       string `json:"name"`
	CertChain  string `json:"cert_chain"`
	PrivateKey string `json:"private_key"`
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
