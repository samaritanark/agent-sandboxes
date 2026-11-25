// Package gwpolicy is the policy sandboxd hands a session's gateway process (sandbox-gateway): one
// entry per microVM link (the agent's first) and the dependencies the agent may reach through the
// gateway (design 5.8.6). Data only.
package gwpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
)

// Link is the gateway's side of one microVM's link.
type Link struct {
	Name         string     `json:"name"` // "agent" or the dependency's name
	Listen       netip.Addr `json:"listen"`
	Ports        []int      `json:"ports"`
	Allow        []string   `json:"allow"`
	BlockDomains []string   `json:"block_domains"`
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
	}
	return &p, nil
}
