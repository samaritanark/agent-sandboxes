package daemon

// Interception's half in sandboxd (design 5.8.5, 5.10): which names a session's gateway intercepts,
// the leaves it gets for them, the rules it applies, and the trust its guests get.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/pki"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// TLS is what interception needs: the gateway CA, the org's L7 baseline (applied to every
// intercepted destination, whatever the spec says), and the VM's trust store (the system roots
// and the operator's corporate CAs), which intercepted upstreams are verified against.
type TLS struct {
	CA          *pki.CA
	Baseline    []l7.Rule
	SystemRoots []byte
}

// Where the guests find the session's trust: the bundle (system roots, corporate CAs, and the
// gateway CA) and the gateway CA alone (for tools that add to their own roots).
const (
	GuestBundle    = "/etc/ssl/sandbox/ca-bundle.pem"
	GuestGatewayCA = "/etc/ssl/sandbox/gateway-ca.pem"
)

// guestTrustEnv points the common TLS stacks at the bundle.
var guestTrustEnv = []string{
	"SSL_CERT_FILE=" + GuestBundle, "REQUESTS_CA_BUNDLE=" + GuestBundle, "CURL_CA_BUNDLE=" + GuestBundle,
	"PIP_CERT=" + GuestBundle, "GIT_SSL_CAINFO=" + GuestBundle, "NODE_EXTRA_CA_CERTS=" + GuestGatewayCA,
}

// interceptNames are the names a microVM's traffic is intercepted for: every L7 rule's own host
// and every binding's destination, normalized, each once, sorted.
func interceptNames(e sessionspec.Egress, bs []sessionspec.Binding) []string {
	seen := map[string]bool{}
	for _, r := range e.L7 {
		if r.Host != l7.AnyHost {
			seen[egressmatch.Normalize(r.Host)] = true
		}
	}
	for _, b := range bs {
		for _, h := range b.Hosts {
			seen[egressmatch.Normalize(h)] = true
		}
	}
	var out []string
	for n := range seen {
		if n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// leafValidity is how long a session's leaves last: the longest a session may live.
func (d *Daemon) leafValidity() time.Duration {
	max := d.Expiry.KeepAliveMax
	if max <= 0 {
		max = limits.DefaultKeepAliveMax
	}
	return max + 24*time.Hour
}

// gatewayTLS issues the session's leaves and fills in each link's intercepted names and rules,
// adding the files the gateway needs (leaves and the upstream roots) to files. names[i] are link
// i's intercepted names. A session that intercepts nothing gets nothing, and needs no CA.
func (d *Daemon) gatewayTLS(id, dir string, names [][]string, rules [][]l7.Rule, pol *gwpolicy.Policy, files map[string][]byte) error {
	var all []string
	seen := map[string]bool{}
	for _, ns := range names {
		for _, n := range ns {
			if !seen[n] {
				seen[n] = true
				all = append(all, n)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	if d.TLS == nil || d.TLS.CA == nil || len(d.TLS.Baseline) == 0 {
		return fmt.Errorf("session %s intercepts %s, but sandboxd has no CA or L7 baseline", id, strings.Join(all, ", "))
	}
	leaves, err := d.TLS.CA.IssueSession(id, all, d.leafValidity(), d.now())
	if err != nil {
		return err
	}
	byName := map[string]int{}
	for i, l := range leaves {
		byName[l.Name] = i
		files[filepath.Join("tls", strconv.Itoa(i)+".crt")] = l.CertPEM
		files[filepath.Join("tls", strconv.Itoa(i)+".key")] = l.KeyPEM
	}
	files["upstream-cas.pem"] = d.TLS.SystemRoots
	pol.UpstreamCAs = filepath.Join(dir, "upstream-cas.pem")
	for i, ns := range names {
		for _, n := range ns {
			k := strconv.Itoa(byName[n])
			pol.Links[i].Intercept = append(pol.Links[i].Intercept, gwpolicy.Intercept{Name: n,
				CertChain: filepath.Join(dir, "tls", k+".crt"), PrivateKey: filepath.Join(dir, "tls", k+".key")})
		}
		if len(ns) > 0 {
			pol.Links[i].L7 = append(append([]l7.Rule(nil), d.TLS.Baseline...), rules[i]...)
		}
	}
	return nil
}

// guestTrust writes the session's trust bundle and gateway CA for its guests, and returns their
// mounts and environment; nothing when sandboxd has no CA.
func (d *Daemon) guestTrust(id string) ([]runtime.Mount, []string, error) {
	if d.TLS == nil || d.TLS.CA == nil {
		return nil, nil, nil
	}
	bundle := filepath.Join(d.maskDir(id), "ca-bundle.pem")
	ca := filepath.Join(d.maskDir(id), "gateway-ca.pem")
	if err := os.WriteFile(bundle, pki.Bundle(d.TLS.SystemRoots, d.TLS.CA), 0o444); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(ca, d.TLS.CA.CertPEM, 0o444); err != nil {
		return nil, nil, err
	}
	return []runtime.Mount{{Source: bundle, Target: GuestBundle, ReadOnly: true}, {Source: ca, Target: GuestGatewayCA, ReadOnly: true}},
		append([]string(nil), guestTrustEnv...), nil
}
