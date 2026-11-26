package daemon

// Interception's half in sandboxd (design 5.8.5, 5.10): which names a session's gateway intercepts,
// the leaves it gets for them, the rules it applies, and the trust its guests get.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
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
	// ExtraCADirs hold corporate CAs read again at every session start (the operator's
	// ~/.sandbox/extra-ca-certs as pushed, the image's config/extra-ca-certs): a CA added with
	// `sandbox setup-proxy-cert` applies from the next session, with no reinstall.
	ExtraCADirs []string
}

// MaxExtraCA bounds one extra CA file.
const MaxExtraCA = 1 << 20

// roots are the system roots and the extra CAs: each certificate of each *.crt or *.pem file in
// ExtraCADirs that parses, a file that does not being skipped.
func (t *TLS) roots() []byte {
	out := append([]byte(nil), t.SystemRoots...)
	for _, dir := range t.ExtraCADirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			n := e.Name()
			if !e.Type().IsRegular() || strings.HasPrefix(n, ".") || !(strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".pem")) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil || len(b) > MaxExtraCA {
				continue
			}
			for rest := b; ; {
				var blk *pem.Block
				blk, rest = pem.Decode(rest)
				if blk == nil {
					break
				}
				if blk.Type != "CERTIFICATE" {
					continue
				}
				if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
					continue
				}
				if len(out) > 0 && out[len(out)-1] != '\n' {
					out = append(out, '\n')
				}
				out = append(out, pem.EncodeToMemory(blk)...)
			}
		}
	}
	return out
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

// LeafDir is the gateway's leaves directory: a symlink LiveLeaves in it points at the current
// version (v<n>), and each intercepted name's SDS file, which the gateway writes, sits beside it.
const (
	LeafDir    = "tls"
	LiveLeaves = "live"
)

// sessionLeaves is what renewal needs of a live session's leaves.
type sessionLeaves struct {
	names    []string // in leaf order: <i>.crt is names[i]'s
	notAfter time.Time
	version  int
	dir      string
	slot     int
}

// renewBefore is how long before its leaves expire a session gets new ones: two days, or half
// their life when that is shorter.
func (d *Daemon) renewBefore() time.Duration {
	if v := d.leafValidity() / 2; v < 48*time.Hour {
		return v
	}
	return 48 * time.Hour
}

// leafFiles are leaves by file name, as the gateway runner installs them.
func leafFiles(ls []pki.Leaf, out map[string][]byte) {
	for i, l := range ls {
		out[strconv.Itoa(i)+".crt"] = l.CertPEM
		out[strconv.Itoa(i)+".key"] = l.KeyPEM
	}
}

// renewLeaves gives every live session whose leaves expire soon a new set for the same names.
// A failure is logged and retried at the next tick; the old leaves serve until they expire.
func (d *Daemon) renewLeaves(ctx context.Context, now time.Time) {
	ids := make([]string, 0, len(d.leaves))
	for id := range d.leaves {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sl := d.leaves[id]
		if now.Before(sl.notAfter.Add(-d.renewBefore())) {
			continue
		}
		ls, err := d.TLS.CA.IssueSession(id, sl.names, d.leafValidity(), now)
		if err != nil {
			d.logf("session %s: renewing its leaves: %v", id, err)
			continue
		}
		files := map[string][]byte{}
		leafFiles(ls, files)
		err = d.Gateways.Renew(ctx, id, sl.dir, sl.slot, sl.version+1, files)
		for _, v := range files {
			clear(v)
		}
		if err != nil {
			d.logf("session %s: renewing its leaves: %v", id, err)
			continue
		}
		sl.version++
		sl.notAfter = now.Add(d.leafValidity())
		d.audit(id, auditlog.Events, "tls_leaves_renewed", map[string]any{"names": len(sl.names), "not_after": sl.notAfter.UTC().Format(time.RFC3339)})
	}
}

// gatewayTLS issues the session's leaves into leaves (leafFiles) and fills in each link's
// intercepted names and rules, adding the other files the gateway needs (the upstream roots) to
// files. names[i] are link i's intercepted names. A session that intercepts nothing gets
// nothing, and needs no CA.
func (d *Daemon) gatewayTLS(id, dir string, names [][]string, rules [][]l7.Rule, pol *gwpolicy.Policy, files, leafOut map[string][]byte) (*sessionLeaves, error) {
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
		return nil, nil
	}
	if d.TLS == nil || d.TLS.CA == nil || len(d.TLS.Baseline) == 0 {
		return nil, fmt.Errorf("session %s intercepts %s, but sandboxd has no CA or L7 baseline", id, strings.Join(all, ", "))
	}
	now := d.now()
	leaves, err := d.TLS.CA.IssueSession(id, all, d.leafValidity(), now)
	if err != nil {
		return nil, err
	}
	byName := map[string]int{}
	var order []string
	for i, l := range leaves {
		byName[l.Name] = i
		order = append(order, l.Name)
	}
	leafFiles(leaves, leafOut)
	files["upstream-cas.pem"] = d.TLS.roots()
	pol.UpstreamCAs = filepath.Join(dir, "upstream-cas.pem")
	for i, ns := range names {
		for _, n := range ns {
			k := strconv.Itoa(byName[n])
			pol.Links[i].Intercept = append(pol.Links[i].Intercept, gwpolicy.Intercept{Name: n,
				CertChain: filepath.Join(dir, LeafDir, LiveLeaves, k+".crt"), PrivateKey: filepath.Join(dir, LeafDir, LiveLeaves, k+".key"),
				SDS: filepath.Join(dir, LeafDir, k+".sds.json")})
		}
		if len(ns) > 0 {
			pol.Links[i].L7 = append(append([]l7.Rule(nil), d.TLS.Baseline...), rules[i]...)
		}
	}
	return &sessionLeaves{names: order, notAfter: now.Add(d.leafValidity()), version: 1, dir: dir}, nil
}

// guestTrust writes the session's trust bundle and gateway CA for its guests, and returns their
// mounts and environment; nothing when sandboxd has no CA.
func (d *Daemon) guestTrust(id string) ([]runtime.Mount, []string, error) {
	if d.TLS == nil || d.TLS.CA == nil {
		return nil, nil, nil
	}
	bundle := filepath.Join(d.maskDir(id), "ca-bundle.pem")
	ca := filepath.Join(d.maskDir(id), "gateway-ca.pem")
	if err := os.WriteFile(bundle, pki.Bundle(d.TLS.roots(), d.TLS.CA), 0o444); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(ca, d.TLS.CA.CertPEM, 0o444); err != nil {
		return nil, nil, err
	}
	return []runtime.Mount{{Source: bundle, Target: GuestBundle, ReadOnly: true}, {Source: ca, Target: GuestGatewayCA, ReadOnly: true}},
		append([]string(nil), guestTrustEnv...), nil
}
