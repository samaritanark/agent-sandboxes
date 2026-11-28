package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// Tier 3 clusters (design 5.9.5): each cluster's gateway name is intercepted (its binding names
// it) and gets its API server as its upstream: the CA goes to a file in the gateway's directory,
// and an mtls cluster's client certificate and key, decrypted by the broker, to a directory of
// the session's on a tmpfs, readable only by the gateway's user. The deny-list's rules are added
// with the session's own L7 rules.

// ClientCert is one mtls cluster's credential: its broker reference and the gateway name it is
// bound to.
type ClientCert struct {
	Ref, Host string
}

func (d *Daemon) kubeCertDir(id string) string { return filepath.Join(d.KubeRoot, id) }

// kubeUpstreams sets each cluster's upstream on its intercepted name in pol, adding its CA to
// files and writing mtls clusters' client certificates.
func (d *Daemon) kubeUpstreams(ctx context.Context, spec *sessionspec.Spec, gwDir string, slot int, pol *gwpolicy.Policy, files map[string][]byte) error {
	if len(spec.Kube) == 0 {
		return nil
	}
	certs := map[string]ClientCert{}
	for i, k := range spec.Kube {
		for _, b := range spec.Bindings {
			if b.Inject == "mtls" && len(b.Hosts) == 1 && b.Hosts[0] == k.Name {
				certs[fmt.Sprintf("kube-%d", i)] = ClientCert{Ref: b.Ref, Host: k.Name}
			}
		}
	}
	certDir := ""
	if len(certs) > 0 {
		if d.Broker == nil || d.KubeRoot == "" {
			return errors.New("the session has client-certificate clusters, but sandboxd has no broker store or tmpfs for them")
		}
		id := spec.ID
		certDir = d.kubeCertDir(id)
		if err := d.step(id, KindKubeCerts, "kube-certs", func() error {
			if err := os.MkdirAll(d.KubeRoot, 0o711); err != nil {
				return err
			}
			return os.Mkdir(certDir, 0o700)
		}); err != nil {
			return err
		}
		if err := d.Broker.WriteClientCerts(ctx, certDir, d.Gateways.User(slot), certs); err != nil {
			return fmt.Errorf("client certificates: %w", err)
		}
	}
	for i, k := range spec.Kube {
		ic := -1
		for j, x := range pol.Links[0].Intercept {
			if x.Name == k.Name {
				ic = j
			}
		}
		if ic < 0 {
			return fmt.Errorf("cluster %s is not intercepted (no binding names it)", k.Name)
		}
		host, port, prefix, sni := k.Upstream()
		ku := &gwpolicy.Kube{Host: host, Port: port, PathPrefix: prefix, SNI: sni}
		if k.CA != "" {
			name := fmt.Sprintf("kube-%d.ca", i)
			files[name] = []byte(k.CA)
			ku.CAFile = filepath.Join(gwDir, name)
		}
		if c := fmt.Sprintf("kube-%d", i); certs[c].Ref != "" {
			ku.ClientCert, ku.ClientKey = filepath.Join(certDir, c+".crt"), filepath.Join(certDir, c+".key")
		}
		pol.Links[0].Intercept[ic].Kube = ku
	}
	return nil
}
