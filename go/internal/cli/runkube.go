package cli

// Tier 3 Kubernetes access (design 5.9.5). The host reads each --infra-kubeconfig itself (kubectl
// config view --minify --flatten, as v2 did), seals each cluster's credential into the broker
// store bound to the cluster's gateway name, and passes the run the clusters' other details in
// KubeEnv. The run checks each API server against the block lists (as v2 did), and the session
// gets: the clusters in its spec, each name on its allowlist, a binding with a placeholder for
// each credential, and a generated kubeconfig at v2's path that names each cluster by its gateway
// name, trusts the gateway's CA, and holds only placeholders.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// KubeEnv carries the run's clusters from the host (a JSON list of KubeCluster).
const KubeEnv = "SANDBOX_INFRA_KUBE"

// KubeCluster is one cluster as the host read it from a kubeconfig: no credential, only what
// names and reaches the cluster, and how the credential the host sealed is used.
type KubeCluster struct {
	Context       string `json:"context"`             // the context's name, kept for use-context
	Namespace     string `json:"namespace,omitempty"` // the context's namespace
	Server        string `json:"server"`
	CA            string `json:"ca,omitempty"` // PEM
	TLSServerName string `json:"tls_server_name,omitempty"`
	Auth          string `json:"auth"`   // "token" or "mtls"
	Source        string `json:"source"` // the kubeconfig on the host, for messages
}

// KubeRef is cluster n's credential in the broker store.
func KubeRef(n int) string { return fmt.Sprintf("infra.kube.%d", n) }

// Where the agent finds its kubeconfig: a read-only directory of its own under ~/.kube (which stays
// writable for kubectl's caches), named by KUBECONFIG; and the gateway's CA in the guest
// (sandboxd's GuestGatewayCA).
const (
	KubeconfigDir  = "/home/agent/.kube/sandbox"
	KubeconfigPath = KubeconfigDir + "/config"
	guestGatewayCA = "/etc/ssl/sandbox/gateway-ca.pem"
	// KubeDir is where in the session's directory the run writes the kubeconfig.
	KubeDir = "kube"
)

// kubeClusters reads KubeEnv: nil when the host passed none.
func (c *cmdCtx) kubeClusters() ([]KubeCluster, error) {
	raw := c.env.Getenv(KubeEnv)
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var ks []KubeCluster
	if err := dec.Decode(&ks); err != nil || dec.More() {
		return nil, fmt.Errorf("the host's kubeconfig description is malformed: %v", err)
	}
	if len(ks) == 0 || len(ks) > sessionspec.MaxKube {
		return nil, fmt.Errorf("the host described %d clusters (1 to %d)", len(ks), sessionspec.MaxKube)
	}
	seen := map[string]bool{}
	for i, k := range ks {
		if k.Context == "" || seen[k.Context] {
			return nil, fmt.Errorf("cluster %d: missing or repeated context name %q", i, k.Context)
		}
		seen[k.Context] = true
		if k.Auth != "token" && k.Auth != "mtls" {
			return nil, fmt.Errorf("cluster %d: unknown credential kind %q", i, k.Auth)
		}
		if err := sessionspec.CheckKubeServer(k.Server); err != nil {
			return nil, fmt.Errorf("kubeconfig '%s': %v", k.Source, err)
		}
	}
	return ks, nil
}

// checkKubeServers is v2's check of each API server: its host, and the address it resolves to,
// against the block lists; a server that resolves to loopback is refused (a guest's 127.0.0.1 is
// its own).
func (c *cmdCtx) checkKubeServers(ks []KubeCluster) {
	chk := c.checks()
	for _, k := range ks {
		u, _ := url.Parse(k.Server)
		host := u.Hostname()
		c.out("  Cluster API: %s (context %s)", k.Server, k.Context)
		w, err := chk.CheckEgressTargetNotBlocked(host)
		for _, l := range w {
			c.warn("%s", l)
		}
		if err != nil {
			c.fail(err)
		}
		addrs := []netip.Addr{}
		if a, err := netip.ParseAddr(host); err == nil {
			addrs = append(addrs, a)
		} else if ips, err := c.lookupHost(host); err == nil {
			addrs = append(addrs, ips...)
		}
		for _, a := range addrs {
			if a.IsLoopback() || a.IsUnspecified() {
				c.die("kubeconfig '%s' server resolves to loopback (%s); a sandbox's 127.0.0.1 is its own, not your machine. Rewrite the server address with examples/k3d-podman/bake-kubeconfig.sh.", k.Source, a)
			}
			if a.Is4() {
				w, err := chk.CheckIPNotInBlockedCIDRs(a.String())
				for _, l := range w {
					c.warn("%s", l)
				}
				if err != nil {
					c.fail(err)
				}
			}
		}
	}
}

// lookupHost resolves a name in the VM (Env.LookupHost in tests).
func (c *cmdCtx) lookupHost(h string) ([]netip.Addr, error) {
	if c.env.LookupHost != nil {
		return c.env.LookupHost(h)
	}
	ips, err := net.LookupIP(h)
	var out []netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, err
}

// bindKube puts the clusters in the spec: each gateway name on the allowlist, each credential's
// binding (the host sealed it as infra.kube.<n>, bound to that name), and the agent's kubeconfig,
// which it returns with the report lines.
func (c *cmdCtx) bindKube(spec *sessionspec.Spec, ks []KubeCluster) ([]byte, []string) {
	var lines []string
	type cluster struct {
		Server string `json:"server"`
		CA     string `json:"certificate-authority"`
	}
	type context struct {
		Cluster   string `json:"cluster"`
		User      string `json:"user"`
		Namespace string `json:"namespace,omitempty"`
	}
	var clusters, contexts, users []map[string]any
	for i, k := range ks {
		name := sessionspec.KubeName(i)
		ref := KubeRef(i)
		inject := map[string]string{"token": "bearer", "mtls": "mtls"}[k.Auth]
		if c.env.CredentialBinding == nil {
			c.die("'run' with --infra-kubeconfig needs the sandbox VM's credential broker.")
		}
		b, ok := c.env.CredentialBinding(ref)
		if !ok || b.Inject != inject || len(b.Hosts) != 1 || b.Hosts[0] != name {
			c.die("cluster %s's credential is not in the sandbox VM's broker as the host sealed it; run the launch again from the host.", k.Context)
		}
		ph := placeholder()
		spec.Kube = append(spec.Kube, sessionspec.KubeCluster{Name: name, Server: k.Server, CA: k.CA, TLSServerName: k.TLSServerName})
		spec.Egress.Allow = append(spec.Egress.Allow, name)
		spec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: ref, Hosts: []string{name}, Inject: inject, Placeholder: ph})
		cn, un := fmt.Sprintf("sandbox-cluster-%d", i), fmt.Sprintf("sandbox-user-%d", i)
		clusters = append(clusters, map[string]any{"name": cn, "cluster": cluster{Server: "https://" + name, CA: guestGatewayCA}})
		contexts = append(contexts, map[string]any{"name": k.Context, "context": context{Cluster: cn, User: un, Namespace: k.Namespace}})
		users = append(users, map[string]any{"name": un, "user": map[string]string{"token": ph}})
		what := "token"
		if k.Auth == "mtls" {
			what = "client certificate"
		}
		lines = append(lines, fmt.Sprintf("==> Cluster %s: %s through the gateway (%s brokered; Secrets, TokenRequest, and CSRs refused)", k.Context, k.Server, what))
	}
	cfg := map[string]any{"apiVersion": "v1", "kind": "Config", "clusters": clusters, "contexts": contexts, "users": users,
		"current-context": ks[0].Context, "preferences": map[string]any{}}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		c.fail(errors.New("cannot write the session's kubeconfig"))
	}
	return buf.Bytes(), lines
}
