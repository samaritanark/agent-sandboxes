package app

// Tier 3 Kubernetes access, the host's half (design 5.9.5, 5.1.4): the kubeconfigs on the command
// line are read here, never in the VM: `kubectl config view --minify --flatten` (v2's
// minify_kubeconfig, which v2 also ran on the host), one cluster each. Each cluster's credential
// (a bearer token, or a client certificate and its key) is sealed into the broker store bound to
// the cluster's gateway name; the rest (the server, its CA, the context's name and namespace)
// goes to the run in KubeEnv. Only what v2 could use is accepted: static credentials, with v2's
// refusals; exec plugins and auth providers are refused with what to do instead.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// KubeEnv carries the clusters to the run (cli.KubeEnv), a JSON list of kubeCluster.
const KubeEnv = "SANDBOX_INFRA_KUBE"

// kubeName is cluster n's gateway name (sessionspec.KubeName).
func kubeName(n int) string { return fmt.Sprintf("kube-%d.gw.sandbox.internal", n) }

// kubeRef is cluster n's credential in the broker store (cli.KubeRef).
func kubeRef(n int) string { return fmt.Sprintf("infra.kube.%d", n) }

// kubeCluster is one cluster for the run (cli.KubeCluster); value is the credential, never sent.
type kubeCluster struct {
	Context       string `json:"context"`
	Namespace     string `json:"namespace,omitempty"`
	Server        string `json:"server"`
	CA            string `json:"ca,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	Auth          string `json:"auth"`
	Source        string `json:"source"`
	value         []byte
	exec          *execSpec // the exec credential plugin that gives the credential, run on the host
	expires       time.Time // the exec plugin's credential's expiry (zero: none given)
}

// execSpec is a kubeconfig user's exec credential plugin (client.authentication.k8s.io).
type execSpec struct {
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	APIVersion string   `json:"apiVersion"`
	Env        []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"env"`
	InteractiveMode string `json:"interactiveMode"`
}

// kubeconfigView is the part of `kubectl config view -o json` read here.
type kubeconfigView struct {
	CurrentContext string `json:"current-context"`
	Clusters       []struct {
		Cluster struct {
			Server   string `json:"server"`
			CAData   string `json:"certificate-authority-data"`
			TLSName  string `json:"tls-server-name"`
			Insecure bool   `json:"insecure-skip-tls-verify"`
			ProxyURL string `json:"proxy-url"`
		} `json:"cluster"`
	} `json:"clusters"`
	Contexts []struct {
		Name    string `json:"name"`
		Context struct {
			Namespace string `json:"namespace"`
		} `json:"context"`
	} `json:"contexts"`
	Users []struct {
		User struct {
			Token        string          `json:"token"`
			TokenFile    string          `json:"tokenFile"`
			CertData     string          `json:"client-certificate-data"`
			KeyData      string          `json:"client-key-data"`
			Exec         *execSpec       `json:"exec"`
			AuthProvider json.RawMessage `json:"auth-provider"`
		} `json:"user"`
	} `json:"users"`
}

// kubectl runs the host's kubectl (Env.Kubectl in tests), returning its output and its error text.
func (a *app) kubectl(args ...string) ([]byte, string, error) {
	if a.env.Kubectl != nil {
		return a.env.Kubectl(args)
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.Bytes(), errb.String(), err
}

// readKubeconfigs reads the run's --infra-kubeconfig files (with --infra-kube-context for a single
// one), with v2's messages and refusals.
func (a *app) readKubeconfigs(args []string) []kubeCluster {
	paths := optionValues(args, "--infra-kubeconfig")
	if len(paths) == 0 {
		return nil
	}
	ctxs := optionValues(args, "--infra-kube-context")
	ctxName := ""
	if len(ctxs) > 0 {
		ctxName = ctxs[len(ctxs)-1]
	}
	if len(paths) > 16 {
		a.die("at most 16 --infra-kubeconfig per launch.")
	}
	var out []kubeCluster
	used := map[string]bool{}
	for i, p := range paths {
		p = a.expandTilde(p)
		if len(paths) > 1 {
			fmt.Fprintf(a.env.Stdout, "==> Minifying kubeconfig %d/%d: %s (current-context)...\n", i+1, len(paths), p)
		} else {
			c := ctxName
			if c == "" {
				c = "<current-context>"
			}
			fmt.Fprintf(a.env.Stdout, "==> Minifying kubeconfig (context: %s)...\n", c)
		}
		kargs := []string{"config", "view", "--minify", "--flatten", "--raw", "-o", "json", "--kubeconfig=" + p}
		if ctxName != "" && len(paths) == 1 {
			kargs = append(kargs, "--context="+ctxName)
		}
		raw, stderr, err := a.kubectl(kargs...)
		if err != nil {
			var b strings.Builder
			fmt.Fprintf(&b, "kubectl could not minify kubeconfig '%s':", p)
			for _, l := range strings.Split(strings.TrimSpace(stderr+"\n"+errString(err)), "\n") {
				if l != "" {
					b.WriteString("\n  " + l)
				}
			}
			if ctxName != "" {
				fmt.Fprintf(&b, "\n  (context requested: '%s')", ctxName)
			} else {
				b.WriteString("\n  Try --infra-kube-context <NAME> to name a context explicitly.")
			}
			a.die("%s", b.String())
		}
		k, err := parseKubeconfig(raw, p, a.expandTilde)
		if err != nil {
			a.die("%v", err)
		}
		if k.exec != nil {
			a.execCredential(&k, p, args)
		}
		a.adminWarning(p, kargs)
		// v2 kept each context's name, suffixed -2, -3, ... on a collision
		name := k.Context
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s-%d", k.Context, n)
		}
		used[name] = true
		k.Context = name
		out = append(out, k)
	}
	return out
}

// adminWarning is design 5.9.5's check of the identity at launch: `kubectl auth can-i '*' '*'
// --all-namespaces` with the operator's kubeconfig, warning when the credential can do anything
// (cluster-admin or an equivalent). The gateway's deny-list is defense in depth, not authorization.
func (a *app) adminWarning(path string, viewArgs []string) {
	args := []string{"auth", "can-i", "*", "*", "--all-namespaces", "--request-timeout=10s"}
	for _, v := range viewArgs {
		if strings.HasPrefix(v, "--kubeconfig=") || strings.HasPrefix(v, "--context=") {
			args = append(args, v)
		}
	}
	out, _, err := a.kubectl(args...)
	if strings.TrimSpace(string(out)) == "yes" {
		fmt.Fprintf(a.env.Stderr, "WARN: kubeconfig '%s' can do anything in its cluster (cluster-admin or equivalent). Tier 3\n", path)
		fmt.Fprintln(a.env.Stderr, "WARN:   identities must be least-privilege; the sandbox's API deny-list is defense in depth, not a")
		fmt.Fprintln(a.env.Stderr, "WARN:   substitute (docs/how-to/tier3-infra-credentials.md).")
	} else if err != nil && strings.TrimSpace(string(out)) != "no" {
		fmt.Fprintf(a.env.Stdout, "    (could not check what kubeconfig '%s' may do: the cluster did not answer)\n", path)
	}
}

// parseKubeconfig reads one minified kubeconfig into a cluster.
func parseKubeconfig(raw []byte, source string, expand func(string) string) (kubeCluster, error) {
	var v kubeconfigView
	if err := json.Unmarshal(raw, &v); err != nil {
		return kubeCluster{}, fmt.Errorf("kubeconfig '%s': kubectl's output is not a kubeconfig: %v", source, err)
	}
	if len(v.Clusters) != 1 || len(v.Users) != 1 || len(v.Contexts) != 1 {
		return kubeCluster{}, fmt.Errorf("kubeconfig '%s': the minified kubeconfig has %d clusters, %d users, %d contexts (one of each expected)",
			source, len(v.Clusters), len(v.Users), len(v.Contexts))
	}
	cl, u := v.Clusters[0].Cluster, v.Users[0].User
	k := kubeCluster{Context: v.Contexts[0].Name, Namespace: v.Contexts[0].Context.Namespace, Server: cl.Server,
		TLSServerName: cl.TLSName, Source: source}
	if k.Context == "" {
		k.Context = v.CurrentContext
	}
	if k.Context == "" {
		k.Context = "context-0"
	}
	switch {
	case cl.Server == "":
		return k, fmt.Errorf("Could not read cluster.server from minified kubeconfig '%s'.", source)
	case cl.Insecure:
		return k, fmt.Errorf("kubeconfig '%s' sets insecure-skip-tls-verify: the sandbox's gateway verifies every cluster's API server, so it needs the cluster's CA (certificate-authority-data).", source)
	case cl.ProxyURL != "":
		return k, fmt.Errorf("kubeconfig '%s' sets a proxy-url, which the sandbox's gateway does not use: remove it, or reach the cluster directly.", source)
	case len(u.AuthProvider) > 0 && string(u.AuthProvider) != "null":
		return k, fmt.Errorf("kubeconfig '%s' uses an auth-provider, which Kubernetes removed in 1.26: use an exec plugin's static output or a token.", source)
	}
	if cl.CAData != "" {
		ca, err := base64.StdEncoding.DecodeString(cl.CAData)
		if err != nil || !x509.NewCertPool().AppendCertsFromPEM(ca) {
			return k, fmt.Errorf("kubeconfig '%s': certificate-authority-data is not a PEM certificate", source)
		}
		k.CA = string(ca)
	}
	token := u.Token
	if token == "" && u.TokenFile != "" {
		b, err := readLimited(expand(u.TokenFile))
		if err != nil {
			return k, fmt.Errorf("kubeconfig '%s': its token file %s: %v", source, u.TokenFile, err)
		}
		token = strings.TrimSpace(string(b))
		brokerseal.Wipe(b)
	}
	switch {
	case token != "":
		k.Auth, k.value = "token", []byte(token)
	case u.CertData != "" && u.KeyData != "":
		c, err1 := base64.StdEncoding.DecodeString(u.CertData)
		kd, err2 := base64.StdEncoding.DecodeString(u.KeyData)
		if err1 != nil || err2 != nil {
			return k, fmt.Errorf("kubeconfig '%s': client-certificate-data or client-key-data is not base64", source)
		}
		if b, _ := pem.Decode(c); b == nil || b.Type != "CERTIFICATE" {
			return k, fmt.Errorf("kubeconfig '%s': client-certificate-data is not a PEM certificate", source)
		}
		if b, _ := pem.Decode(kd); b == nil || !strings.HasSuffix(b.Type, "PRIVATE KEY") {
			brokerseal.Wipe(kd)
			return k, fmt.Errorf("kubeconfig '%s': client-key-data is not a PEM private key", source)
		}
		k.Auth, k.value = "mtls", append(append(c, '\n'), kd...)
		brokerseal.Wipe(kd)
	case u.Exec != nil && u.Exec.Command != "":
		k.exec = u.Exec // run on the host, once the operator agrees (execCredential)
	default:
		return k, fmt.Errorf("kubeconfig for context '%s' has no static credentials this tool can use (a bearer token, or a client cert+key pair).", k.Context)
	}
	return k, nil
}

// expandTilde is a path with "~" as the operator's home.
func (a *app) expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}

// kubeEnv is the run's KubeEnv setting for the clusters.
func kubeEnv(ks []kubeCluster) string {
	b, _ := json.Marshal(ks)
	return KubeEnv + "=" + string(b)
}

// pushKube seals each cluster's credential bound to its gateway name, and pushes it.
func (a *app) pushKube(ep driver.SSHEndpoint, ks []kubeCluster) {
	if len(ks) == 0 {
		return
	}
	if a.env.BrokerKey == nil {
		a.die("this launch brokers kubeconfig credentials, but this host has no place to keep the credential broker's key.")
	}
	var names []string
	for _, k := range ks {
		names = append(names, k.Context)
	}
	fmt.Fprintf(a.env.Stdout, "==> Sealing this launch's cluster credentials for the sandbox VM: %s\n", strings.Join(names, " "))
	key, err := a.brokerKey()
	if err != nil {
		a.die("%v", err)
	}
	defer brokerseal.Wipe(key)
	for i := range ks {
		k := &ks[i]
		inject := map[string]string{"token": "bearer", "mtls": "mtls"}[k.Auth]
		sealed, err := brokerseal.SealBound(key, kubeRef(i), k.value, brokerseal.Binding{Hosts: []string{kubeName(i)}, Inject: inject})
		brokerseal.Wipe(k.value)
		k.value = nil
		if err != nil {
			a.die("%v", err)
		}
		if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", kubeRef(i)); err != nil {
			a.die("could not store cluster %s's credential in the sandbox VM: %v", k.Context, err)
		}
	}
}
