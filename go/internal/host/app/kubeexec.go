package app

// Exec credential plugins (aws eks get-token, gke-gcloud-auth-plugin, kubelogin): v2 copied the
// kubeconfig into the pod, where the plugin and its configuration were absent, so every kubectl call
// failed at auth (it warned, and asked, or --allow-exec-plugin skipped the question). v3 runs the
// plugin here, on the operator's machine with the operator's own configuration, once at launch,
// after the same question (or --allow-exec-plugin), and brokers the credential it returns like a
// static one. It is not renewed: when it expires the session's kubectl gets 401 and a new launch
// gets a new one.

import (
	"bytes"
	"context"

	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// execCredential runs k's exec plugin, if the operator agrees, and takes its credential.
func (a *app) execCredential(k *kubeCluster, kubeconfig string, args []string) {
	e := k.exec
	fmt.Fprintf(a.env.Stderr, "WARN: kubeconfig '%s' gets its credential from the exec plugin '%s'.\n", kubeconfig, e.Command)
	fmt.Fprintln(a.env.Stderr, "WARN:   The sandbox runs it here, on this machine, once now, and brokers the credential it")
	fmt.Fprintln(a.env.Stderr, "WARN:   returns for the session; it is not renewed, so kubectl in the session fails once it expires.")
	switch {
	case hasFlag(args, "--allow-exec-plugin"):
		fmt.Fprintln(a.env.Stderr, "WARN:   --allow-exec-plugin set; running it.")
	case !a.env.StdinTTY:
		a.die("stdin is not a TTY, so the exec plugin cannot be agreed to. Pass --allow-exec-plugin to run it, or bake static credentials (docs/how-to/tier3-infra-credentials.md).")
	default:
		fmt.Fprint(a.env.Stderr, "  Run it now? [y/N] ")
		line, _ := readLine(a.env.Stdin)
		if l := strings.TrimSpace(line); l != "y" && l != "Y" && l != "yes" && l != "YES" {
			a.die("Aborted. Bake static credentials and retry, or re-run with --allow-exec-plugin.")
		}
	}
	cred, err := a.runExecPlugin(e, kubeconfig)
	if err != nil {
		a.die("the exec plugin '%s' for kubeconfig '%s' did not give a credential: %v", e.Command, kubeconfig, err)
	}
	until := "no expiry given"
	if !cred.expires.IsZero() {
		until = "valid until " + cred.expires.UTC().Format("2006-01-02 15:04 UTC")
	}
	if cred.token != "" {
		k.Auth, k.value = "token", []byte(cred.token)
	} else {
		k.Auth, k.value = "mtls", append(append([]byte(cred.cert), '\n'), cred.key...)
	}
	fmt.Fprintf(a.env.Stdout, "==> Cluster %s: credential from the exec plugin '%s' (%s)\n", k.Context, e.Command, until)
}

func hasFlag(args []string, f string) bool {
	for _, x := range args {
		if x == f {
			return true
		}
	}
	return false
}

type execCred struct {
	token, cert, key string
	expires          time.Time
}

// runExecPlugin runs the plugin as kubectl does (its env, KUBERNETES_EXEC_INFO, a relative command
// resolved against the kubeconfig's directory) and reads the ExecCredential it prints.
func (a *app) runExecPlugin(e *execSpec, kubeconfig string) (execCred, error) {
	cmdPath := e.Command
	if strings.Contains(cmdPath, "/") && !filepath.IsAbs(cmdPath) {
		cmdPath = filepath.Join(filepath.Dir(kubeconfig), cmdPath)
	}
	api := e.APIVersion
	if api == "" {
		api = "client.authentication.k8s.io/v1"
	}
	interactive := a.env.StdinTTY && e.InteractiveMode != "Never"
	info, _ := json.Marshal(map[string]any{"apiVersion": api, "kind": "ExecCredential", "spec": map[string]any{"interactive": interactive}})
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute) // a browser sign-in may take a while
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdPath, e.Args...)
	cmd.Env = append(os.Environ(), "KUBERNETES_EXEC_INFO="+string(info))
	for _, v := range e.Env {
		cmd.Env = append(cmd.Env, v.Name+"="+v.Value)
	}
	if interactive {
		cmd.Stdin = a.env.Stdin
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, a.env.Stderr
	if err := cmd.Run(); err != nil {
		return execCred{}, err
	}
	var c struct {
		Kind   string `json:"kind"`
		Status *struct {
			Token      string `json:"token"`
			Cert       string `json:"clientCertificateData"`
			Key        string `json:"clientKeyData"`
			Expiration string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out.Bytes(), &c); err != nil || c.Kind != "ExecCredential" || c.Status == nil {
		return execCred{}, fmt.Errorf("it printed no ExecCredential")
	}
	r := execCred{token: strings.TrimSpace(c.Status.Token), cert: c.Status.Cert, key: c.Status.Key}
	if c.Status.Expiration != "" {
		t, err := time.Parse(time.RFC3339, c.Status.Expiration)
		if err != nil {
			return execCred{}, fmt.Errorf("its expirationTimestamp %q is not a time", c.Status.Expiration)
		}
		if !t.After(a.env.Now()) {
			return execCred{}, fmt.Errorf("its credential expired at %s", c.Status.Expiration)
		}
		r.expires = t
	}
	switch {
	case r.token != "":
		if strings.ContainsAny(r.token, "\r\n\x00") {
			return execCred{}, fmt.Errorf("its token is not a header value")
		}
	case r.cert != "" && r.key != "":
		// PEM, as the API documents (not base64 like a kubeconfig's *-data fields)
		if !strings.Contains(r.cert, "-----BEGIN CERTIFICATE-----") || !strings.Contains(r.key, "PRIVATE KEY-----") {
			return execCred{}, fmt.Errorf("its client certificate or key is not PEM")
		}
	default:
		return execCred{}, fmt.Errorf("its ExecCredential has no token and no client certificate")
	}
	return r, nil
}
