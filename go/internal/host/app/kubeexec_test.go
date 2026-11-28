package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// TestExecPlugin: a kubeconfig whose credential comes from an exec plugin has it run on the host
// (with --allow-exec-plugin, or a yes on a terminal; without either it stops, as v2 did), with
// KUBERNETES_EXEC_INFO and its env, a relative command resolved against the kubeconfig; the token or
// client certificate it prints is sealed like a static one. A plugin that fails, prints no
// ExecCredential, or an expired one, stops the launch.
func TestExecPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test plugin is a shell script")
	}
	dir := t.TempDir()
	kcdir := filepath.Join(dir, "kube")
	os.MkdirAll(filepath.Join(kcdir, "bin"), 0o755)
	plugin := func(body string) {
		os.WriteFile(filepath.Join(kcdir, "bin", "aws"), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	exp := time.Unix(1800003600, 0).UTC().Format(time.RFC3339)
	plugin(`case "$KUBERNETES_EXEC_INFO" in *'"kind":"ExecCredential"'*) ;; *) exit 9 ;; esac
[ "$CLUSTER" = prod ] || exit 8
case "$KUBERNETES_EXEC_INFO" in *'"interactive":false'*) ;; *) exit 7 ;; esac
echo '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1","status":{"token":"exec-tok-'"$3"'","expirationTimestamp":"` + exp + `"}}'`)
	user := map[string]any{"exec": map[string]any{"command": "./bin/aws", "args": []string{"eks", "get-token", "x1"}, "apiVersion": "client.authentication.k8s.io/v1",
		"env": []map[string]string{{"name": "CLUSTER", "value": "prod"}}}}
	kubectl := func(args []string) ([]byte, string, error) {
		return view("eks", "https://eks.example.com", user, nil), "", nil
	}
	state := t.TempDir()
	k := brokerkey.File{Path: filepath.Join(state, "broker.key")}
	run := func(stdin string, tty bool, args ...string) (int, *fakeTransport, string, string) {
		tr := &fakeTransport{release: goodRelease}
		var out, errb bytes.Buffer
		rc := Run(context.Background(), append([]string{"run", "--tier", "3", "--infra-kubeconfig", filepath.Join(kcdir, "config")}, args...),
			Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr, Stdin: strings.NewReader(stdin), StdinTTY: tty, Stdout: &out, Stderr: &errb,
				StateDir: state, Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k, Kubectl: kubectl})
		return rc, tr, out.String(), errb.String()
	}
	rc, tr, out, errb := run("", false, "--allow-exec-plugin")
	if rc != 0 || !strings.Contains(out, "==> Cluster eks: credential from the exec plugin './bin/aws' (valid until 2027-01-15 09:00 UTC)") {
		t.Fatalf("%d\n%s\n%s", rc, out, errb)
	}
	key, _ := k.Load()
	sealed := false
	for i, c := range tr.ctl {
		if len(c) == 3 && c[2] == "infra.kube.0" {
			v, b, _, err := brokerseal.OpenBound(key, c[2], tr.ctlIn[i])
			sealed = err == nil && string(v) == "exec-tok-x1" && b.Inject == "bearer"
		}
	}
	if !sealed {
		t.Errorf("the plugin's token was not sealed: %q", tr.ctl)
	}
	// only cluster-scoped plugins run (design 5.9.5): a general-purpose cloud credential, a plugin
	// not on the list, and an always-interactive one are refused before anything runs
	for name, c := range map[string]struct {
		exec map[string]any
		want string
	}{
		"gke":         {map[string]any{"command": "gke-gcloud-auth-plugin"}, "reaches beyond the cluster"},
		"other aws":   {map[string]any{"command": "aws", "args": []string{"sts", "get-session-token"}}, "reaches beyond the cluster"},
		"unknown":     {map[string]any{"command": "./bin/aws-ish"}, "not on the sandbox's list"},
		"interactive": {map[string]any{"command": "tsh", "args": []string{"kube", "credentials"}, "interactiveMode": "Always"}, "interactiveMode: Always"},
	} {
		saved := kubectl
		kubectl = func(args []string) ([]byte, string, error) {
			return view("x", "https://k.example.com", map[string]any{"exec": c.exec}, nil), "", nil
		}
		if rc, tr, _, errb := run("", false, "--allow-exec-plugin"); rc != 1 || len(tr.runs) != 0 || !strings.Contains(errb, c.want) {
			t.Errorf("%s: %d %s", name, rc, errb)
		}
		kubectl = saved
	}
	// on a terminal it asks; no terminal and no flag stops, as v2 did
	if rc, _, _, errb := run("y\n", true); rc != 0 {
		t.Errorf("yes: %d %s", rc, errb)
	}
	for name, c := range map[string]struct {
		stdin string
		tty   bool
		want  string
	}{"no": {"n\n", true, "Aborted"}, "no terminal": {"", false, "Pass --allow-exec-plugin"}} {
		if rc, tr, _, errb := run(c.stdin, c.tty); rc != 1 || !strings.Contains(errb, c.want) || len(tr.runs) != 0 {
			t.Errorf("%s: %d %s", name, rc, errb)
		}
	}
	// a client certificate
	plugin(`printf '{"kind":"ExecCredential","status":{"clientCertificateData":"%s","clientKeyData":"%s"}}' "-----BEGIN CERTIFICATE-----\\nX\\n-----END CERTIFICATE-----" "-----BEGIN PRIVATE KEY-----\\nK\\n-----END PRIVATE KEY-----"`)
	if rc, _, out, errb := run("", false, "--allow-exec-plugin"); rc != 0 || !strings.Contains(out, "(no expiry given)") {
		t.Errorf("certificate: %d %s %s", rc, out, errb)
	}
	for name, body := range map[string]string{
		"fails":      "exit 3",
		"not json":   "echo hello",
		"expired":    `echo '{"kind":"ExecCredential","status":{"token":"t","expirationTimestamp":"2020-01-01T00:00:00Z"}}'`,
		"no token":   `echo '{"kind":"ExecCredential","status":{}}'`,
		"bad header": `printf '{"kind":"ExecCredential","status":{"token":"a\\nb"}}'`,
		"wrong kind": `echo '{"kind":"Other","status":{"token":"t"}}'`,
	} {
		plugin(body)
		if rc, tr, _, errb := run("", false, "--allow-exec-plugin"); rc != 1 || len(tr.runs) != 0 || !strings.Contains(errb, "did not give a credential") {
			t.Errorf("%s: %d %s", name, rc, errb)
		}
	}
}
