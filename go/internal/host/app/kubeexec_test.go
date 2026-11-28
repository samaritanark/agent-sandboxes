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
	if argv := strings.Join(tr.runs[len(tr.runs)-1], " "); !strings.Contains(argv, SessionIDEnv+"=ses-") {
		t.Errorf("no session ID for the pump: %q", argv)
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

// TestPump (design 5.9.5): while the operator is attached, an exec plugin's credential is renewed
// before it expires: the plugin runs again, the new credential is sealed into the broker store bound
// as before, and sandboxd hands the session's gateway its credentials again; it stops when the run
// ends, and a plugin that fails stops renewing (logged, never printed on the agent's terminal).
func TestPump(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test plugin is a shell script")
	}
	dir, state := t.TempDir(), t.TempDir()
	plugin := filepath.Join(dir, "aws")
	now := time.Unix(1800000000, 0)
	later := now.Add(time.Hour).UTC().Format(time.RFC3339)
	os.WriteFile(plugin, []byte("#!/bin/sh\necho '{\"kind\":\"ExecCredential\",\"status\":{\"token\":\"renewed-tok\",\"expirationTimestamp\":\""+later+"\"}}'\n"), 0o755)
	k := brokerkey.File{Path: filepath.Join(state, "broker.key")}
	tr := &fakeTransport{release: goodRelease}
	var out bytes.Buffer
	a := &app{env: Env{Transport: tr, StateDir: state, Stdout: &out, Stderr: &out, Now: func() time.Time { return now }, BrokerKey: k},
		ctx: context.Background()}
	if _, err := a.brokerKey(); err != nil { // made at install in real life
		t.Fatal(err)
	}
	out.Reset()
	id := "ses-20270115-080000-beef"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.runPump(ctx, driver.SSHEndpoint{}, id, []pumpJob{{index: 0, exec: &execSpec{Command: plugin, Args: []string{"eks", "get-token"}}, kubeconfig: filepath.Join(dir, "config"),
			inject: "bearer", expires: now.Add(pumpLead)}}) // due now
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(tr.ctl) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(tr.ctl) != 2 || tr.ctl[0][1] != "broker-put" || tr.ctl[0][2] != "infra.kube.0" || tr.ctl[1][1] != "rebind" || tr.ctl[1][2] != id {
		t.Fatalf("ctl %q", tr.ctl)
	}
	key, _ := k.Load()
	v, b, _, err := brokerseal.OpenBound(key, "infra.kube.0", tr.ctlIn[0])
	if err != nil || string(v) != "renewed-tok" || b.Inject != "bearer" || len(b.Hosts) != 1 || b.Hosts[0] != "kube-0.gw.sandbox.internal" {
		t.Errorf("sealed %q %+v %v", v, b, err)
	}
	logb, _ := os.ReadFile(filepath.Join(state, "logs", "token-pump.log"))
	if !strings.Contains(string(logb), id+" cluster 0: credential renewed") || out.Len() != 0 {
		t.Errorf("log %q, terminal %q", logb, out.String())
	}
	// a plugin that fails: logged, nothing stored, and the pump ends by itself
	os.WriteFile(plugin, []byte("#!/bin/sh\nexit 4\n"), 0o755)
	tr.ctl = nil
	a.runPump(context.Background(), driver.SSHEndpoint{}, id, []pumpJob{{index: 0, exec: &execSpec{Command: plugin, Args: []string{"eks", "get-token"}},
		inject: "bearer", expires: now}})
	logb, _ = os.ReadFile(filepath.Join(state, "logs", "token-pump.log"))
	if len(tr.ctl) != 0 || !strings.Contains(string(logb), "failed") {
		t.Errorf("failing plugin: %q %s", tr.ctl, logb)
	}
	// no expiry given: nothing to renew, and the pump ends at once
	tr.ctl = nil
	ended := make(chan struct{})
	go func() {
		a.runPump(context.Background(), driver.SSHEndpoint{}, id, []pumpJob{{index: 0, exec: &execSpec{Command: plugin}}})
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the pump waited on a credential with no expiry")
	}
	if len(tr.ctl) != 0 {
		t.Errorf("a credential with no expiry was renewed: %q", tr.ctl)
	}
}
