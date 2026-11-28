package broker

import (
	"strings"
	"testing"
)

// TestRiskyWorkload (design 5.9.5): a pod, a controller's template, a custom resource, or a patch
// that asks for a privileged container, a hostPath volume, or a node namespace is refused, and so is
// a body the broker cannot read; an ordinary workload, and text that only mentions those words, pass.
func TestRiskyWorkload(t *testing.T) {
	for name, c := range map[string]struct {
		ct, body, want string
	}{
		"pod":               {"application/json", `{"kind":"Pod","spec":{"containers":[{"name":"a","image":"x"}]}}`, ""},
		"privileged":        {"application/json", `{"kind":"Pod","spec":{"containers":[{"securityContext":{"privileged":true}}]}}`, "privileged container"},
		"not privileged":    {"application/json", `{"spec":{"containers":[{"securityContext":{"privileged":false}}]}}`, ""},
		"hostPath":          {"application/json", `{"spec":{"volumes":[{"name":"root","hostPath":{"path":"/"}}]}}`, "hostPath volume"},
		"hostNetwork":       {"application/json", `{"kind":"Deployment","spec":{"template":{"spec":{"hostNetwork":true}}}}`, "network namespace (hostNetwork)"},
		"hostPID cronjob":   {"application/json", `{"spec":{"jobTemplate":{"spec":{"template":{"spec":{"hostPID":true}}}}}}`, "pid namespace (hostPID)"},
		"crd":               {"application/json", `{"kind":"Workflow","spec":{"templates":[{"podSpecPatch":{"hostIPC":true}}]}}`, "ipc namespace"},
		"merge patch":       {"application/merge-patch+json", `{"spec":{"template":{"spec":{"hostNetwork":true}}}}`, "hostNetwork"},
		"strategic":         {"application/strategic-merge-patch+json; charset=utf-8", `{"spec":{"volumes":[{"hostPath":{"path":"/var"}}]}}`, "hostPath"},
		"json patch":        {"application/json-patch+json", `[{"op":"add","path":"/spec/template/spec/hostNetwork","value":true}]`, "hostNetwork"},
		"json patch value":  {"application/json-patch+json", `[{"op":"add","path":"/spec/volumes/-","value":{"name":"r","hostPath":{"path":"/"}}}]`, "hostPath"},
		"json patch priv":   {"application/json-patch+json", `[{"op":"replace","path":"/spec/containers/0/securityContext/privileged","value":true}]`, "privileged"},
		"json patch benign": {"application/json-patch+json", `[{"op":"replace","path":"/spec/replicas","value":3}]`, ""},
		"configmap text":    {"application/json", `{"kind":"ConfigMap","data":{"x":"hostNetwork: true\nprivileged: true"}}`, ""},
		"apply as json":     {"application/apply-patch+yaml", `{"spec":{"hostNetwork":true}}`, "hostNetwork"},
		"apply as yaml":     {"application/apply-patch+yaml", "spec:\n  hostNetwork: true\n", "not JSON"},
		"protobuf":          {"application/vnd.kubernetes.protobuf", "\x6b\x38\x73\x00", "does not inspect"},
		"empty":             {"application/json", ``, ""},
	} {
		got := riskyWorkload(c.ct, []byte(c.body))
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q", name, got)
		}
	}
}
