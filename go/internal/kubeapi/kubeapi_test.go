package kubeapi

import (
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// TestDenyRules: the deny-list refuses Secret reads (and the writes that return one), TokenRequest,
// and CSR create and approve, and leaves the rest of the API alone.
func TestDenyRules(t *testing.T) {
	const h = "kube-0.gw.sandbox.internal"
	rules := DenyRules(h)
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		method, path string
		deny         bool
	}{
		{"GET", "/api/v1/secrets", true},
		{"GET", "/api/v1/namespaces/default/secrets", true},
		{"GET", "/api/v1/namespaces/default/secrets/db?watch=true", true},
		{"GET", "/api/v1/watch/namespaces/kube-system/secrets", true},
		{"PATCH", "/api/v1/namespaces/a/secrets/s", true},
		{"DELETE", "/api/v1/namespaces/a/secrets/s", true},
		{"POST", "/api/v1/namespaces/a/secrets", false},
		{"POST", "/api/v1/namespaces/a/serviceaccounts/default/token", true},
		{"POST", "/apis/certificates.k8s.io/v1/certificatesigningrequests", true},
		{"PUT", "/apis/certificates.k8s.io/v1/certificatesigningrequests/c/approval", true},
		{"GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests", false},
		{"GET", "/api/v1/namespaces/default/pods", false},
		{"GET", "/api/v1/namespaces/default/configmaps", false},
		{"POST", "/api/v1/namespaces/a/pods/p/exec", false},
		{"GET", "/apis/apps/v1/deployments", false},
	} {
		p, q, _ := strings.Cut(c.path, "?")
		if ok, i := l7.Decide(rules, h, c.method, p, q); ok == c.deny {
			t.Errorf("%s %s: allowed %v (rule %d)", c.method, c.path, ok, i)
		}
	}
}
