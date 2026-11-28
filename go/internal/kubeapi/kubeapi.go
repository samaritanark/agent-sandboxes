// Package kubeapi is the minimal API-server deny-list a tier 3 session's gateway applies to each
// cluster (design 5.9.5, credential brokering "Kubeconfigs are the flagship case"). It is defense
// in depth, not authorization: the identity must be least-privilege. It refuses what turns a
// cluster credential into other credentials:
//
//   - reading Secrets: get, list, and watch, and also update, patch, and delete, whose responses
//     carry the whole object, data included (creating one returns only what the agent sent);
//   - TokenRequest (a service account's token);
//   - creating and approving CertificateSigningRequests (a client certificate the cluster trusts).
//
// Workloads that would reach the node (hostPath, privileged, hostNetwork) need the request body
// and are refused by the broker, not here.
package kubeapi

import "github.com/samaritanark/agent-sandboxes/go/internal/l7"

// DenyRules are the deny-list as L7 rules for the cluster's gateway name host.
func DenyRules(host string) []l7.Rule {
	return []l7.Rule{
		{Host: host, Methods: []string{"GET", "PUT", "PATCH", "DELETE"}, Action: l7.Deny, PathPatterns: []string{
			"/api/v1/secrets/**",
			"/api/v1/namespaces/*/secrets/**",
			"/api/v1/watch/secrets/**",
			"/api/v1/watch/namespaces/*/secrets/**",
		}},
		{Host: host, Methods: []string{"POST"}, Action: l7.Deny, PathPatterns: []string{
			"/api/v1/namespaces/*/serviceaccounts/*/token",
			"/apis/certificates.k8s.io/*/certificatesigningrequests",
		}},
		{Host: host, Methods: []string{"PUT", "PATCH", "POST"}, Action: l7.Deny, PathPatterns: []string{
			"/apis/certificates.k8s.io/*/certificatesigningrequests/*/approval",
		}},
	}
}
