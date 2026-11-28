package envoyconf

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Tier 3 Kubernetes access (design 5.9.5): an intercepted name can be a cluster's gateway name
// (kube-<n>.gw.sandbox.internal). Its requests do not leave by the forward proxy: they go to the
// cluster's own API server, over TLS verified against the cluster's CA (or the system roots) and
// checked against the server's name or address, with the client certificate for an mtls cluster,
// and the server URL's path in front of each request's. The broker has already put in (or, for
// mtls, checked and removed) the credential, and the routes refused what the API deny-list names.
// kubectl's streaming verbs (exec, attach, port-forward) upgrade to WebSocket or SPDY/3.1, so
// these connections are HTTP/1.1.

// Kube is the upstream of a cluster's gateway name.
type Kube struct {
	Host       string // the API server's name or address
	Port       int
	PathPrefix string // the server URL's path ("" or /a/b)
	SNI        string // the server name to send and check (tls-server-name, else Host when a name)
	CAFile     string // the cluster's CA; "" for the system and corporate roots
	ClientCert string // an mtls cluster's certificate and key files
	ClientKey  string
}

var pathPrefixRE = regexp.MustCompile(`^(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$`)

func (k Kube) check(name string) error {
	if k.Host == "" || k.Port < 1 || k.Port > 65535 {
		return fmt.Errorf("kube %s: host and port are required", name)
	}
	if !pathPrefixRE.MatchString(k.PathPrefix) {
		return fmt.Errorf("kube %s: invalid path prefix %q", name, k.PathPrefix)
	}
	if (k.ClientCert == "") != (k.ClientKey == "") {
		return fmt.Errorf("kube %s: a client certificate needs its key", name)
	}
	return nil
}

func kubeCluster(name string) string { return "kube:" + name }

// kubeUpstream is the cluster for one cluster's gateway name.
func (c Config) kubeUpstream(name string, k Kube, timeout int) obj {
	san := obj{"san_type": "DNS", "matcher": obj{"exact": k.SNI}}
	if _, err := netip.ParseAddr(k.SNI); err == nil {
		san = obj{"san_type": "IP_ADDRESS", "matcher": obj{"exact": k.SNI}}
	}
	ca := k.CAFile
	if ca == "" {
		ca = c.UpstreamCAs
	}
	tlsCtx := obj{
		"validation_context": obj{"trusted_ca": obj{"filename": ca}, "match_typed_subject_alt_names": []obj{san}},
		"alpn_protocols":     []string{"http/1.1"},
	}
	if k.ClientCert != "" {
		tlsCtx["tls_certificates"] = []obj{{"certificate_chain": obj{"filename": k.ClientCert}, "private_key": obj{"filename": k.ClientKey}}}
	}
	upstream := obj{"common_tls_context": tlsCtx}
	if _, err := netip.ParseAddr(k.SNI); err != nil {
		upstream["sni"] = k.SNI // an address is not sent as SNI
	}
	typ := "STRICT_DNS"
	if _, err := netip.ParseAddr(k.Host); err == nil {
		typ = "STATIC"
	}
	cl := obj{
		"name":              kubeCluster(name),
		"type":              typ,
		"connect_timeout":   fmt.Sprintf("%ds", timeout),
		"dns_lookup_family": "V4_PREFERRED",
		"load_assignment": obj{"cluster_name": kubeCluster(name), "endpoints": []obj{{"lb_endpoints": []obj{{"endpoint": obj{
			"address": obj{"socket_address": obj{"address": k.Host, "port_value": k.Port}}}}}}}},
		"transport_socket": obj{"name": "envoy.transport_sockets.tls", "typed_config": typed("envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", upstream)},
		"typed_extension_protocol_options": obj{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
			obj{"explicit_http_config": obj{"http_protocol_options": obj{}}})},
	}
	if typ == "STRICT_DNS" {
		cl["typed_dns_resolver_config"] = c.dnsCacheConfig()["typed_dns_resolver_config"]
	}
	return cl
}

// kubeUpgrades are the protocol upgrades a cluster's API takes.
var kubeUpgrades = []obj{{"upgrade_type": "websocket"}, {"upgrade_type": "SPDY/3.1"}}

// kubeRoutes points a cluster's routes at its own upstream, with its path prefix, and lets them
// upgrade: forwarding routes leave for the cluster, refusing ones stay as they are.
func kubeRoutes(rs []obj, name string, k Kube) []obj {
	out := make([]obj, 0, len(rs))
	for _, r := range rs {
		if _, ok := r["route"].(obj); !ok {
			out = append(out, r)
			continue
		}
		na := obj{"cluster": kubeCluster(name), "timeout": "0s", "upgrade_configs": kubeUpgrades}
		if k.PathPrefix != "" {
			na["regex_rewrite"] = obj{"pattern": obj{"regex": "^(.*)$"}, "substitution": strings.TrimRight(k.PathPrefix, "/") + `\1`}
		}
		nr := obj{}
		for key, v := range r {
			nr[key] = v
		}
		nr["route"] = na
		out = append(out, nr)
	}
	return out
}
