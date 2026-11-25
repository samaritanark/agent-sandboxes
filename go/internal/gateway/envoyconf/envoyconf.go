// Package envoyconf writes a session gateway's Envoy bootstrap (design 5.8.4): passthrough by
// default. One listener per allowed port (443 and any declared extra ports) on the gateway's link
// address reads the TLS SNI (tls_inspector) and picks a filter chain by it:
//
//   - an SNI the allowlist names (exact, or a single-label wildcard: Envoy's server_names match
//     the allowlist's own semantics, S5) gets the connection check (ext_authz, the authz package,
//     which applies the block lists, deny wins) and is then forwarded unchanged to its host
//     (sni_dynamic_forward_proxy and tcp_proxy);
//   - every other connection (a name a block pattern carves out of an allowed wildcard, a name
//     not on the allowlist, an IP address, no SNI at all) gets the check alone, which refuses and
//     records it, and is never looked up or connected.
//
// The order matters: Envoy's forward proxy resolves and connects when a connection opens, before
// ext_authz sees its first data, so a name must be on the allowlist before it reaches the forward
// proxy, or a refused name would still be resolved upstream (measured, 2026-11-25).
// Envoy resolves that host with the VM's upstream resolver; blocked addresses are refused by
// nftables on the gateway namespace's output chain (S5), which checks the address actually
// dialled. Plain HTTP, CONNECT, and anything without a usable SNI never pass the check.
//
// Interception (TLS termination for L7 rules and credential injection, 5.8.5, 5.9) comes later.
package envoyconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
)

// Link is the gateway's side of one microVM's link (the agent's, or a dependency's): its address,
// the egress ports it serves, and that microVM's own allowlist and block patterns.
type Link struct {
	Addr         netip.Addr
	Ports        []int // 443 and the microVM's declared extra ports
	Allow        []string
	BlockDomains []string
}

// Dep is a dependency the agent reaches through the gateway (design 5.8.6): the agent connects to
// the agent link's gateway address on Port, and the gateway forwards to the dependency's Addr.
type Dep struct {
	Name string
	Port int
	Addr netip.Addr
}

// Config is one session gateway.
type Config struct {
	Links         []Link // the agent's first
	Deps          []Dep
	AuthzSocket   string       // the authz service's Unix socket
	AdminSocket   string       // Envoy's admin interface, as a Unix socket ("" for none)
	Resolvers     []netip.Addr // the VM's upstream resolvers
	AccessLog     string       // the connection log ("" for none)
	ConnectTimout int          // seconds; 0 means 10
}

func (c Config) check() error {
	if len(c.Links) == 0 || !path.IsAbs(c.AuthzSocket) || len(c.Resolvers) == 0 {
		return errors.New("envoyconf: links, authz socket, and resolvers are required")
	}
	agent := map[int]bool{}
	for i, l := range c.Links {
		if !l.Addr.IsValid() || len(l.Ports) == 0 {
			return fmt.Errorf("envoyconf: link %d needs an address and ports", i)
		}
		seen := map[int]bool{}
		for _, p := range l.Ports {
			if p < 1 || p > 65535 || seen[p] {
				return fmt.Errorf("envoyconf: link %d: bad or repeated port %d", i, p)
			}
			seen[p] = true
			if i == 0 {
				agent[p] = true
			}
		}
	}
	for _, d := range c.Deps {
		if d.Name == "" || !d.Addr.IsValid() || d.Port < 1 || d.Port > 65535 || agent[d.Port] {
			return fmt.Errorf("envoyconf: dependency %q: bad or colliding port %d", d.Name, d.Port)
		}
		agent[d.Port] = true
	}
	return nil
}

type obj = map[string]any

func typed(t string, cfg obj) obj {
	cfg["@type"] = "type.googleapis.com/" + t
	return cfg
}

const dnsCache = "sandbox_dns"

func (c Config) dnsCacheConfig() obj {
	var rs []obj
	for _, r := range c.Resolvers {
		rs = append(rs, obj{"socket_address": obj{"address": r.String(), "port_value": 53}})
	}
	return obj{
		"name":              dnsCache,
		"dns_lookup_family": "V4_ONLY",
		"typed_dns_resolver_config": obj{
			"name": "envoy.network.dns_resolver.cares",
			"typed_config": typed("envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig", obj{
				"resolvers":                  rs,
				"use_resolvers_as_fallback":  false,
				"filter_unroutable_families": true,
				"dns_resolver_options":       obj{"use_tcp_for_dns_lookups": false, "no_default_search_domain": true},
			}),
		},
	}
}

func (c Config) authzFilter() obj {
	return obj{"name": "envoy.filters.network.ext_authz", "typed_config": typed("envoy.extensions.filters.network.ext_authz.v3.ExtAuthz", obj{
		"stat_prefix":              "authz",
		"grpc_service":             obj{"envoy_grpc": obj{"cluster_name": "authz"}, "timeout": "2s"},
		"failure_mode_allow":       false,
		"transport_api_version":    "V3",
		"include_peer_certificate": false,
		// the check decides on the SNI, which Envoy sends only when asked
		"include_tls_session":      true,
		"send_tls_alert_on_denial": true,
	})}
}

// ServerNames splits the allowlist for Envoy's filter chain match: allow is what may reach the
// forward proxy, deny the exact names inside an allowed wildcard that a block pattern refuses (an
// exact server name outranks a wildcard in Envoy's match). A wildcard whose every name is blocked,
// and an exact name that is blocked, are left out.
func ServerNames(allowList, block []string) (allow, deny []string) {
	seenA, seenD := map[string]bool{}, map[string]bool{}
	add := func(m map[string]bool, out *[]string, n string) {
		if !m[n] {
			m[n] = true
			*out = append(*out, n)
		}
	}
	for _, e := range allowList {
		e = egressmatch.Normalize(e)
		parent, wild := strings.CutPrefix(e, "*.")
		if !wild {
			if egressmatch.Decide(e, allowList, block) {
				add(seenA, &allow, e)
			}
			continue
		}
		all := false
		for _, b := range block {
			b = egressmatch.Normalize(b)
			switch {
			case strings.HasPrefix(b, "*."):
				y := b[2:]
				if y == parent || strings.HasSuffix(parent, "."+y) {
					all = true
				} else if child, ok := strings.CutSuffix(y, "."+parent); ok && !strings.Contains(child, ".") {
					add(seenD, &deny, y)
				}
			case strings.HasPrefix(b, "*"):
				if strings.HasSuffix("."+parent, b[1:]) {
					all = true
				}
			case strings.HasSuffix(b, ".*"):
				if p := b[:len(b)-2]; strings.Count(p, ".") == strings.Count(parent, ".")+1 && strings.HasSuffix(p, "."+parent) {
					add(seenD, &deny, p)
				}
			default:
				if child, ok := strings.CutSuffix(b, "."+parent); ok && child != "" && !strings.Contains(child, ".") {
					add(seenD, &deny, b)
				}
			}
		}
		if !all {
			add(seenA, &allow, e)
		}
	}
	return allow, deny
}

// refusedFilters end a chain that must never connect anywhere: the check (which refuses and
// records), then a proxy to a cluster with no endpoints, since Envoy needs a terminal filter.
// Every refused connection is logged (the check itself never sees it: the proxy closes it first).
func (c Config) refusedFilters() []obj {
	tcp := obj{"stat_prefix": "refused", "cluster": "refused"}
	c.accessLog(tcp, true)
	return []obj{c.authzFilter(), {"name": "envoy.filters.network.tcp_proxy", "typed_config": typed("envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", tcp)}}
}

// accessLog adds the connection log to a tcp_proxy's config.
func (c Config) accessLog(tcp obj, refused bool) {
	if c.AccessLog == "" {
		return
	}
	f := obj{
		"start": "%START_TIME%", "sni": "%REQUESTED_SERVER_NAME%", "port": "%DOWNSTREAM_LOCAL_PORT%",
		"upstream": "%UPSTREAM_HOST%", "sent": "%BYTES_SENT%", "received": "%BYTES_RECEIVED%",
		"duration_ms": "%DURATION%", "flags": "%RESPONSE_FLAGS%",
	}
	if refused {
		f = obj{"start": "%START_TIME%", "sni": "%REQUESTED_SERVER_NAME%", "port": "%DOWNSTREAM_LOCAL_PORT%", "refused": true}
	}
	tcp["access_log"] = []obj{{"name": "envoy.access_loggers.file", "typed_config": typed("envoy.extensions.access_loggers.file.v3.FileAccessLog", obj{
		"path": c.AccessLog, "log_format": obj{"json_format": f},
	})}}
}

// depListener forwards the agent's connections on the dependency's port to the dependency.
func (c Config) depListener(d Dep) obj {
	tcp := obj{"stat_prefix": "dep_" + d.Name, "cluster": "dep_" + d.Name}
	if c.AccessLog != "" {
		tcp["access_log"] = []obj{{"name": "envoy.access_loggers.file", "typed_config": typed("envoy.extensions.access_loggers.file.v3.FileAccessLog", obj{
			"path": c.AccessLog, "log_format": obj{"json_format": obj{
				"start": "%START_TIME%", "dependency": d.Name, "port": "%DOWNSTREAM_LOCAL_PORT%",
				"sent": "%BYTES_SENT%", "received": "%BYTES_RECEIVED%", "duration_ms": "%DURATION%", "flags": "%RESPONSE_FLAGS%",
			}},
		})}}
	}
	return obj{
		"name":          "dep_" + d.Name,
		"address":       obj{"socket_address": obj{"address": c.Links[0].Addr.String(), "port_value": d.Port}},
		"filter_chains": []obj{{"filters": []obj{{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed("envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", tcp)}}}},
	}
}

func (c Config) listener(link Link, port int) obj {
	allow, deny := ServerNames(link.Allow, link.BlockDomains)
	filters := []obj{
		c.authzFilter(),
		{"name": "envoy.filters.network.sni_dynamic_forward_proxy", "typed_config": typed("envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig", obj{
			"port_value":       port,
			"dns_cache_config": c.dnsCacheConfig(),
		})},
	}
	tcp := obj{"stat_prefix": fmt.Sprintf("egress_%s_%d", link.Addr, port), "cluster": "upstream"}
	c.accessLog(tcp, false)
	filters = append(filters, obj{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed("envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", tcp)})
	l := obj{
		"name":             fmt.Sprintf("egress_%s_%d", link.Addr, port),
		"address":          obj{"socket_address": obj{"address": link.Addr.String(), "port_value": port}},
		"listener_filters": []obj{{"name": "envoy.filters.listener.tls_inspector", "typed_config": typed("envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector", obj{})}},
		// a connection that is not TLS gets no SNI, so the check refuses it; this bounds how long
		// the inspector waits for a ClientHello
		"listener_filters_timeout":             "5s",
		"continue_on_listener_filters_timeout": true,
		// everything not on the allowlist: the check alone (it refuses and records); no lookup
		"default_filter_chain": obj{"name": "refused", "filters": c.refusedFilters()},
	}
	var chains []obj
	if len(deny) > 0 {
		chains = append(chains, obj{"name": "blocked", "filter_chain_match": obj{"server_names": deny}, "filters": c.refusedFilters()})
	}
	if len(allow) > 0 {
		chains = append(chains, obj{"name": "allowed", "filter_chain_match": obj{"server_names": allow}, "filters": filters})
	}
	l["filter_chains"] = chains
	return l
}

// Args is Envoy's command line for a bootstrap at conf: every session's Envoy picks its own shared
// memory id (several run side by side), and connection log lines are flushed within 0.1 s rather
// than Envoy's default 10 s, so the audit log keeps up.
func Args(conf string) []string {
	return []string{"-c", conf, "--use-dynamic-base-id", "--file-flush-interval-msec", "100", "--log-level", "warn"}
}

// Bootstrap is the Envoy bootstrap as JSON.
func (c Config) Bootstrap() ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	timeout := c.ConnectTimout
	if timeout <= 0 {
		timeout = 10
	}
	var listeners []obj
	for _, l := range c.Links {
		for _, p := range l.Ports {
			listeners = append(listeners, c.listener(l, p))
		}
	}
	for _, d := range c.Deps {
		listeners = append(listeners, c.depListener(d))
	}
	clusters := []obj{
		{
			"name":            "authz",
			"type":            "STATIC",
			"connect_timeout": "1s",
			"typed_extension_protocol_options": obj{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions", obj{
				"explicit_http_config": obj{"http2_protocol_options": obj{}},
			})},
			"load_assignment": obj{"cluster_name": "authz", "endpoints": []obj{{"lb_endpoints": []obj{{"endpoint": obj{"address": obj{"pipe": obj{"path": c.AuthzSocket}}}}}}}},
		},
		{"name": "refused", "type": "STATIC", "connect_timeout": "1s", "load_assignment": obj{"cluster_name": "refused"}},
		{
			"name":            "upstream",
			"connect_timeout": fmt.Sprintf("%ds", timeout),
			"lb_policy":       "CLUSTER_PROVIDED",
			"cluster_type": obj{"name": "envoy.clusters.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{
				"dns_cache_config": c.dnsCacheConfig(),
			})},
		},
	}
	for _, d := range c.Deps {
		clusters = append(clusters, obj{"name": "dep_" + d.Name, "type": "STATIC", "connect_timeout": "5s",
			"load_assignment": obj{"cluster_name": "dep_" + d.Name, "endpoints": []obj{{"lb_endpoints": []obj{{"endpoint": obj{
				"address": obj{"socket_address": obj{"address": d.Addr.String(), "port_value": d.Port}}}}}}}}})
	}
	b := obj{
		"node":             obj{"id": "sandbox-gateway", "cluster": "sandbox"},
		"static_resources": obj{"listeners": listeners, "clusters": clusters},
	}
	// nothing in the session can reach Envoy's admin interface: a Unix socket in the gateway's
	// own directory, or none
	if c.AdminSocket != "" {
		b["admin"] = obj{"address": obj{"pipe": obj{"path": c.AdminSocket, "mode": 0o600}}}
	}
	return json.MarshalIndent(b, "", "  ")
}
