// Package envoyconf writes a session gateway's Envoy bootstrap (design 5.8.4): passthrough by
// default. One listener per allowed port (443 and any declared extra ports) on the gateway's link
// address reads the TLS SNI (tls_inspector) and picks a filter chain by it:
//
//   - an SNI that no block pattern matches and the allowlist names (exact, "*.x", or "**.x"; the
//     filter chain matcher mirrors egressmatch exactly) gets the connection check (ext_authz, the
//     authz package, which decides again from the same rules) and is then forwarded unchanged to
//     its host (sni_dynamic_forward_proxy and tcp_proxy);
//   - every other connection (a blocked name, a name not on the allowlist, an IP address, no SNI
//     at all) is refused and recorded by Envoy, and is never looked up or connected.
//
// The order matters: Envoy's forward proxy resolves and connects when a connection opens, before
// ext_authz sees its first data, so a name must be on the allowlist before it reaches the forward
// proxy, or a refused name would still be resolved upstream (measured, 2026-11-25).
// Envoy resolves that host with the VM's upstream resolver; blocked addresses are refused by
// nftables on the gateway namespace's output chain (S5), which checks the address actually
// dialled. Plain HTTP, CONNECT, and anything without a usable SNI never pass the check.
//
// A name with L7 rules is intercepted instead (intercept.go): its own chain terminates TLS and
// applies the rules per request. Credential injection (5.9) comes later.
package envoyconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
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
	Intercept    []Intercept // names whose TLS the gateway terminates (intercept.go)
	BrokerSocket string      // this microVM's credential broker (ext_proc), "" for none
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
	UpstreamCAs   string       // the roots intercepted upstreams are verified against (system and corporate)
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
	return c.checkIntercepts()
}

type obj = map[string]any

func typed(t string, cfg obj) obj {
	cfg["@type"] = "type.googleapis.com/" + t
	return cfg
}

const dnsCache = "sandbox_dns"

// MaxConnections bounds the connections a session's gateway holds open at once.
const MaxConnections = 4096

// MaxRegexProgram is the RE2 program size Envoy accepts in this bootstrap.
const MaxRegexProgram = 2048

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

// The filter chain matcher (Envoy's filter_chain_matcher, a list matcher on the SNI) mirrors
// egressmatch exactly: the first match wins, so every block pattern comes before every allowlist
// entry and a blocked name never reaches the forward proxy, whatever wildcard allows it. Names are
// compared ignoring case; SNIs carry no trailing dot.

func sniPredicate(match obj) obj {
	return obj{"single_predicate": obj{
		"input":       obj{"name": "sni", "typed_config": typed("envoy.extensions.matching.common_inputs.network.v3.ServerNameInput", obj{})},
		"value_match": match,
	}}
}

func exact(v string) obj  { return sniPredicate(obj{"exact": v, "ignore_case": true}) }
func suffix(v string) obj { return sniPredicate(obj{"suffix": v, "ignore_case": true}) }
func prefix(v string) obj { return sniPredicate(obj{"prefix": v, "ignore_case": true}) }

// BlockPredicates are the SNI predicates that together match egressmatch.Blocked(·, pattern).
func BlockPredicates(pattern string) []obj {
	p := egressmatch.Normalize(pattern)
	switch {
	case p == "":
		return nil
	case strings.HasPrefix(p, "*."):
		return []obj{exact(p[2:]), suffix(p[1:])}
	case strings.HasPrefix(p, "*"):
		return []obj{suffix(p[1:])}
	case strings.HasSuffix(p, ".*"):
		return []obj{exact(p[:len(p)-2]), prefix(p[:len(p)-1])}
	}
	return []obj{exact(p)}
}

// AllowPredicate is the SNI predicate that matches egressmatch.Allowed(·, entry).
func AllowPredicate(entry string) obj {
	e := egressmatch.Normalize(entry)
	if rest, ok := strings.CutPrefix(e, "**."); ok {
		return obj{"and_matcher": obj{"predicate": []obj{suffix("." + rest), {"not_matcher": exact("." + rest)}}}}
	}
	if rest, ok := strings.CutPrefix(e, "*."); ok {
		return sniPredicate(obj{"safe_regex": obj{"google_re2": obj{}, "regex": `(?i)^[^.]+\.` + regexp.QuoteMeta(rest) + "$"}})
	}
	return exact(e)
}

func chainAction(name string) obj {
	return obj{"action": obj{"name": name, "typed_config": typed("google.protobuf.StringValue", obj{"value": name})}}
}

// chainMatcher selects "blocked" for any block pattern, then an intercepted name's own chain
// (exact names before wildcards), then "allowed" for any allowlist entry; anything else falls to
// the default chain. It is nil when nothing is allowed.
func chainMatcher(allow, block []string, intercept []Intercept) obj {
	var ms []obj
	for _, b := range block {
		for _, p := range BlockPredicates(b) {
			ms = append(ms, obj{"predicate": p, "on_match": chainAction("blocked")})
		}
	}
	nb := len(ms)
	for _, wild := range []bool{false, true} {
		for _, ic := range intercept {
			if strings.HasPrefix(ic.Name, "*.") == wild {
				ms = append(ms, obj{"predicate": AllowPredicate(ic.Name), "on_match": chainAction("intercept:" + ic.Name)})
			}
		}
	}
	for _, a := range allow {
		if egressmatch.Normalize(a) != "" {
			ms = append(ms, obj{"predicate": AllowPredicate(a), "on_match": chainAction("allowed")})
		}
	}
	if len(ms) == nb {
		return nil
	}
	return obj{"matcher_list": obj{"matchers": ms}}
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

func (c Config) listener(link Link, port int) (obj, error) {
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
	if m := chainMatcher(link.Allow, link.BlockDomains, link.Intercept); m != nil {
		l["filter_chain_matcher"] = m
		chains := []obj{{"name": "blocked", "filters": c.refusedFilters()}, {"name": "allowed", "filters": filters}}
		for _, ic := range link.Intercept {
			ch, err := c.interceptChain(link, ic, port)
			if err != nil {
				return nil, err
			}
			chains = append(chains, ch)
		}
		l["filter_chains"] = chains
	}
	return l, nil
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
	intercepting := false
	for _, l := range c.Links {
		intercepting = intercepting || len(l.Intercept) > 0
		for _, p := range l.Ports {
			ln, err := c.listener(l, p)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, ln)
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
	if intercepting {
		clusters = append(clusters, c.interceptedUpstream(timeout, false), c.interceptedUpstream(timeout, true))
	}
	for i, l := range c.Links {
		if l.BrokerSocket != "" && len(l.Intercept) > 0 {
			clusters = append(clusters, brokerCluster(i, l.BrokerSocket))
		}
	}
	for _, d := range c.Deps {
		clusters = append(clusters, obj{"name": "dep_" + d.Name, "type": "STATIC", "connect_timeout": "5s",
			"load_assignment": obj{"cluster_name": "dep_" + d.Name, "endpoints": []obj{{"lb_endpoints": []obj{{"endpoint": obj{
				"address": obj{"socket_address": obj{"address": d.Addr.String(), "port_value": d.Port}}}}}}}}})
	}
	b := obj{
		"node":             obj{"id": "sandbox-gateway", "cluster": "sandbox"},
		"static_resources": obj{"listeners": listeners, "clusters": clusters},
		// RE2's program size limit: Envoy's default (100) is below a long host name's single-label
		// match and a percent-encoding-aware query condition; l7 bounds pattern lengths to fit
		// a session cannot hold more connections open on its gateway than this
		"overload_manager": obj{"resource_monitors": []obj{{"name": "envoy.resource_monitors.global_downstream_max_connections",
			"typed_config": typed("envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig", obj{
				"max_active_downstream_connections": MaxConnections,
			})}}},
		"layered_runtime": obj{"layers": []obj{{"name": "static", "static_layer": obj{
			"re2.max_program_size.error_level": MaxRegexProgram, "re2.max_program_size.warn_level": MaxRegexProgram,
		}}}},
	}
	// nothing in the session can reach Envoy's admin interface: a Unix socket in the gateway's
	// own directory, or none
	if c.AdminSocket != "" {
		b["admin"] = obj{"address": obj{"pipe": obj{"path": c.AdminSocket, "mode": 0o600}}}
	}
	return json.MarshalIndent(b, "", "  ")
}
