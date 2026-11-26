package envoyconf

// Interception (design 5.8.5, 5.10): a destination with L7 rules (or, later, a broker binding) is
// intercepted. Its connections take a filter chain of their own that terminates TLS with the
// session's leaf for that name (issued by sandboxd's CA, name-constrained to the session's
// intercepted names) and runs an HTTP connection manager:
//
//   - the request's authority must be the connection's own name (virtual host domains; anything
//     else is refused with 421), so a connection cannot borrow another name's rules;
//   - the L7 rules become routes, every deny before every allow, exactly as l7.Decide decides;
//     a host with allow rules refuses what none of them matches;
//   - paths are normalized, slashes merged, and escaped slashes unescaped before the match and
//     forwarded as matched, so what is checked is what is sent;
//   - allowed requests go to the forward proxy over TLS verified against the system and corporate
//     roots, with the upstream name as SNI and checked against the certificate's names;
//   - every request is logged by method, authority, path without its query, status, and the
//     deciding route; never a header, body, or query string.

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// Intercept is one intercepted name on a link: an exact name or a single-label wildcard "*.x",
// the leaf certificate chain and key files for it, and the L7 rules (the session's and the org
// baseline's; those that apply to the name are picked here).
//
// With SDS set, Envoy reads the leaf through that file (SDSSecret's output, naming CertChain and
// PrivateKey) and watches its directory: when a file is moved there, it reloads the secret and
// the files it names, so a renewed leaf takes effect for new connections while open ones go on.
// The renewal swaps a symlink in that directory onto a fresh directory of leaves.
type Intercept struct {
	Name       string
	CertChain  string
	PrivateKey string
	SDS        string
	Rules      []l7.Rule
}

func secretName(ic Intercept) string { return "leaf:" + ic.Name }

// SDSSecret is the SDS file for an intercepted name's leaf.
func SDSSecret(ic Intercept) ([]byte, error) {
	return json.MarshalIndent(obj{"resources": []obj{{
		"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		"name":  secretName(ic),
		// the leaf files are reloaded on a move in the SDS file's directory (by default Envoy would
		// watch their own directory, behind the symlink, which a swap never touches); the pair is
		// read together and checked for a change in between
		"tls_certificate": obj{"certificate_chain": obj{"filename": ic.CertChain}, "private_key": obj{"filename": ic.PrivateKey},
			"watched_directory": obj{"path": path.Dir(ic.SDS)}},
	}}}, "", "  ")
}

const interceptCluster = "intercepted_upstream"

// upgradeCluster carries protocol upgrades (WebSocket): over HTTP/1.1 only, since an upgrade on an
// HTTP/2 upstream connection needs extended CONNECT (RFC 8441), which many servers lack.
const upgradeCluster = "intercepted_upstream_upgrade"

func (c Config) checkIntercepts() error {
	any := false
	for i, l := range c.Links {
		seen := map[string]bool{}
		for _, ic := range l.Intercept {
			any = true
			n := egressmatch.Normalize(ic.Name)
			bare := strings.TrimPrefix(n, "*.")
			if n == "" || n != ic.Name || strings.Contains(bare, "*") || seen[n] || !path.IsAbs(ic.CertChain) || !path.IsAbs(ic.PrivateKey) || (ic.SDS != "" && !path.IsAbs(ic.SDS)) {
				return fmt.Errorf("envoyconf: link %d: bad intercept %q", i, ic.Name)
			}
			seen[n] = true
			// an intercepted name must be one the link may reach at all
			if strings.HasPrefix(n, "*.") {
				if !hasEntry(l.Allow, n) {
					return fmt.Errorf("envoyconf: link %d: intercepted wildcard %q is not on the allowlist", i, n)
				}
			} else if !egressmatch.Decide(n, l.Allow, l.BlockDomains) {
				return fmt.Errorf("envoyconf: link %d: intercepted name %q is not allowed", i, n)
			}
			for _, r := range ic.Rules {
				if err := r.Validate(); err != nil {
					return fmt.Errorf("envoyconf: link %d: %s: %w", i, n, err)
				}
			}
		}
	}
	if any && !path.IsAbs(c.UpstreamCAs) {
		return errors.New("envoyconf: interception needs the upstream trust bundle")
	}
	return nil
}

func hasEntry(list []string, e string) bool {
	for _, a := range list {
		if egressmatch.Normalize(a) == e {
			return true
		}
	}
	return false
}

// rulesFor are the rules that apply to an intercepted name: every-host rules, rules naming it, and
// for an exact name the wildcard rules that cover it.
func rulesFor(name string, rules []l7.Rule) []l7.Rule {
	var out []l7.Rule
	for _, r := range rules {
		rh := egressmatch.Normalize(r.Host)
		if r.Host == l7.AnyHost || rh == name || (!strings.HasPrefix(name, "*.") && l7.HostMatches(r.Host, name)) {
			out = append(out, r)
		}
	}
	return out
}

var refusedBody = obj{"inline_string": "refused by the sandbox egress policy\n"}

// routes are an intercepted name's L7 rules as Envoy routes: every deny, then every allow, then
// the default (refuse when there are allow rules, forward otherwise). Route names say which rule
// decided, for the log.
func routes(rules []l7.Rule) ([]obj, error) {
	var out []obj
	forward := obj{"cluster": interceptCluster, "timeout": "0s"}
	upgrade := obj{"cluster": upgradeCluster, "timeout": "0s", "upgrade_configs": []obj{{"upgrade_type": "websocket"}}}
	// forwarding is two routes with the same match: upgrades first, over HTTP/1.1, then the rest
	forwarding := func(name string, match obj) []obj {
		um := obj{}
		for k, v := range match {
			um[k] = v
		}
		hs, _ := match["headers"].([]obj)
		um["headers"] = append(append([]obj(nil), hs...), obj{"name": "upgrade", "present_match": true})
		return []obj{{"name": name, "match": um, "route": upgrade}, {"name": name, "match": match, "route": forward}}
	}
	add := func(i int, r l7.Rule) error {
		methods := r.Methods
		if len(methods) == 0 {
			methods = []string{""}
		}
		pats := r.PathPatterns
		if len(pats) == 0 {
			pats = []string{""}
		}
		for _, m := range methods {
			for _, g := range pats {
				match := obj{"prefix": "/"}
				if g != "" {
					p, err := l7.Compile(g)
					if err != nil {
						return err
					}
					match = obj{"safe_regex": obj{"regex": p.PathRegex}}
					// query conditions match the raw ":path", percent-encoded or not (l7.QueryCond)
					var hs []obj
					for _, q := range p.Query {
						hs = append(hs, obj{"name": ":path", "string_match": obj{"safe_regex": obj{"regex": q.QueryPathRegex()}}})
					}
					if len(hs) > 0 {
						match["headers"] = hs
					}
				}
				if m != "" {
					hs, _ := match["headers"].([]obj)
					match["headers"] = append(hs, obj{"name": ":method", "string_match": obj{"exact": m}})
				}
				name := fmt.Sprintf("%s:%d", r.Action, i)
				if r.Action == l7.Deny {
					out = append(out, obj{"name": name, "match": match, "direct_response": obj{"status": 403, "body": refusedBody}})
				} else {
					out = append(out, forwarding(name, match)...)
				}
			}
		}
		return nil
	}
	hasAllow := false
	for _, pass := range []string{l7.Deny, l7.Allow} {
		for i, r := range rules {
			if r.Action != pass {
				continue
			}
			hasAllow = hasAllow || pass == l7.Allow
			if err := add(i, r); err != nil {
				return nil, err
			}
		}
	}
	if hasAllow {
		out = append(out, obj{"name": "default:refused", "match": obj{"prefix": "/"}, "direct_response": obj{"status": 403, "body": refusedBody}})
	} else {
		out = append(out, forwarding("default:forward", obj{"prefix": "/"})...)
	}
	return out, nil
}

// virtualHosts makes the authority the connection's own name: an exact name's host takes only that
// authority; a wildcard's takes a single label under it, except names intercepted on their own.
func virtualHosts(ic Intercept, port int, exactNames []string, rs []obj) []obj {
	domains := []string{fmt.Sprintf("%s:%d", ic.Name, port)}
	if port == 443 {
		domains = append(domains, ic.Name)
	}
	misdirected := func(name string, m obj) obj {
		return obj{"name": name, "match": m, "direct_response": obj{"status": 421, "body": refusedBody}}
	}
	if rest, ok := strings.CutPrefix(ic.Name, "*."); ok {
		portRE := fmt.Sprintf("(:%d)", port)
		if port == 443 {
			portRE += "?"
		}
		var guard []obj
		// Envoy's "*.x" domain takes any depth; the connection's wildcard takes one label
		guard = append(guard, misdirected("misdirected:depth", obj{"prefix": "/", "headers": []obj{{"name": ":authority", "invert_match": true,
			"string_match": obj{"safe_regex": obj{"regex": `(?i)^[^.:]+\.` + regexp.QuoteMeta(rest) + portRE + "$"}}}}}))
		for _, e := range exactNames {
			if egressmatch.Allowed(e, ic.Name) {
				guard = append(guard, misdirected("misdirected:"+e, obj{"prefix": "/", "headers": []obj{{"name": ":authority",
					"string_match": obj{"safe_regex": obj{"regex": `(?i)^` + regexp.QuoteMeta(e) + portRE + "$"}}}}}))
			}
		}
		rs = append(guard, rs...)
	}
	return []obj{
		{"name": "intercepted", "domains": domains, "routes": rs},
		{"name": "misdirected", "domains": []string{"*"}, "routes": []obj{misdirected("misdirected", obj{"prefix": "/"})}},
	}
}

// interceptChain is the filter chain for one intercepted name on one listener.
func (c Config) interceptChain(link Link, ic Intercept, port int) (obj, error) {
	var exact []string
	for _, o := range link.Intercept {
		if !strings.HasPrefix(o.Name, "*.") {
			exact = append(exact, o.Name)
		}
	}
	rs, err := routes(rulesFor(ic.Name, ic.Rules))
	if err != nil {
		return nil, err
	}
	hcm := obj{
		"stat_prefix":                      "intercept",
		"codec_type":                       "AUTO",
		"normalize_path":                   true,
		"merge_slashes":                    true,
		"path_with_escaped_slashes_action": "UNESCAPE_AND_FORWARD",
		"generate_request_id":              false,
		"server_header_transformation":     "PASS_THROUGH",
		"upgrade_configs":                  []obj{{"upgrade_type": "websocket"}},
		"route_config": obj{
			"name":          "intercepted",
			"virtual_hosts": virtualHosts(ic, port, exact, rs),
			// the gateway inspects messages, so none are compressed per message
			"request_headers_to_remove": []string{"sec-websocket-extensions"},
		},
		"http_filters": append(brokerFilters(c.linkIndex(link), link.BrokerSocket), []obj{
			{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig", obj{
				"dns_cache_config": c.dnsCacheConfig(),
			})},
			{"name": "envoy.filters.http.router", "typed_config": typed("envoy.extensions.filters.http.router.v3.Router", obj{"suppress_envoy_headers": true})},
		}...),
	}
	if c.AccessLog != "" {
		hcm["access_log"] = []obj{{"name": "envoy.access_loggers.file", "typed_config": typed("envoy.extensions.access_loggers.file.v3.FileAccessLog", obj{
			"path": c.AccessLog, "log_format": obj{"json_format": obj{
				"start": "%START_TIME%", "sni": "%REQUESTED_SERVER_NAME%", "port": "%DOWNSTREAM_LOCAL_PORT%", "intercepted": true,
				"method": "%REQ(:METHOD)%", "authority": "%REQ(:AUTHORITY)%", "path": "%PATH(NQ)%", "status": "%RESPONSE_CODE%",
				"rule": "%ROUTE_NAME%", "upstream": "%UPSTREAM_HOST%", "sent": "%BYTES_SENT%", "received": "%BYTES_RECEIVED%",
				"duration_ms": "%DURATION%", "flags": "%RESPONSE_FLAGS%",
			}},
		})}}
	}
	return obj{
		"name": "intercept:" + ic.Name,
		"transport_socket": obj{"name": "envoy.transport_sockets.tls", "typed_config": typed("envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext", obj{
			"common_tls_context": leafContext(ic),
		})},
		"filters": []obj{c.authzFilter(), {"name": "envoy.filters.network.http_connection_manager",
			"typed_config": typed("envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", hcm)}},
	}, nil
}

// leafContext serves the name's leaf: from its files, or through its watched SDS file.
func leafContext(ic Intercept) obj {
	ctx := obj{"alpn_protocols": []string{"h2", "http/1.1"}}
	if ic.SDS == "" {
		ctx["tls_certificates"] = []obj{{"certificate_chain": obj{"filename": ic.CertChain}, "private_key": obj{"filename": ic.PrivateKey}}}
		return ctx
	}
	ctx["tls_certificate_sds_secret_configs"] = []obj{{"name": secretName(ic), "sds_config": obj{
		"path_config_source":   obj{"path": ic.SDS, "watched_directory": obj{"path": path.Dir(ic.SDS)}},
		"resource_api_version": "V3",
	}}}
	return ctx
}

// interceptedUpstream is the cluster intercepted requests leave by: the forward proxy over TLS,
// verified against the trust bundle, with the request's host as SNI and checked against the
// certificate's names.
func (c Config) interceptedUpstream(timeout int, upgrades bool) obj {
	name, alpn := interceptCluster, []string{"h2", "http/1.1"}
	protocols := obj{"auto_config": obj{"http_protocol_options": obj{}, "http2_protocol_options": obj{}}}
	if upgrades {
		name, alpn = upgradeCluster, []string{"http/1.1"}
		protocols = obj{"explicit_http_config": obj{"http_protocol_options": obj{}}}
	}
	protocols["upstream_http_protocol_options"] = obj{"auto_sni": true, "auto_san_validation": true}
	return obj{
		"name":            name,
		"connect_timeout": fmt.Sprintf("%ds", timeout),
		"lb_policy":       "CLUSTER_PROVIDED",
		"cluster_type": obj{"name": "envoy.clusters.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{
			"dns_cache_config": c.dnsCacheConfig(),
		})},
		"transport_socket": obj{"name": "envoy.transport_sockets.tls", "typed_config": typed("envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", obj{
			"common_tls_context": obj{
				"validation_context": obj{"trusted_ca": obj{"filename": c.UpstreamCAs}},
				"alpn_protocols":     alpn,
			},
		})},
		"typed_extension_protocol_options": obj{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions", protocols)},
	}
}

// brokerFilters put the link's credential broker (the broker package, an ext_proc service) in front of
// every intercepted request when the session has one: it injects, refuses, and scrubs responses
// as they stream, and Envoy refuses the request when the broker does not answer.
func brokerFilters(i int, socket string) []obj {
	if socket == "" {
		return nil
	}
	return []obj{{"name": "envoy.filters.http.ext_proc", "typed_config": typed("envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor", obj{
		"grpc_service":       obj{"envoy_grpc": obj{"cluster_name": fmt.Sprintf("broker_%d", i)}, "timeout": "5s"},
		"failure_mode_allow": false,
		"processing_mode": obj{"request_header_mode": "SEND", "response_header_mode": "SEND", "request_body_mode": "NONE",
			"response_body_mode": "STREAMED", "request_trailer_mode": "SKIP", "response_trailer_mode": "SKIP"},
		"allow_mode_override": true,
		"message_timeout":     "5s",
	})}}
}

// linkIndex is a link's place in the configuration (each link has its own broker).
func (c Config) linkIndex(l Link) int {
	for i, o := range c.Links {
		if o.Addr == l.Addr {
			return i
		}
	}
	return -1
}

func brokerCluster(i int, socket string) obj {
	name := fmt.Sprintf("broker_%d", i)
	return obj{
		"name": name, "type": "STATIC", "connect_timeout": "1s",
		"typed_extension_protocol_options": obj{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions", obj{
			"explicit_http_config": obj{"http2_protocol_options": obj{}},
		})},
		"load_assignment": obj{"cluster_name": name, "endpoints": []obj{{"lb_endpoints": []obj{{"endpoint": obj{"address": obj{"pipe": obj{"path": socket}}}}}}}},
	}
}
