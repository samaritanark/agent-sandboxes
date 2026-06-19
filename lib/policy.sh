#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/policy.sh — CiliumNetworkPolicy generation
set -euo pipefail

# build_cilium_policy — emit CiliumNetworkPolicy YAML for a session
# Args: session_id agent tier kube_api_cidr kube_api_port [allow_domains...]
#   kube_api_cidr: CIDR of the Tier 3 kube API server (e.g. "10.0.0.1/32"),
#                  or "" when there is none. Allowed via toCIDR rather than
#                  toFQDNs: when the API server is pinned as a pod hostAlias,
#                  kubectl resolves it from /etc/hosts with no DNS query, so a
#                  toFQDNs rule would never be populated by the DNS proxy.
#   kube_api_port: TCP port for the kube API server (e.g. "6443"); used only
#                  when kube_api_cidr is non-empty.
#   allow_domains: extra FQDNs to allow on 443/TCP beyond the built-in
#                  per-agent and per-tier lists (--allow-domain, --infra-endpoint).
build_cilium_policy() {
  local session_id="$1"
  local agent="$2"
  local tier="$3"
  local kube_api_cidr="$4"
  local kube_api_port="$5"
  shift 5

  local -a extra_allow_domains=("$@")

  # Full set of HTTPS-allowed FQDNs: per-agent + per-tier built-in lists,
  # plus any caller-supplied extras.
  local -a fqdn_domains=()
  mapfile -t fqdn_domains < <(get_agent_domains "${agent}")
  local -a tier_domains=()
  mapfile -t tier_domains < <(get_tier_domains "${tier}")
  fqdn_domains+=("${tier_domains[@]+"${tier_domains[@]}"}")
  fqdn_domains+=("${extra_allow_domains[@]+"${extra_allow_domains[@]}"}")

  # Render the toFQDNs match entries.
  local fqdn_block=""
  local d
  for d in "${fqdn_domains[@]}"; do
    [[ -z "${d}" ]] && continue
    [[ -n "${fqdn_block}" ]] && fqdn_block+=$'\n'
    fqdn_block+="$(indent_fqdn_entry "${d}")"
  done

  # Render the L7 DNS match entries — the SAME allowlist enforced on 443 below.
  # toFQDNs only governs which resolved IPs the session may dial; it does not
  # govern which names the session may *ask* about. With a wildcard DNS rule a
  # mistaken or injected agent can tunnel data straight out the resolver as
  # query labels ("<base64-secret>.attacker.tld") — the proxy forwards it
  # upstream and the secret leaves over DNS, entirely outside the 443 allow
  # rule. Coupling the DNS filter to the FQDN allowlist closes that channel;
  # what remains is the in-allowlist residual (a wildcard-allowed domain is
  # still a possible label sink), which is an accepted, documented cost.
  local dns_block=""
  for d in "${fqdn_domains[@]}"; do
    [[ -z "${d}" ]] && continue
    [[ -n "${dns_block}" ]] && dns_block+=$'\n'
    dns_block+="$(indent_dns_entry "${d}")"
  done

  # Phase 5 — per-dependency reach. For each declared dependency (read from the
  # SESSION_DEP_ENDPOINTS global, entries "resource_name port") the session
  # gains two things and nothing else (§2.4):
  #   (a) a toEndpoints egress rule scoped to that dependency's pod identity and
  #       its single port — the only in-cluster reach the session is granted;
  #   (b) the dependency's cluster-local Service FQDN in the L7 DNS allow, so the
  #       session can RESOLVE it. The toEndpoints rule opens the connection, but
  #       the DNS proxy is scoped to the FQDN allowlist and refuses any name not
  #       on the list — cluster-local names included — so without (b) the session
  #       could reach the dependency's IP but never learn it.
  # The dependency is reached by endpoint identity (ClusterIP→backend pod), so it
  # needs NO toFQDNs entry — toFQDNs governs dialing external/world IPs. Allowing
  # the cluster.local name does not reopen the DNS-exfil channel (§1.4 #9):
  # kube-dns answers cluster.local authoritatively and never forwards it upstream,
  # so an encoded <secret>.svc.cluster.local dead-ends at NXDOMAIN.
  local dep_endpoints_block=""
  local entry rname rport fqdn
  for entry in "${SESSION_DEP_ENDPOINTS[@]+"${SESSION_DEP_ENDPOINTS[@]}"}"; do
    [[ -z "${entry}" ]] && continue
    rname="${entry%% *}"
    rport="${entry##* }"
    fqdn="${rname}.${SANDBOX_NAMESPACE}.svc.cluster.local"
    [[ -n "${dns_block}" ]] && dns_block+=$'\n'
    dns_block+="$(indent_dns_entry "${fqdn}")"
    dep_endpoints_block+="$(cat <<EOF
    - toEndpoints:
        - matchLabels:
            sandbox-dependency: "${rname}"
      toPorts:
        - ports:
            - port: "${rport}"
              protocol: TCP
EOF
)"$'\n'
  done

  # Tier 3 kube API server — allowed by IP (see kube_api_cidr note above).
  local kube_cidr_block=""
  if [[ -n "${kube_api_cidr}" ]]; then
    kube_cidr_block="$(cat <<EOF
    - toCIDR:
        - "${kube_api_cidr}"
      toPorts:
        - ports:
            - port: "${kube_api_port:-443}"
              protocol: TCP
EOF
)"
  fi

  # Blocked CIDRs — deny egress to forbidden IP ranges even when an allow-listed
  # FQDN resolves into one (DNS rebinding, or an allowed domain that points at
  # internal infra or a cloud-metadata endpoint like 169.254.169.254). Cilium
  # evaluates deny rules ahead of allow rules, so this is a hard backstop over
  # the FQDN allowlist above. CIDR rules match the external/"world" identity
  # only; in-cluster traffic (kube-dns, the Tier 3 API server's pod identity)
  # is governed by endpoint identities, so this never breaks cluster DNS.
  local egress_deny_block=""
  local -a blocked_cidrs=()
  mapfile -t blocked_cidrs < <(get_blocked_cidrs)
  if [[ "${#blocked_cidrs[@]}" -gt 0 ]]; then
    local cidr_entries="" c
    for c in "${blocked_cidrs[@]}"; do
      [[ -z "${c}" ]] && continue
      cidr_entries+="        - \"${c}\""$'\n'
    done
    if [[ -n "${cidr_entries}" ]]; then
      egress_deny_block="$(cat <<EOF
  egressDeny:
    - toCIDR:
${cidr_entries%$'\n'}
EOF
)"
    fi
  fi

  cat <<EOF
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "policy-${session_id}"
  namespace: "${SANDBOX_NAMESPACE}"
  labels:
    sandbox-session: "${session_id}"
    sandbox-agent: "${agent}"
    sandbox-tier: "${tier}"
spec:
  endpointSelector:
    matchLabels:
      sandbox-session: "${session_id}"
  egress:
    # queries through Cilium's DNS proxy, which populates the FQDN->IP cache
    # the toFQDNs rule below is enforced against. Verified working with gVisor
    # pods: the DNS proxy intercepts netstack traffic at the pod veth.
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
          rules:
            dns:
${dns_block}
    # HTTPS egress restricted to the per-agent + per-tier domain allowlist,
    # enforced via Cilium FQDN policy.
    - toFQDNs:
${fqdn_block}
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
${dep_endpoints_block}${kube_cidr_block}
${egress_deny_block}
  ingress:
    # Allow return traffic for all outbound connections.
    # The sandbox pod does not listen on any ports; this rule only enables
    # return-path packets (DNS responses, HTTPS responses, etc.).
    - fromEntities:
        - cluster
        - world
EOF
}

# indent_fqdn_entry — emit a single toFQDNs match entry (8-space indented).
# A domain containing a leading '*' becomes a matchPattern; otherwise matchName.
indent_fqdn_entry() {
  local domain="$1"
  if [[ "${domain}" == \** ]]; then
    printf '        - matchPattern: "%s"\n' "${domain}"
  else
    printf '        - matchName: "%s"\n' "${domain}"
  fi
}

# indent_dns_entry — emit a single L7 DNS match entry (14-space indented to sit
# under egress[].toPorts[].rules.dns). Same matchName/matchPattern split as the
# toFQDNs entries so the set of resolvable names equals the set of dialable
# domains. Note printf has no trailing newline: callers join entries with '\n'.
indent_dns_entry() {
  local domain="$1"
  if [[ "${domain}" == \** ]]; then
    printf '              - matchPattern: "%s"' "${domain}"
  else
    printf '              - matchName: "%s"' "${domain}"
  fi
}

# build_dependency_policy — emit the CiliumNetworkPolicy for ONE dependency pod.
# Args: session_id resource_name port [egress_domain ...]
#
# This is a clone-or-subset of the session's own egress (§1.6, generalised):
#   - DNS to kube-dns, L7-scoped to the dependency's OWN egress allowlist (never
#     a wildcard) — a dependency with no egress resolves nothing externally, so
#     the DNS-tunnel channel (§1.4 #9) is closed for it too.
#   - 443/TCP restricted to that same allowlist via toFQDNs (omitted entirely
#     when the dependency declares no egress — a pure-internal dep like a DB).
#   - egressDeny to the blocked-CIDR list (IMDS/link-local), same backstop the
#     session carries, so a permitted FQDN that resolves inward is still denied.
# Ingress is the discriminating control: the dependency accepts traffic ONLY
# from the owning session pod ({sandbox-session, sandbox-role: session}) on its
# one port — never from a sibling dependency, never from the namespace at large.
# No dependency gets an unpoliced NIC (§2.2).
build_dependency_policy() {
  local session_id="$1"
  local resource_name="$2"
  local port="$3"
  shift 3
  local -a egress_domains=("$@")

  # L7 DNS + toFQDNs entries over the dependency's own egress allowlist.
  local dns_block="" fqdn_block="" d
  for d in "${egress_domains[@]+"${egress_domains[@]}"}"; do
    [[ -z "${d}" ]] && continue
    [[ -n "${dns_block}" ]] && dns_block+=$'\n'
    dns_block+="$(indent_dns_entry "${d}")"
    [[ -n "${fqdn_block}" ]] && fqdn_block+=$'\n'
    fqdn_block+="$(indent_fqdn_entry "${d}")"
  done

  # Render the L7 DNS rules. A dependency with no egress gets an explicit EMPTY
  # list (dns: []) — not a bare `dns:` (which YAML reads as null = no L7 filter =
  # unfiltered DNS, reopening the tunnel channel of §1.4 #9). Empty list = the
  # proxy answers no external name, so a pure-internal dep resolves nothing.
  local dns_rules_yaml
  if [[ -n "${dns_block}" ]]; then
    dns_rules_yaml="            dns:"$'\n'"${dns_block}"
  else
    dns_rules_yaml="            dns: []"
  fi

  # 443/TCP toFQDNs block only when the dependency has external egress.
  local fqdn_egress_block=""
  if [[ -n "${fqdn_block}" ]]; then
    fqdn_egress_block="$(cat <<EOF
    - toFQDNs:
${fqdn_block}
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
EOF
)"
  fi

  # egressDeny to the blocked-CIDR list — identical backstop to the session.
  local egress_deny_block="" c cidr_entries=""
  local -a blocked_cidrs=()
  mapfile -t blocked_cidrs < <(get_blocked_cidrs)
  for c in "${blocked_cidrs[@]+"${blocked_cidrs[@]}"}"; do
    [[ -z "${c}" ]] && continue
    cidr_entries+="        - \"${c}\""$'\n'
  done
  if [[ -n "${cidr_entries}" ]]; then
    egress_deny_block="$(cat <<EOF
  egressDeny:
    - toCIDR:
${cidr_entries%$'\n'}
EOF
)"
  fi

  cat <<EOF
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "policy-${resource_name}"
  namespace: "${SANDBOX_NAMESPACE}"
  labels:
    sandbox-session: "${session_id}"
    sandbox-dependency: "${resource_name}"
    sandbox-role: "dependency"
spec:
  endpointSelector:
    matchLabels:
      sandbox-dependency: "${resource_name}"
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
          rules:
${dns_rules_yaml}
${fqdn_egress_block}
${egress_deny_block}
  ingress:
    # The discriminating control: accept ONLY the owning session pod, on the one
    # dependency port. No sibling dependency, no other session, no namespace
    # reach. This — not a CIDR block — is what forecloses SSRF to siblings.
    - fromEndpoints:
        - matchLabels:
            sandbox-session: "${session_id}"
            sandbox-role: "session"
      toPorts:
        - ports:
            - port: "${port}"
              protocol: TCP
EOF
}
