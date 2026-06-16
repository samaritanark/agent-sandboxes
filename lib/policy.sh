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
${kube_cidr_block}
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
