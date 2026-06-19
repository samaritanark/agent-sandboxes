#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/catalogue.sh — Vetted dependency catalogue (Phase 5)
#
# A profile may declare per-session dependencies it needs at runtime — an
# MCP server registered with the agent (`mcps:`), or a plain service the
# session connects to directly (`services:`). Each declared name resolves to
# a *catalogue entry*: a vetted spec (image+digest, port, egress allowlist,
# resource limits, declared secrets) shipped by the org install or a team
# overlay — NOT free-form YAML a user can author inline. Users select from a
# catalogue; they do not describe arbitrary workloads. This mirrors how
# --allow-domain is checked-not-trusted (lib/checks.sh) and how blocked
# destinations are org-controlled. See docs/design/phase5-mcp-dependencies.md
# (§2.1) and PRINCIPLES.md ("Never permitted" #8 — no "just add it for this
# one task" escape hatch).
#
# Resolution order (org is canonical, wins on a name collision):
#   1. ${SANDBOX_ROOT}/config/catalogue/<name>.yaml   — org install
#   2. <overlay>/catalogue/<name>.yaml                — team overlay
# An overlay may ADD entirely new entries; it can never override an org entry
# (org-first resolution makes "an overlay broadens an org dependency"
# structurally impossible — the safety property from PRINCIPLES.md
# "Overlays additive-only on safety"). Per-field narrowing-merge of an
# existing org entry is intentionally out of scope for the first cut.
#
# Catalogue entry schema (flat — parses with the lib/config.sh YAML helpers):
#   name: example-mcp                  # informational; filename is canonical
#   kind: mcp                            # required: mcp | service
#   image: ghcr.io/example-org/example-mcp@sha256:<64hex>   # required, digest-pinned
#   port: 8080                           # required: container port the dep serves
#   version: "1.2.3"                     # optional; recorded in the audit trail
#   # Resource limits — optional; defaults below. Full K8s quantity strings.
#   cpu_request: "250m"
#   cpu_limit: "1"
#   mem_request: "256Mi"
#   mem_limit: "512Mi"
#   ephemeral_limit: "1Gi"
#   # MCP transport (kind: mcp only) — how the agent reaches it over the Service.
#   mcp_transport: http                  # http | sse  (default http)
#   mcp_path: /mcp                       # URL path    (default /mcp)
#   # The dependency's OWN egress allowlist (443/TCP), default empty = DNS-only.
#   # Every entry is checked against blocked-destinations like --allow-domain.
#   egress:
#     - api.internal.example.com
#   # Session-scoped secrets (Phase 4 names) provisioned into the dep pod.
#   secrets:
#     - INNKEEPER_TOKEN
set -euo pipefail

# Resource defaults for a dependency pod when the entry omits them. Deliberately
# smaller than the agent pod (lib/resources.sh) — most deps are lightweight; the
# browser entry overrides these explicitly (Phase 3).
CATALOGUE_DEFAULT_CPU_REQUEST="250m"
CATALOGUE_DEFAULT_CPU_LIMIT="1"
CATALOGUE_DEFAULT_MEM_REQUEST="256Mi"
CATALOGUE_DEFAULT_MEM_LIMIT="512Mi"
CATALOGUE_DEFAULT_EPHEMERAL_LIMIT="1Gi"
# Default non-root UID a dependency pod runs as when the entry doesn't override
# it. Catalogue images often default to root; the dependency builder pins this
# UID alongside runAsNonRoot so the pod is non-root regardless (lib/dependency.sh).
CATALOGUE_DEFAULT_RUN_AS_USER="1000"

# catalogue_is_valid_name <name> — true if name is safe as a catalogue
# filename (<name>.yaml) and reference. Same ruleset as is_valid_profile_name
# (lib/profile.sh): rejects empty, path separators/traversal, leading dots.
catalogue_is_valid_name() {
  local name="$1"
  [[ -n "${name}" ]]                   || return 1
  [[ "${name}" == *"/"* ]]             && return 1
  [[ "${name}" == *".."* ]]            && return 1
  [[ "${name}" == .* ]]                && return 1
  [[ "${name}" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  return 0
}

# org_catalogue_dir — print the org catalogue directory path (always; may not
# exist yet, callers check).
org_catalogue_dir() {
  echo "${SANDBOX_ROOT}/config/catalogue"
}

# overlay_catalogue_dir — print the active overlay's catalogue directory, if an
# overlay is configured and ships one. Empty otherwise.
overlay_catalogue_dir() {
  local overlay
  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  [[ -n "${overlay}" ]] || return 0
  local path="${overlay}/catalogue"
  [[ -d "${path}" ]] && echo "${path}"
}

# catalogue_resolve <name> — locate a catalogue entry YAML by name. Org dir
# first, then the overlay (org wins on collision). Prints the absolute path on
# success; returns 1 with no output on miss.
catalogue_resolve() {
  local name="$1"
  catalogue_is_valid_name "${name}" || return 1

  local org_path
  org_path="$(org_catalogue_dir)/${name}.yaml"
  if [[ -f "${org_path}" ]]; then
    echo "${org_path}"
    return 0
  fi

  local ov_dir
  ov_dir="$(overlay_catalogue_dir)"
  if [[ -n "${ov_dir}" ]] && [[ -f "${ov_dir}/${name}.yaml" ]]; then
    echo "${ov_dir}/${name}.yaml"
    return 0
  fi

  return 1
}

# catalogue_field <path> <key> [default] — print a scalar catalogue field,
# falling back to a default when the key is absent or empty.
catalogue_field() {
  local path="$1" key="$2" default="${3:-}"
  local val
  val="$(extract_yaml_scalar_from_file "${path}" "${key}")"
  if [[ -z "${val}" ]]; then
    echo "${default}"
  else
    echo "${val}"
  fi
}

# catalogue_list <path> <key> — print a catalogue list field, one item per line.
catalogue_list() {
  extract_yaml_list_from_file "$1" "$2"
}

# catalogue_has_key <path> <key> — return 0 if a top-level key is present at all,
# regardless of whether its value is a scalar, a block list, or empty. Used to
# reject forbidden fields (cap_add etc.) that catalogue_field would miss when
# written as a list.
catalogue_has_key() {
  local path="$1" key="$2"
  [[ -f "${path}" ]] || return 1
  grep -qE "^${key}:" "${path}"
}

# catalogue_validate_entry <path> <name> — verify a resolved entry is safe to
# deploy. Prints ERROR lines to stderr and returns 1 on the first failure;
# returns 0 when the entry is sound. Checks:
#   - kind is mcp|service
#   - image is present AND digest-pinned (@sha256:<64hex>) — never a mutable tag
#   - port is a plausible TCP port
#   - every egress domain passes the blocked-destinations check (org + overlay)
#   - declared secret names are valid env-var identifiers
#   - kind: mcp declares a supported transport
# Image signature + scan gating (cosign) is layered on at catalogue admission
# for high-value images (the browser); see §2.7 #2 and Phase 3.
catalogue_validate_entry() {
  local path="$1" name="$2"

  local kind image port
  kind="$(catalogue_field "${path}" kind)"
  image="$(catalogue_field "${path}" image)"
  port="$(catalogue_field "${path}" port)"

  case "${kind}" in
    mcp|service) ;;
    *)
      echo "ERROR: catalogue entry '${name}': kind must be 'mcp' or 'service' (got '${kind}')." >&2
      return 1
      ;;
  esac

  if [[ -z "${image}" ]]; then
    echo "ERROR: catalogue entry '${name}': missing required 'image'." >&2
    return 1
  fi
  # Digest pinning is non-negotiable: a mutable tag lets the image change under
  # a vetted name, defeating the whole catalogue-is-vetted premise (§2.7 #2).
  if [[ ! "${image}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: catalogue entry '${name}': image must be digest-pinned" >&2
    echo "       (…@sha256:<64 hex>), not a mutable tag: '${image}'." >&2
    return 1
  fi

  if [[ ! "${port}" =~ ^[0-9]+$ ]] || [[ "${port}" -lt 1 ]] || [[ "${port}" -gt 65535 ]]; then
    echo "ERROR: catalogue entry '${name}': 'port' must be 1-65535 (got '${port}')." >&2
    return 1
  fi

  # run_as_user, if set, must be a non-zero UID — the dependency pod enforces
  # runAsNonRoot, so UID 0 would be a contradiction the kubelet rejects anyway.
  local run_as_user
  run_as_user="$(catalogue_field "${path}" run_as_user)"
  if [[ -n "${run_as_user}" ]]; then
    if [[ ! "${run_as_user}" =~ ^[0-9]+$ ]] || [[ "${run_as_user}" -eq 0 ]]; then
      echo "ERROR: catalogue entry '${name}': run_as_user must be a non-zero UID (got '${run_as_user}')." >&2
      return 1
    fi
  fi

  # The dependency's own egress allowlist is checked exactly like --allow-domain:
  # an org/overlay block can never be opened by a catalogue entry. A bare '*'
  # wildcard is refused outright — a dependency may not be granted unbounded
  # egress (that is the "unpoliced NIC" the design forbids, §2.2).
  local d
  while IFS= read -r d; do
    [[ -z "${d}" ]] && continue
    if [[ "${d}" == "*" ]]; then
      echo "ERROR: catalogue entry '${name}': egress '*' (allow-all) is forbidden." >&2
      return 1
    fi
    # check_domain_not_blocked dies on a match; run it in a subshell so a block
    # surfaces as a clean validation failure rather than aborting the process
    # mid-resolution.
    if ! ( check_domain_not_blocked "${d}" ) 2>/dev/null; then
      echo "ERROR: catalogue entry '${name}': egress domain '${d}' is blocked by" >&2
      echo "       the org or overlay blocked-destinations list." >&2
      return 1
    fi
  done < <(catalogue_list "${path}" egress)

  local s
  while IFS= read -r s; do
    [[ -z "${s}" ]] && continue
    if [[ ! "${s}" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
      echo "ERROR: catalogue entry '${name}': secret name '${s}' must match" >&2
      echo "       [A-Z_][A-Z0-9_]* (it becomes an env var in the dep pod)." >&2
      return 1
    fi
  done < <(catalogue_list "${path}" secrets)

  if [[ "${kind}" == "mcp" ]]; then
    local transport
    transport="$(catalogue_field "${path}" mcp_transport http)"
    case "${transport}" in
      http|sse) ;;
      *)
        echo "ERROR: catalogue entry '${name}': mcp_transport must be 'http' or 'sse' (got '${transport}')." >&2
        return 1
        ;;
    esac
  fi

  # Privilege-escalation fields are forbidden in a catalogue entry. The
  # dependency manifest builder drops ALL capabilities and has no path to add
  # one, so this is defense-in-depth with a clear error: never grant a
  # dependency (least of all a browser) a capability, privileged mode, or the
  # host network. Adding --cap-add=SYS_ADMIN to "restore" Chromium's sandbox is
  # the specific wrong workaround the design forbids (§1.8).
  local forbidden_field
  for forbidden_field in cap_add capabilities privileged host_network hostPID hostIPC; do
    if catalogue_has_key "${path}" "${forbidden_field}"; then
      echo "ERROR: catalogue entry '${name}': field '${forbidden_field}' is forbidden." >&2
      echo "       Dependencies run with ALL capabilities dropped and no host" >&2
      echo "       namespaces; a browser uses --no-sandbox, never added caps (§1.8)." >&2
      return 1
    fi
  done

  # High-value images (the browser is the canary, §2.7 #2) must be signature-
  # verified at admission, not digest-pinned alone. An entry opts in with
  # `verify_signature: true`; we then require cosign and a passing verification.
  local class verify_sig
  class="$(catalogue_field "${path}" class)"
  verify_sig="$(catalogue_field "${path}" verify_signature)"
  if [[ "${class}" == "browser" ]] && [[ "${verify_sig}" != "true" ]]; then
    echo "ERROR: catalogue entry '${name}': class 'browser' requires" >&2
    echo "       'verify_signature: true' — the largest, most third-party image" >&2
    echo "       in the catalogue is the highest-value supply-chain target and" >&2
    echo "       must be signature-verified, not digest-pinned alone (§2.7 #2)." >&2
    return 1
  fi
  if [[ "${verify_sig}" == "true" ]]; then
    if ! verify_catalogue_image_signature "${path}" "${name}" "${image}"; then
      return 1
    fi
  fi

  return 0
}

# verify_catalogue_image_signature <path> <name> <image> — verify a catalogue
# image's signature with cosign at admission. Keyless (Fulcio) verification when
# the entry declares cosign_identity + cosign_issuer; key-based when it declares
# cosign_key. Fails closed: if cosign is not installed, a high-value image cannot
# be admitted (that is a setup gap, not a reason to skip the check). Returns 0
# on a verified signature, non-zero otherwise.
verify_catalogue_image_signature() {
  local path="$1" name="$2" image="$3"

  if ! command -v cosign >/dev/null 2>&1; then
    echo "ERROR: catalogue entry '${name}' requires signature verification but" >&2
    echo "       'cosign' is not installed. Install cosign or remove the entry." >&2
    return 1
  fi

  local key identity issuer
  key="$(catalogue_field "${path}" cosign_key)"
  identity="$(catalogue_field "${path}" cosign_identity)"
  issuer="$(catalogue_field "${path}" cosign_issuer)"

  local -a args=(verify)
  if [[ -n "${key}" ]]; then
    args+=(--key "${key}")
  elif [[ -n "${identity}" ]] && [[ -n "${issuer}" ]]; then
    args+=(--certificate-identity-regexp "${identity}" --certificate-oidc-issuer "${issuer}")
  else
    echo "ERROR: catalogue entry '${name}': verify_signature is set but neither" >&2
    echo "       cosign_key nor (cosign_identity + cosign_issuer) is declared." >&2
    return 1
  fi
  args+=("${image}")

  if ! cosign "${args[@]}" >/dev/null 2>&1; then
    echo "ERROR: catalogue entry '${name}': cosign signature verification failed" >&2
    echo "       for image '${image}'." >&2
    return 1
  fi
  return 0
}
