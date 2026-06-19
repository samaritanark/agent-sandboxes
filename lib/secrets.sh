#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/secrets.sh — Host-side secret store + session-scoped injection
#
# Background credential pattern (mirrors PRINCIPLES.md "Credential
# isolation" rule 2): user-managed secrets live in a host-side store at
# ~/.sandbox/secrets/, never persisted in the cluster across sessions.
# When a profile declares `secrets: [NAME, ...]`, those values are
# packed into ONE session-scoped K8s Secret at launch and torn down
# with the session — same lifecycle as --infra-token.
#
# Host-side store:
#   ~/.sandbox/secrets/<NAME>        mode 0600, value is the file's bytes
#
# Naming: NAME must be a valid env-var identifier — uppercase letters,
# digits, underscore; leading non-digit. The name IS the env-var seen by
# the agent inside the pod, so 'JIRA_PAT' lands as $JIRA_PAT.
#
# Cluster-side injection: see create_session_secrets / delete_session_secrets
# below. The manifest layer (lib/manifest.sh) pulls the secret in via
# envFrom: secretRef so all declared keys become container env vars.
set -euo pipefail

SECRETS_STORE_DIR="${SANDBOX_SECRETS_DIR:-${HOME}/.sandbox/secrets}"

###############################################################################
# Host-side store
###############################################################################

# secret_validate_name <name> — die if name is not a valid env-var
# identifier. Max length 64 keeps secret names readable and well within
# K8s annotation/label limits when we use them.
secret_validate_name() {
  local name="$1"
  if [[ -z "${name}" ]]; then
    echo "ERROR: secret name is empty." >&2
    exit 1
  fi
  if [[ ${#name} -gt 64 ]]; then
    echo "ERROR: secret name '${name}' is longer than 64 characters." >&2
    exit 1
  fi
  if [[ ! "${name}" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
    echo "ERROR: secret name '${name}' must match [A-Z_][A-Z0-9_]* — the" >&2
    echo "       name is also the env-var the agent sees inside the pod." >&2
    exit 1
  fi
}

# secret_store_path <name> — print the host-side store path for a name.
secret_store_path() {
  echo "${SECRETS_STORE_DIR}/$1"
}

# secret_exists <name> — return 0 if the secret is present in the store.
secret_exists() {
  [[ -f "$(secret_store_path "$1")" ]]
}

# secret_set_from_stdin <name> — read secret value from stdin and write
# to the store. Writes mode 0600. Overwrites any existing entry.
secret_set_from_stdin() {
  local name="$1"
  secret_validate_name "${name}"

  mkdir -p "${SECRETS_STORE_DIR}"
  chmod 0700 "${SECRETS_STORE_DIR}" 2>/dev/null || true

  local path
  path="$(secret_store_path "${name}")"
  # umask so the create itself is restrictive, in case the explicit
  # chmod below races a reader on a shared host.
  ( umask 0177 && cat > "${path}" )
  chmod 0600 "${path}"
}

# secret_set_from_file <name> <file> — copy a file's content into the
# store. Same mode handling as secret_set_from_stdin.
secret_set_from_file() {
  local name="$1"
  local src="$2"
  secret_validate_name "${name}"
  if [[ ! -f "${src}" ]]; then
    echo "ERROR: source file not found: ${src}" >&2
    exit 1
  fi

  mkdir -p "${SECRETS_STORE_DIR}"
  chmod 0700 "${SECRETS_STORE_DIR}" 2>/dev/null || true

  local path
  path="$(secret_store_path "${name}")"
  cp -f "${src}" "${path}"
  chmod 0600 "${path}"
}

# secret_set_from_env <name> <env_var> — copy the value of a host env var
# into the store. Refuses an unset or empty source — storing an empty
# secret silently would be a worse footgun than a clear error, since the
# launch path validates only presence-in-store, not value-non-empty.
# Caller is responsible for env-var name validation (it's a shell ident,
# not a secret name — different ruleset). No trailing-newline trap that
# `echo $VAR | sandbox secret set NAME` carries.
secret_set_from_env() {
  local name="$1"
  local env_var="$2"
  secret_validate_name "${name}"

  if [[ -z "${env_var}" ]]; then
    echo "ERROR: --from-env requires a source variable name." >&2
    exit 1
  fi
  # Indirect expansion: ${!env_var} reads the named variable. Unset and
  # empty are indistinguishable here, which is fine — both are user error.
  local value="${!env_var:-}"
  if [[ -z "${value}" ]]; then
    echo "ERROR: env var \$${env_var} is unset or empty in this shell." >&2
    echo "       Export it first, e.g.  export ${env_var}=...  then re-run." >&2
    exit 1
  fi

  mkdir -p "${SECRETS_STORE_DIR}"
  chmod 0700 "${SECRETS_STORE_DIR}" 2>/dev/null || true

  local path
  path="$(secret_store_path "${name}")"
  ( umask 0177 && printf '%s' "${value}" > "${path}" )
  chmod 0600 "${path}"
}

# secret_get_value <name> — print a secret's value to stdout. Used by
# the launch path to populate the session-scoped K8s Secret. Errors
# (with exit) if the named secret isn't in the store.
secret_get_value() {
  local name="$1"
  secret_validate_name "${name}"
  local path
  path="$(secret_store_path "${name}")"
  if [[ ! -f "${path}" ]]; then
    echo "ERROR: secret '${name}' is not in ${SECRETS_STORE_DIR/#${HOME}/\~}/" >&2
    echo "       Run 'sandbox secret set ${name}' first." >&2
    exit 1
  fi
  cat "${path}"
}

# secret_delete <name> — remove a secret from the store. Returns 0
# whether or not the secret existed.
secret_delete() {
  local name="$1"
  secret_validate_name "${name}"
  rm -f "$(secret_store_path "${name}")"
}

# secret_list — print one row per stored secret: "NAME  <bytes>  <mtime>".
# Values are never printed. No-op (empty output) when no store exists yet.
secret_list() {
  [[ -d "${SECRETS_STORE_DIR}" ]] || return 0
  local f name size mtime
  for f in "${SECRETS_STORE_DIR}"/*; do
    [[ -f "${f}" ]] || continue
    name="$(basename "${f}")"
    size="$(stat -c '%s' "${f}" 2>/dev/null || echo "?")"
    mtime="$(stat -c '%y' "${f}" 2>/dev/null | cut -d. -f1 || echo "?")"
    printf '%-32s  %6s bytes  %s\n' "${name}" "${size}" "${mtime}"
  done
}

###############################################################################
# Cluster-side injection (session-scoped Secret)
###############################################################################

# session_secrets_name <session_id> — canonical K8s Secret name for the
# bundle of profile-declared secrets for one session.
session_secrets_name() {
  echo "session-secrets-$1"
}

# create_session_secrets <session_id> <NAME1> <NAME2> ... — read each
# named secret from the host-side store and apply a single K8s Secret
# bundling them. The Secret name is canonical so the manifest layer
# and teardown can find it without a registry lookup.
#
# Caller is responsible for first validating that every NAME exists in
# the store via secret_exists — this function uses secret_get_value
# which dies on missing.
create_session_secrets() {
  local session_id="$1"
  shift
  local -a names=("$@")

  [[ "${#names[@]}" -eq 0 ]] && return 0

  local secret_name
  secret_name="$(session_secrets_name "${session_id}")"

  # Build the kubectl args one --from-literal at a time. Using
  # --from-literal=KEY="${value}" avoids ever writing the value to a
  # tempfile on disk; the value sits in the helper's process memory and
  # in kubectl's API call payload.
  local -a kc_args=(create secret generic "${secret_name}"
                    --namespace "${SANDBOX_NAMESPACE}")
  local n value
  for n in "${names[@]}"; do
    value="$(secret_get_value "${n}")"
    kc_args+=("--from-literal=${n}=${value}")
  done
  kc_args+=(--dry-run=client -o yaml)

  kubectl "${kc_args[@]}" | kubectl apply -f - >/dev/null

  echo "  Created session secrets: ${secret_name} (${#names[@]} key(s))"
}

# create_dependency_secrets <resource_name> <session_id> <NAME1> ... — create a
# per-DEPENDENCY Secret bundle (Phase 5 §2.5). Identical mechanism to
# create_session_secrets, but keyed to one dependency's resource name and
# carrying the sandbox-session + sandbox-role=dependency labels so
# teardown_dependencies (lib/dependency.sh) reaps it with the rest of the
# dependency's objects. The dependency pod consumes it via envFrom (the
# secret_bundle argument to build_dependency_pod_manifest). Values come from the
# same host-side store as the agent's secrets — nothing long-lived in an image.
#
# Caller validates each NAME exists in the store first (resolve_session_dependencies
# does this so a missing secret fails the launch before any cluster op).
create_dependency_secrets() {
  local resource_name="$1"
  local session_id="$2"
  shift 2
  local -a names=("$@")

  [[ "${#names[@]}" -eq 0 ]] && return 0

  local secret_name="${resource_name}-secrets"
  local -a kc_args=(create secret generic "${secret_name}"
                    --namespace "${SANDBOX_NAMESPACE}")
  local n value
  for n in "${names[@]}"; do
    value="$(secret_get_value "${n}")"
    kc_args+=("--from-literal=${n}=${value}")
  done
  kc_args+=(--dry-run=client -o yaml)

  kubectl "${kc_args[@]}" | kubectl apply -f - >/dev/null
  # Label after apply (no yq dependency — yq is not a required runtime tool) so
  # the dependency sweeper's label selector reaps this Secret.
  kubectl label secret "${secret_name}" -n "${SANDBOX_NAMESPACE}" \
    "sandbox-session=${session_id}" "sandbox-role=dependency" \
    --overwrite >/dev/null 2>&1 || true

  echo "    Dependency secret: ${secret_name} (${#names[@]} key(s))"
}

# delete_session_secrets <session_id> — remove the per-session Secret.
# No-op if not present.
delete_session_secrets() {
  local session_id="$1"
  local secret_name
  secret_name="$(session_secrets_name "${session_id}")"
  kubectl delete secret -n "${SANDBOX_NAMESPACE}" \
    "${secret_name}" --ignore-not-found=true >/dev/null 2>&1 || true
}
