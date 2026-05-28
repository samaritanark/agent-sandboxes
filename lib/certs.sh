#!/usr/bin/env bash
# lib/certs.sh — Extract a corporate TLS-intercept proxy's root CA from
# the host's trust store (or directly from the wire), so users can drop
# it into config/extra-ca-certs/ without hand-rolling platform-specific
# openssl/security/PowerShell incantations.
#
# Companion to bin/sandbox's `setup-proxy-cert` subcommand.
set -euo pipefail

# Common subject-name fragments for TLS-intercept proxies seen in the wild.
# Used to filter the host's trust store down to "things that look like a MITM
# root", since the trust store has hundreds of legitimate public CAs we don't
# want to bake into the sandbox image. Case-insensitive substring match.
SANDBOX_PROXY_CA_VENDORS=(
  "Zscaler"
  "Netskope"
  "Forcepoint"
  "Cisco Umbrella"
  "Palo Alto"
  "Symantec"
  "Blue Coat"
  "Prisma"
  "iboss"
  "Menlo"
)

# proxy_ca_vendor_regex — pipe-joined egrep pattern from SANDBOX_PROXY_CA_VENDORS
# (and any extra vendor passed via --vendor). Matches the certificate Subject CN
# or Subject string.
proxy_ca_vendor_regex() {
  local extra="${1:-}"
  local -a vendors=("${SANDBOX_PROXY_CA_VENDORS[@]}")
  [[ -n "${extra}" ]] && vendors=("${extra}" "${vendors[@]}")
  local IFS='|'
  echo "${vendors[*]}"
}

# extract_proxy_cert_linux <vendor_regex> [out_pem]
#
# Scan the host's trust store for certs whose Subject matches one of the
# proxy-vendor name fragments. The local-admin / IT-managed install location
# is /usr/local/share/ca-certificates/*.crt — one PEM per file. We prefer
# that over /etc/ssl/certs/ca-certificates.crt because the per-file layout
# preserves the original cert without splitting/dedup gymnastics. As a
# fallback we walk the full bundle and emit each matching block.
#
# Prints PEM cert(s) to stdout (or writes to out_pem if given). Returns 0 if
# at least one cert was found, 1 otherwise.
extract_proxy_cert_linux() {
  local vendor_re="$1"
  local out="${2:-}"
  local -a found_pems=()

  # 1. Per-file location (preferred).
  local f
  for f in /usr/local/share/ca-certificates/*.crt /etc/ssl/certs/*.pem; do
    [[ -e "${f}" ]] || continue
    local subj
    subj="$(openssl x509 -noout -subject -in "${f}" 2>/dev/null \
      | sed 's/^subject= *//')"
    [[ -z "${subj}" ]] && continue
    if echo "${subj}" | grep -Eqi "${vendor_re}"; then
      found_pems+=("${f}")
    fi
  done

  # 2. Bundle fallback — split the system bundle into individual PEM blocks
  #    and emit any whose subject matches. awk is the simplest cross-distro
  #    PEM splitter; we shell out to openssl per-block to read the subject.
  if [[ "${#found_pems[@]}" -eq 0 ]] && [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    local tmpdir
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${tmpdir}'" RETURN
    awk -v dir="${tmpdir}" '
      /-----BEGIN CERTIFICATE-----/ { idx++; f = sprintf("%s/c%05d.pem", dir, idx) }
      idx { print > f }
    ' /etc/ssl/certs/ca-certificates.crt
    for f in "${tmpdir}"/c*.pem; do
      [[ -e "${f}" ]] || continue
      local subj
      subj="$(openssl x509 -noout -subject -in "${f}" 2>/dev/null \
        | sed 's/^subject= *//')"
      if echo "${subj}" | grep -Eqi "${vendor_re}"; then
        found_pems+=("${f}")
      fi
    done
  fi

  [[ "${#found_pems[@]}" -eq 0 ]] && return 1

  if [[ -n "${out}" ]]; then
    : > "${out}"
    cat "${found_pems[@]}" >> "${out}"
  else
    cat "${found_pems[@]}"
  fi
  return 0
}

# extract_proxy_cert_macos <vendor_regex> [out_pem]
#
# Walk the macOS System keychain (where MDM/Jamf installs corporate roots)
# and dump any cert whose CN matches the vendor regex. `security
# find-certificate -a -p` emits one PEM block per cert; we filter via openssl
# subject inspection identical to the Linux path.
extract_proxy_cert_macos() {
  local vendor_re="$1"
  local out="${2:-}"

  command -v security >/dev/null 2>&1 \
    || { echo "ERROR: 'security' command not found (macOS Security framework CLI)." >&2; return 2; }

  local tmpdir
  tmpdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmpdir}'" RETURN

  # Dump all PEM certs from the System keychain, split into one file per cert.
  security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null \
    | awk -v dir="${tmpdir}" '
        /-----BEGIN CERTIFICATE-----/ { idx++; f = sprintf("%s/c%05d.pem", dir, idx) }
        idx { print > f }
      '

  local -a found_pems=()
  local f
  for f in "${tmpdir}"/c*.pem; do
    [[ -e "${f}" ]] || continue
    local subj
    subj="$(openssl x509 -noout -subject -in "${f}" 2>/dev/null \
      | sed 's/^subject= *//')"
    if echo "${subj}" | grep -Eqi "${vendor_re}"; then
      found_pems+=("${f}")
    fi
  done

  [[ "${#found_pems[@]}" -eq 0 ]] && return 1

  if [[ -n "${out}" ]]; then
    : > "${out}"
    cat "${found_pems[@]}" >> "${out}"
  else
    cat "${found_pems[@]}"
  fi
  return 0
}

# extract_proxy_cert_windows <vendor_regex> [out_pem]
#
# Called from WSL2 when the Linux trust store had no proxy CA — the corporate
# root commonly lives only in the Windows LocalMachine\Root store. We shell
# out to powershell.exe (always on PATH inside WSL) to enumerate the store,
# filter by Subject substring, and emit PEM.
#
# We split the regex back into vendor list at the bash level so we can
# build a PowerShell `-or` chain; piping a regex into PowerShell's
# -match operator would also work but is fiddlier to quote across the
# wsl/PowerShell boundary.
extract_proxy_cert_windows() {
  local vendor_re="$1"
  local out="${2:-}"

  command -v powershell.exe >/dev/null 2>&1 \
    || { echo "ERROR: powershell.exe not found on PATH inside this WSL distro." >&2; return 2; }

  # Build the PowerShell Where-Object filter from the same vendor list. The
  # outer single quotes survive into PS; we use -match with the same alternation
  # regex.
  local ps_filter="\$_.Subject -match '${vendor_re}'"
  local ps_script
  ps_script="$(cat <<EOF
\$ErrorActionPreference = 'Stop'
Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root |
  Where-Object { ${ps_filter} } |
  ForEach-Object {
    \$b64 = [Convert]::ToBase64String(\$_.RawData, 'InsertLineBreaks')
    "-----BEGIN CERTIFICATE-----`n\$b64`n-----END CERTIFICATE-----"
  }
EOF
)"

  # Capture into a temp file so we can detect "nothing returned" cleanly.
  local tmp
  tmp="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '${tmp}'" RETURN

  powershell.exe -NoProfile -Command "${ps_script}" 2>/dev/null \
    | tr -d '\r' > "${tmp}"

  if ! grep -q 'BEGIN CERTIFICATE' "${tmp}"; then
    return 1
  fi

  if [[ -n "${out}" ]]; then
    cp "${tmp}" "${out}"
  else
    cat "${tmp}"
  fi
  return 0
}

# extract_proxy_cert_from_wire <host[:port]> [out_pem]
#
# Last-resort extraction: open a TLS connection to `host` and capture every
# non-leaf cert the network presents. On a transparent-intercept proxy the
# chain we receive is leaf -> proxy-intermediate(s) -> proxy-root. We skip
# the first cert (the resigned leaf, which is per-site and not what we
# want to trust) and emit the rest. Servers don't always send the root,
# so the user may still need to combine with one of the trust-store
# extractors above, but in practice including the intermediate is usually
# enough to make TLS validate inside the sandbox image.
extract_proxy_cert_from_wire() {
  local target="$1"
  local out="${2:-}"

  command -v openssl >/dev/null 2>&1 \
    || { echo "ERROR: openssl not found." >&2; return 2; }

  [[ "${target}" == *:* ]] || target="${target}:443"

  local tmpdir
  tmpdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmpdir}'" RETURN

  # -showcerts: print every cert the server sends. openssl has no connect
  # timeout flag, so wrap with timeout(1) — without it a routing blackhole
  # or filtered firewall would leave us hanging on stdin.
  local timeout_cmd=""
  if command -v timeout >/dev/null 2>&1; then
    timeout_cmd="timeout 10"
  fi
  if ! echo | ${timeout_cmd} openssl s_client \
       -showcerts -servername "${target%%:*}" \
       -connect "${target}" 2>/dev/null \
       | awk -v dir="${tmpdir}" '
           /-----BEGIN CERTIFICATE-----/ { idx++; f = sprintf("%s/c%05d.pem", dir, idx) }
           idx { print > f }
         '; then
    return 1
  fi

  local -a pems=("${tmpdir}"/c*.pem)
  [[ -e "${pems[0]:-}" ]] || return 1

  # Drop the leaf (index 0). If only one cert was sent, fall back to emitting
  # the leaf — better something than nothing, and the user can inspect.
  if [[ "${#pems[@]}" -gt 1 ]]; then
    pems=("${pems[@]:1}")
  fi

  if [[ -n "${out}" ]]; then
    : > "${out}"
    cat "${pems[@]}" >> "${out}"
  else
    cat "${pems[@]}"
  fi
  return 0
}

# describe_pems <file> — print Subject + Issuer for each cert in a multi-cert
# PEM file. Used by the setup-proxy-cert command to confirm to the user what
# was extracted before they trust the sandbox build with it.
describe_pems() {
  local file="$1"
  [[ -f "${file}" ]] || return 0
  local tmpdir
  tmpdir="$(mktemp -d)"
  awk -v dir="${tmpdir}" '
    /-----BEGIN CERTIFICATE-----/ { idx++; f = sprintf("%s/c%05d.pem", dir, idx) }
    idx { print > f }
  ' "${file}"
  local f i=0
  for f in "${tmpdir}"/c*.pem; do
    [[ -e "${f}" ]] || continue
    (( i++ )) || true
    local subj iss
    subj="$(openssl x509 -noout -subject -in "${f}" 2>/dev/null | sed 's/^subject= *//')"
    iss="$(openssl x509 -noout -issuer -in "${f}" 2>/dev/null | sed 's/^issuer= *//')"
    echo "  [${i}] Subject: ${subj}"
    echo "      Issuer:  ${iss}"
  done
  rm -rf "${tmpdir}"
}
