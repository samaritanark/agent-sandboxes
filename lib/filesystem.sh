#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/filesystem.sh — Workspace filesystem helpers
set -euo pipefail

# FORBIDDEN_PATH_PATTERNS — host paths that must never be used as --repo
FORBIDDEN_PATH_PATTERNS=(
  "${HOME}/.tsh"
  "${HOME}/.kube"
  "${HOME}/.ssh"
  "${HOME}/.config/openstack"
  "${HOME}/.aws"
  # Google Cloud SDK: config dir is ~/.config/gcloud on Linux/macOS
  # (overridable via CLOUDSDK_CONFIG); ~/.gcloud is not a path gcloud uses.
  "${HOME}/.config/gcloud"
  "${HOME}/.azure"
)

# MASKED_* — single source of truth for the paths the Tier 2/3 mask handles.
# Both the workspace classifier here and the pod-manifest builder in
# lib/manifest.sh consume these so the scan and the mask cannot drift.
MASKED_FILE_PATHS=(.env .env.local .npmrc clouds.yaml kubeconfig)
MASKED_DIR_PATH=.kube
MASKED_OPENRC_PATTERN='*-openrc.sh'

# validate_repo_path — check that path is safe for use as workspace
validate_repo_path() {
  local repo="$1"

  # Must exist and be a directory
  if [[ ! -d "${repo}" ]]; then
    echo "ERROR: Repo path does not exist or is not a directory: ${repo}" >&2
    echo " " >&2
    exit 1
  fi

  # Must be a git repository
  if ! git -C "${repo}" rev-parse --git-dir &>/dev/null; then
    echo "ERROR: Repo path is not a git repository: ${repo}" >&2
    echo "  Tier 2/3 requires a git repository." >&2
    exit 1
  fi

  # Resolve real path to handle symlinks
  local real_repo
  real_repo="$(realpath "${repo}")"

  # On WSL, /mnt/<drive>/... is a Windows NTFS path mounted in over 9P.
  # Every filesystem syscall crosses the NTFS<->WSL boundary, so git status,
  # file walks, and builds run 10-20x slower than on native ext4 inside
  # the distro. Refuse rather than letting Tier 2/3 sessions grind.
  if is_wsl && [[ "${real_repo}" == /mnt/* ]]; then
    echo "ERROR: Windows-side repo path detected: ${repo}" >&2
    echo "  Paths under /mnt/ (Windows drives) cross the NTFS<->WSL boundary," >&2
    echo "  which makes Tier 2/3 sessions extremely slow. Clone the repo" >&2
    echo "  inside the sandbox distro instead:" >&2
    echo "    wsl -d sandbox-vm -- bash -c 'git clone <url> ~/repos/$(basename "${repo}")'" >&2
    echo "  Then re-run with --repo ~/repos/$(basename "${repo}")" >&2
    exit 1
  fi

  # Check against forbidden patterns
  for forbidden in "${FORBIDDEN_PATH_PATTERNS[@]}"; do
    local real_forbidden
    real_forbidden="$(realpath "${forbidden}" 2>/dev/null || echo "${forbidden}")"
    # Exact match or path is under forbidden directory
    if [[ "${real_repo}" == "${real_forbidden}" ]] || \
       [[ "${real_repo}" == "${real_forbidden}/"* ]]; then
      echo "ERROR: Forbidden repo path: ${repo}" >&2
      echo "  '${forbidden}' is not allowed as a workspace." >&2
      exit 1
    fi
  done

  # Warn if path equals HOME exactly (redundant safety check)
  local real_home
  real_home="$(realpath "${HOME}")"
  if [[ "${real_repo}" == "${real_home}" ]]; then
    echo "ERROR: Cannot use \$HOME as workspace root." >&2
    exit 1
  fi
}

# workspace_prescan — scan workspace for sensitive files before session
workspace_prescan() {
  local workspace="$1"
  local issues_found=0

  echo "  Scanning for sensitive files in: ${workspace}"

  # Check for .env files
  local env_files=()
  while IFS= read -r -d '' f; do
    env_files+=("${f}")
  done < <(find "${workspace}" -maxdepth 3 \
             \( -name '.env' -o -name '.env.*' -o -name '*.env' \) \
             -not -path '*/.git/*' -print0 2>/dev/null)

  if [[ "${#env_files[@]}" -gt 0 ]]; then
    echo "  WARN: Found .env files (will be masked inside sandbox):"
    for f in "${env_files[@]}"; do
      echo "    ${f}"
    done
    (( issues_found++ )) || true
  fi

  # Check for common credential files
  local cred_patterns=(
    "clouds.yaml" "kubeconfig" ".npmrc" "*-openrc.sh"
    "*.pem" "*.key" "*.pfx" "id_rsa" "id_ed25519"
  )
  for pattern in "${cred_patterns[@]}"; do
    local found_files=()
    while IFS= read -r -d '' f; do
      found_files+=("${f}")
    done < <(find "${workspace}" -maxdepth 3 \
               -name "${pattern}" \
               -not -path '*/.git/*' -print0 2>/dev/null)
    if [[ "${#found_files[@]}" -gt 0 ]]; then
      echo "  WARN: Found potential credential file(s) matching '${pattern}':"
      for f in "${found_files[@]}"; do
        echo "    ${f}"
      done
      (( issues_found++ )) || true
    fi
  done

  # NOTE: the betterleaks secret scan that *gates* the launch lives in
  # secret_gate_repos (below), called from bin/sandbox's pre-session step.
  # workspace_prescan stays warn-only for the filename heuristics above.

  if [[ "${issues_found}" -gt 0 ]]; then
    echo ""
    echo "  NOTICE: ${issues_found} concern(s) found. Root-level matches of the masked"
    echo "  set will be masked inside the sandbox; deeper matches and broader patterns"
    echo "  (.pem, .key, id_rsa, ...) are flagged for review but NOT masked —"
    echo "  remove or relocate them before launching if they contain real secrets."
    echo ""
  else
    echo "  Pre-scan passed with no concerns."
  fi
}

# is_path_masked <repo> <relpath> — return 0 if a workspace-relative path is
# hidden from the agent by the sandbox mask, 1 otherwise. The masked set is
# the built-in constants above (root-level files, the .kube directory, the
# root *-openrc.sh glob) plus the repo's configured masked_paths: list
# (lib/config.sh:load_repo_masked_paths). Single source of truth for "would
# the agent be able to read this file?", consumed by the secret gate.
is_path_masked() {
  local repo="$1" relpath="$2"

  local p
  for p in "${MASKED_FILE_PATHS[@]}"; do
    [[ "${relpath}" == "${p}" ]] && return 0
  done

  # .kube directory: the dir itself or anything under it.
  [[ "${relpath}" == "${MASKED_DIR_PATH}" ]] && return 0
  [[ "${relpath}" == "${MASKED_DIR_PATH}/"* ]] && return 0

  # Root-level *-openrc.sh only (the mask is maxdepth 1). Guard against the
  # glob matching a slash, which [[ == ]] would otherwise allow. The unquoted
  # RHS is an intentional glob match against the pattern.
  # shellcheck disable=SC2053
  if [[ "${relpath}" != */* ]] && [[ "${relpath}" == ${MASKED_OPENRC_PATTERN} ]]; then
    return 0
  fi

  # Configured masked_paths (exact workspace-relative match).
  while IFS= read -r p; do
    [[ -z "${p}" ]] && continue
    [[ "${relpath}" == "${p}" ]] && return 0
  done < <(load_repo_masked_paths "${repo}")

  return 1
}

# LEAKSCAN_DEP_DIRS — basenames of dependency / module install trees that hold
# upstream-managed code, never workspace-owned secrets (npm's node_modules,
# Python virtualenvs and site-packages, a vendored Composer/Go/Bundler tree,
# build-tool caches, ...). When one of these is *gitignored* — a copy installed
# locally, not first-party content the repo tracks — it is excluded from the
# secret scan so a deep, polyglot workspace does not pay to walk it. The
# gitignore gate is deliberate: a directory with one of these names that the
# repo actually *tracks* is scanned normally, because a secret committed there
# IS the workspace's responsibility. Entries are shell globs.
#
# This built-in set is defined in tracked source on purpose: it is a security
# control, so it changes through git review (and, where operators use it, the
# `sandbox vet` signing gate). Two config knobs adjust it at runtime, split by
# the direction of risk (mirroring the vetting posture's "only ratchet UP"
# rule in lib/vetting.sh):
#   * WIDENING the skip set (adding names) makes the scan LOOSER — a way to hide
#     a secret from the gate — so it is confined to the operator trust level:
#     `leakscan_extra_dep_dirs:` in the team OVERLAY config only. A repo's or a
#     user's own config cannot add skips.  (_leakscan_overlay_extra_dep_dirs)
#   * DISABLING the exclusion makes the scan STRICTER (walks everything), so any
#     repo or user may do it locally: `leakscan_dep_exclusions: off`.
#     (_leakscan_exclusions_enabled)
LEAKSCAN_DEP_DIRS=(
  node_modules bower_components .pnp .yarn
  vendor .go
  .venv venv virtualenv .virtualenvs site-packages '*.egg-info' .eggs .tox .nox
  __pycache__ .mypy_cache .pytest_cache .ruff_cache
  .gradle .ansible
)

# LEAKSCAN_SKIP_PATHS — basenames of known-safe, first-party artifacts skipped
# *unconditionally* (whether tracked or gitignored), because their contents are
# audited or derived, not live secrets:
#   * .secrets.baseline — a detect-secrets baseline. It records SHA-1 *hashes* of
#     already-reviewed findings for the CI pipeline to diff against, so it is
#     not a place live secrets live; scanning it only yields hash-shaped false
#     positives. Requested by the security team.
# These differ from LEAKSCAN_DEP_DIRS: a detect-secrets baseline is committed
# (tracked), so the gitignore gate would never skip it — this list is not gated.
# That is a deliberate, narrow exemption: naming a file to match one of these
# entries would hide it from the gate, so keep the set to specific, well-known
# artifact filenames, never broad patterns. Disabling exclusions
# (`leakscan_dep_exclusions: off`) turns this off too and scans them.
LEAKSCAN_SKIP_PATHS=(
  .secrets.baseline
)

# _leakscan_is_dep_dir <basename> <glob>... — 0 if <basename> matches one of
# the candidate globs. The effective set is passed in (built-in + operator
# additions), not read from the global, so widening stays operator-scoped.
_leakscan_is_dep_dir() {
  local base="$1"; shift
  local glob
  for glob in "$@"; do
    # Intentional glob match: RHS is unquoted so patterns like *.egg-info work.
    # shellcheck disable=SC2053
    [[ "${base}" == ${glob} ]] && return 0
  done
  return 1
}

# _leakscan_overlay_extra_dep_dirs — extra dependency-dir names an operator has
# added via the team overlay's config.yaml (`leakscan_extra_dep_dirs:` list),
# one per line. Read ONLY from the operator overlay — never a repo's or a user's
# own config — because adding a skip loosens the scan, and that authority lives
# at the operator trust level (see LEAKSCAN_DEP_DIRS). Empty if no overlay is
# set or the key is absent.
_leakscan_overlay_extra_dep_dirs() {
  local overlay
  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  [[ -n "${overlay}" && -f "${overlay}/config.yaml" ]] || return 0
  extract_yaml_list_from_file "${overlay}/config.yaml" "leakscan_extra_dep_dirs"
}

# _leakscan_ignore_path — path to pass to betterleaks' -i/--gitleaks-ignore-path,
# an EXTRA .betterleaksignore/.gitleaksignore listing finding fingerprints to
# suppress. betterleaks' -i default is "." (the process CWD), so leaving it
# unset lets a stray ignore file in whatever directory `sandbox` runs from feed
# the scanner. We never let it default:
#   * if the team OVERLAY ships one (<overlay>/.betterleaksignore, else
#     .gitleaksignore) use it — an operator may keep a REVIEWED baseline of
#     accepted fingerprints. Suppressing findings is a loosening, so that
#     authority lives at the operator trust level, never a repo's or a user's
#     own config (mirrors leakscan_extra_dep_dirs; see LEAKSCAN_DEP_DIRS).
#   * otherwise print nothing; the caller passes a neutral empty path instead.
# Prints the chosen path, or nothing.
#
# NOTE: -i is ADDITIVE. betterleaks ALSO always reads a .gitleaksignore/
# .betterleaksignore at the SCAN-TARGET ROOT and offers no flag (as of 1.6.0) to
# disable it, so an operator baseline here does NOT neutralize a workspace that
# ships its own root ignore file — see the KNOWN LIMITATION in scan_repo_secrets.
_leakscan_ignore_path() {
  local overlay
  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  [[ -n "${overlay}" ]] || return 0
  local f
  for f in .betterleaksignore .gitleaksignore; do
    if [[ -f "${overlay}/${f}" ]]; then
      echo "${overlay}/${f}"
      return 0
    fi
  done
  return 0
}

# _leakscan_exclusions_enabled <repo> — 0 unless a repo or user config has
# turned dependency-tree exclusion OFF (`leakscan_dep_exclusions: off`, also
# false/no/0). Disabling makes the scan STRICTER (it then walks every tracked
# and gitignored file, save betterleaks' own built-in node_modules skip), so it
# is honored at the local trust level; there is deliberately no local way to
# make the scan looser. Repo config wins over user config; default is enabled.
_leakscan_exclusions_enabled() {
  local repo="$1" v=""
  v="$(extract_yaml_scalar_from_file "${repo}/${SANDBOX_REPO_CONFIG_NAME}" leakscan_dep_exclusions 2>/dev/null || true)"
  [[ -z "${v}" ]] && v="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" leakscan_dep_exclusions 2>/dev/null || true)"
  case "${v}" in
    off|false|no|0|OFF|False|FALSE|No|NO) return 1 ;;
    *) return 0 ;;
  esac
}

# _leakscan_regex_escape <string> — escape re2 metacharacters so a literal path
# can be embedded in an allowlist regex.
_leakscan_regex_escape() {
  printf '%s' "$1" | sed 's/[][\.^$*+?(){}|]/\\&/g'
}

# _leakscan_write_config <repo> <config_out> — write a betterleaks config to
# <config_out>. It (1) uses betterleaks' default ruleset and default allowlist
# (`[extend] useDefault = true`), and (2) unless a repo/user config disabled it
# (_leakscan_exclusions_enabled), adds allowlist paths for:
#   * every known-safe artifact filename (LEAKSCAN_SKIP_PATHS), unconditionally;
#   * every gitignored dependency directory — the built-in LEAKSCAN_DEP_DIRS
#     plus any operator-added names (_leakscan_overlay_extra_dep_dirs).
# `git ls-files --directory` collapses a wholly-ignored directory to its top and
# git walks the whole tree, so a nested one (packages/*/.venv) is found and
# excluded too. Owning the config is also a hardening: a passed -c takes
# precedence over a workspace's own .gitleaks.toml, so an untrusted repo can no
# longer ship a config that allowlists its own secrets away.
_leakscan_write_config() {
  local repo="$1" out="$2"
  {
    echo '# generated by sandbox — betterleaks config for the secret gate'
    echo '[extend]'
    echo 'useDefault = true'
  } > "${out}"

  # A repo or user may turn exclusions off (stricter: scan everything). Only
  # betterleaks' own built-in node_modules/lockfile skip remains in that case.
  _leakscan_exclusions_enabled "${repo}" || return 0

  # Collect allowlist regexes, then emit the block only if any apply.
  local -a paths=()

  # (a) Known-safe artifact filenames — unconditional (tracked or not), anchored
  # to a full path component so `.secrets.baseline` never matches, say,
  # `.secrets.baseline.bak`.
  local sp
  for sp in "${LEAKSCAN_SKIP_PATHS[@]}"; do
    paths+=("(^|/)$(_leakscan_regex_escape "${sp}")\$")
  done

  # (b) Gitignored dependency trees: built-in list + operator-overlay additions.
  # Widening is operator-scoped by construction — the extras come only from the
  # overlay, never a repo's or a user's own config.
  local -a dep_dirs=("${LEAKSCAN_DEP_DIRS[@]}")
  local extra
  while IFS= read -r extra; do
    [[ -n "${extra}" ]] && dep_dirs+=("${extra}")
  done < <(_leakscan_overlay_extra_dep_dirs)

  local d base
  while IFS= read -r d; do
    d="${d%/}"
    [[ -z "${d}" ]] && continue
    base="${d##*/}"
    _leakscan_is_dep_dir "${base}" "${dep_dirs[@]}" || continue
    paths+=("(^|/)$(_leakscan_regex_escape "${d}")(/|\$)")
  done < <(git -C "${repo}" ls-files --others --ignored --exclude-standard --directory 2>/dev/null)

  [[ "${#paths[@]}" -eq 0 ]] && return 0
  { echo '[allowlist]'; echo 'paths = ['; } >> "${out}"
  local p
  for p in "${paths[@]}"; do
    printf "  '''%s''',\n" "${p}" >> "${out}"
  done
  echo ']' >> "${out}"
  return 0
}

# _betterleaks_run <target> <report> [config] [ignore_path] — run one
# trustworthy betterleaks scan of <target> into <report>, optionally under
# <config> (-c) and <ignore_path> (-i, extra fingerprint allowlist). Returns 0 if
# the run can be trusted (a clean run, or leaks-found with a valid JSON-array
# report); returns 1 if it failed and the caller must fail closed. The exit code
# is left in LEAKSCAN_RC for the error message.
#
# Fail closed on scanner failure: a betterleaks runtime error (panic, bad
# config, OOM, truncated report) must NOT look like "no secrets found", or the
# gate would silently let a workspace through. The exit code alone is not
# enough — betterleaks returns 1 both for leaks-found and for some errors — so
# the report is the discriminator:
#   rc 0                    -> clean run (report is `null`/empty)
#   rc 1 + valid JSON array -> leaks found, parse the report
#   anything else           -> failure.
#
# --validation=false: never let the scanner reach out to live APIs to validate
# a secret found in an untrusted workspace (it is the betterleaks default, but
# we pin it so a future default flip or repo-local config cannot enable it).
#
# --ignore-gitleaks-allow: do NOT honor inline `gitleaks:allow`/`betterleaks:allow`
# comments. Those are workspace-authored suppression — an untrusted repo could
# annotate its own secret lines and pass the gate — the same bypass class that
# owning -c closes for a repo-local .gitleaks.toml. Pinned on unconditionally:
# there is no operator-owned inline comment, so nothing legitimately relies on
# them being honored.
#
# -i/--gitleaks-ignore-path points at an EXTRA .betterleaksignore/.gitleaksignore
# of accepted fingerprints (an operator baseline; see _leakscan_ignore_path).
# Its default is "." (the process CWD), which we never let stand. NOTE: -i is
# additive — betterleaks ALSO always reads an ignore file at the scan-target
# ROOT and (as of 1.6.0) offers no flag to disable that, so -i does NOT
# neutralize a workspace that ships its own root ignore file. See the KNOWN
# LIMITATION note in scan_repo_secrets.
#
# The scan runs at low CPU and (Linux) idle I/O priority so a deep-repo walk
# cannot starve interactive work on the host. ionice is Linux-only (absent on
# macOS) so it is used only when present; its idle class (-c3) needs no
# privilege. nice -n 19 is portable across GNU and BSD.
_betterleaks_run() {
  local target="$1" report="$2" config="${3:-}" ignore_path="${4:-}"
  LEAKSCAN_RC=0
  local -a cmd=(nice -n 19)
  command -v ionice >/dev/null 2>&1 && cmd+=(ionice -c3)
  cmd+=(betterleaks dir "${target}" --no-banner -f json -r "${report}" --validation=false --redact --ignore-gitleaks-allow)
  [[ -n "${config}" ]] && cmd+=(-c "${config}")
  [[ -n "${ignore_path}" ]] && cmd+=(-i "${ignore_path}")
  "${cmd[@]}" >/dev/null 2>&1 || LEAKSCAN_RC=$?
  [[ "${LEAKSCAN_RC}" == 0 ]] && return 0
  [[ "${LEAKSCAN_RC}" == 1 ]] && jq -e 'type == "array"' "${report}" >/dev/null 2>&1 && return 0
  return 1
}

# finding_is_encrypted <file> <line> [startcol] [endcol] — return 0 if the
# betterleaks finding at <file>:<line> (columns <startcol>..<endcol>, 1-based
# inclusive over the real file) is a value that is encrypted at rest, and
# therefore safe for the agent to read: only ciphertext is exposed, and the
# plaintext is unrecoverable without a key the workspace does not hold. Two
# shapes are recognised:
#
#   * Bitnami SealedSecret — the finding sits under the spec.encryptedData: of a
#     `kind: SealedSecret` (apiVersion *bitnami.com*) object. The object may be a
#     top-level document OR a mapping nested inside a block sequence (e.g. a
#     SealedSecret in a Helm `extraObjects:` list), so block-sequence "- "
#     markers are folded into indentation when walking the tree. kind and
#     apiVersion must be siblings of that spec: WITHIN the same object (one
#     sequence element), so a plaintext secret smuggled into the same file is NOT
#     exempted: not a sibling `kind: Secret` document/list-element, not the
#     SealedSecret's own spec.template, and not a SealedSecret elsewhere in the
#     list vouching for a different element.
#
#   * Mozilla SOPS — the flagged secret's own column span sits *inside* a SOPS
#     `ENC[AES256_GCM,...]` envelope on the flagged line. Containment (not mere
#     presence of the envelope on the line) is required, so a plaintext secret
#     that only shares a line with an envelope — an adjacent unencrypted value
#     (SOPS's unencrypted_regex escape hatch), or an `ENC[...]` string in a
#     trailing comment — is NOT exempted. Without a column span (betterleaks
#     StartColumn/EndColumn) containment cannot be proven, so we do not exempt.
#
# The real file is inspected (not betterleaks' --redact'd match), and only the
# enclosing YAML document / flagged span — never the wider workspace — so this
# cannot be widened by content elsewhere. Unlike a masked path, an exempted
# finding is one the agent CAN read; it is safe only because it is ciphertext.
# We do not (and cannot, without the key) verify the value decrypts; kind +
# apiVersion + encryptedData scoping (SealedSecret) and envelope containment
# (SOPS) are the honest, pragmatic bar.
finding_is_encrypted() {
  local file="$1" line="$2" startcol="${3:-}" endcol="${4:-}"
  [[ -f "${file}" ]] || return 1
  [[ "${line}" =~ ^[0-9]+$ ]] || return 1

  # SOPS: the flagged secret's span must lie strictly between the `[` and `]`
  # of an ENC[AES256_GCM,...] envelope on the flagged line — sharing the line
  # with one is not enough. Needs the finding's column span; without it we
  # cannot prove containment and fall through (no exemption). The real file is
  # read (the scanner match is redacted). StartColumn is de-inflated by one
  # (betterleaks reports it one past the match start) in the conservative
  # direction so an off-by-one can only make containment stricter, never
  # falsely exempt.
  if [[ "${startcol}" =~ ^[0-9]+$ && "${endcol}" =~ ^[0-9]+$ ]]; then
    if awk -v n="${line}" -v sc="${startcol}" -v ec="${endcol}" '
      NR != n { next }
      {
        s = sc - 1                             # real match start (1-based)
        pos = 1
        while ((idx = index(substr($0, pos), "ENC[AES256_GCM,")) > 0) {
          estart = pos + idx - 1               # column of the E in ENC[
          bopen = estart + 3                   # column of the [
          rest = substr($0, bopen)
          close_rel = index(rest, "]")
          if (close_rel == 0) { pos = estart + 1; continue }  # no terminator
          bclose = bopen + close_rel - 1       # column of the ]
          if (s > bopen && ec < bclose) { found = 1; exit }
          pos = estart + 1
        }
      }
      END { exit(found ? 0 : 1) }
    ' "${file}"; then
      return 0
    fi
  fi

  # SealedSecret: cheap pre-filter before buffering the file in awk. Allow the
  # `kind: SealedSecret` line to be indented and/or introduced by a sequence
  # marker so a SealedSecret nested in a list (Helm extraObjects:) still primes.
  grep -Eq '^[[:space:]]*(-[[:space:]]+)?kind:[[:space:]]*SealedSecret[[:space:]]*$' \
    "${file}" 2>/dev/null || return 1

  local verdict
  verdict="$(awk -v target="${line}" '
    { lines[NR] = $0 }
    END {
      if (target < 1 || target > NR) { print "0"; exit }
      # Bound the YAML document that contains the target line: from the doc
      # separator before it to the one after it (or the file ends).
      ds = 1; de = NR
      for (i = 1; i <= NR; i++) {
        if (lines[i] ~ /^(---|\.\.\.)([[:space:]].*)?$/) {
          if (i < target) ds = i + 1
          else if (i > target) { de = i - 1; break }
        }
      }
      # Precompute, for every line in the document window: its content indent
      # (leading spaces with each block-sequence "- " marker folded into the two
      # columns of indentation it introduces, so a mapping nested in a list is
      # walked at its true depth), whether it is a mapping key (and that key +
      # value), and whether it starts a sequence element (item[]). item[] is what
      # bounds one object from its list siblings.
      for (i = ds; i <= de; i++) {
        s = lines[i]
        t = s; sub(/^[[:space:]]+/, "", t)
        if (t == "" || substr(t, 1, 1) == "#") { blank[i] = 1; cind[i] = -1; continue }
        blank[i] = 0
        L = length(s); pos = 0
        while (pos < L && substr(s, pos + 1, 1) == " ") pos++
        it = 0
        while (pos < L && substr(s, pos + 1, 1) == "-" && (pos + 2 > L || substr(s, pos + 2, 1) == " ")) {
          it = 1; pos++
          while (pos < L && substr(s, pos + 1, 1) == " ") pos++
        }
        cind[i] = pos; item[i] = it
        rest = substr(s, pos + 1)
        if (rest ~ /^[^[:space:]#][^:]*:([[:space:]].*)?$/) {
          iskey[i] = 1
          k = rest; sub(/:.*$/, "", k); key[i] = k
          v = rest; sub(/^[^:]*:[[:space:]]*/, "", v); val[i] = v
        } else { iskey[i] = 0; key[i] = ""; val[i] = "" }
      }
      if (blank[target]) { print "0"; exit }

      # The target must nest directly under spec: > encryptedData:. Resolve its
      # parent and grandparent as the nearest preceding key lines at a strictly
      # smaller content indent (block-YAML structural parents).
      tInd = cind[target]
      p = -1
      for (j = target - 1; j >= ds; j--) {
        if (blank[j]) continue
        if (cind[j] < tInd) { if (iskey[j]) p = j; break }
      }
      if (p < 0 || key[p] != "encryptedData") { print "0"; exit }
      gp = -1
      for (j = p - 1; j >= ds; j--) {
        if (blank[j]) continue
        if (cind[j] < cind[p]) { if (iskey[j]) gp = j; break }
      }
      if (gp < 0 || key[gp] != "spec") { print "0"; exit }
      specInd = cind[gp]

      # Bound the SINGLE object (mapping / sequence element) that directly owns
      # this spec:, then require kind: SealedSecret + apiVersion *bitnami.com*
      # among the keys at spec: s indent WITHIN that object. Scanning up stops at
      # the element start (item[]) or a dedent; scanning down stops at the next
      # sibling element or a dedent. So a SealedSecret in another list element,
      # or a nested spec.template.spec:, cannot vouch for this value.
      start = ds
      for (j = gp; j >= ds; j--) {
        if (blank[j]) continue
        if (cind[j] > specInd) continue
        if (cind[j] < specInd) { start = j + 1; break }
        start = j
        if (item[j]) break
      }
      end = de + 1
      for (j = gp + 1; j <= de; j++) {
        if (blank[j]) continue
        if (cind[j] < specInd) { end = j; break }
        if (cind[j] == specInd && item[j]) { end = j; break }
      }
      kindok = 0; apiok = 0
      for (j = start; j < end; j++) {
        if (blank[j] || cind[j] != specInd || !iskey[j]) continue
        if (key[j] == "kind" && val[j] ~ /^SealedSecret[[:space:]]*$/) kindok = 1
        if (key[j] == "apiVersion" && val[j] ~ /bitnami\.com/) apiok = 1
      }
      print (kindok && apiok) ? "1" : "0"
    }
  ' "${file}")"
  [[ "${verdict}" == "1" ]] && return 0
  return 1
}

# scan_repo_secrets <repo> — scan a workspace with betterleaks and emit one TSV
# line per finding: "<class>\t<relpath>\t<RuleID>\t<line>\t<match>", where class
# is one of: yes (secret in a masked path, hidden from the agent), sealed
# (secret is an encrypted-at-rest value — SealedSecret/SOPS — the agent may read
# safely, see finding_is_encrypted), no (secret in an unmasked path), gitconfig
# (secret in .git/config), or error (scan failed). Secret values are redacted
# (--redact).
#
# Two scans run. (1) A whole-workspace directory scan — betterleaks excludes
# .git/ from directory walks, so this never sees anything under .git, and a
# generated config additionally excludes gitignored dependency trees (see
# _leakscan_write_config) so a deep repo is not walked in full. (2) An
# explicit scan of .git/config: the repo is mounted into the pod *including*
# .git, the mask does not (and cannot — emptying it breaks git) hide it, and it
# commonly carries credentials in remote URLs and http.<url>.extraheader. Such a
# finding cannot be masked, so it gets its own `gitconfig` class for tailored
# remediation. Git history/objects remain out of scope for this gate.
#
# On scanner failure either scan emits an `error` sentinel line; the caller
# (secret_gate_repos) aborts on it. A bare return/exit here would be swallowed
# by the process substitution the caller reads us through.
#
# The scan owns its allowlist inputs so an untrusted workspace cannot suppress
# its own findings: -c (our generated config) overrides a repo-local
# .gitleaks.toml, and --ignore-gitleaks-allow ignores inline allow comments
# (both in _betterleaks_run). -i points at an operator-owned fingerprint
# baseline when the overlay ships one, else a neutral empty dir.
#
# KNOWN LIMITATION: betterleaks always reads a .gitleaksignore/.betterleaksignore
# at the SCAN-TARGET ROOT (here the workspace root and .git/config's dir) and
# 1.6.0 has no flag to disable that, so a workspace committing a root ignore
# file listing its own findings' fingerprints can still suppress them below the
# gate. -i is additive and cannot override it; neutralizing it would mean
# removing/relocating the file or refusing the scan. Tracked as a follow-up.
# Nested (non-root) ignore files are not auto-read, and inline allow comments
# and a repo-local .gitleaks.toml are already neutralized.
scan_repo_secrets() {
  local repo="$1"
  local real_repo
  real_repo="$(realpath "${repo}")"

  local report config
  report="$(mktemp "${TMPDIR:-/tmp}/sandbox-leakscan-XXXXXX")"
  config="$(mktemp "${TMPDIR:-/tmp}/sandbox-leakcfg-XXXXXX")"
  _leakscan_write_config "${repo}" "${config}"

  # betterleaks -i: an operator-owned baseline of accepted fingerprints when the
  # overlay ships one, else a neutral empty dir so the -i default (".", the
  # process CWD) is never used. See _leakscan_ignore_path.
  local ignore_path empty_ignore_dir=""
  ignore_path="$(_leakscan_ignore_path)"
  if [[ -z "${ignore_path}" ]]; then
    empty_ignore_dir="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-leakignore-XXXXXX")"
    ignore_path="${empty_ignore_dir}"
  fi

  local file ruleid line startcol endcol match relpath

  # (1) Whole-workspace scan.
  if ! _betterleaks_run "${real_repo}" "${report}" "${config}" "${ignore_path}"; then
    printf 'error\tbetterleaks scan failed (exit %s)\n' "${LEAKSCAN_RC}"
    rm -f "${report}" "${config}"
    [[ -n "${empty_ignore_dir}" ]] && rmdir "${empty_ignore_dir}" 2>/dev/null || true
    return 0
  fi
  while IFS=$'\t' read -r file ruleid line startcol endcol match; do
    [[ -z "${file}" ]] && continue
    relpath="${file#${real_repo}/}"
    [[ "${relpath}" == .git/* ]] && continue
    if finding_is_encrypted "${file}" "${line}" "${startcol}" "${endcol}"; then
      printf 'sealed\t%s\t%s\t%s\t%s\n' "${relpath}" "${ruleid}" "${line}" "${match}"
    elif is_path_masked "${repo}" "${relpath}"; then
      printf 'yes\t%s\t%s\t%s\t%s\n' "${relpath}" "${ruleid}" "${line}" "${match}"
    else
      printf 'no\t%s\t%s\t%s\t%s\n' "${relpath}" "${ruleid}" "${line}" "${match}"
    fi
  done < <(jq -r '.[] | [.File, .RuleID, (.StartLine|tostring), (.StartColumn|tostring), (.EndColumn|tostring), .Match] | @tsv' \
             "${report}" 2>/dev/null)

  # (2) .git/config — readable in the pod, unmaskable, common credential home.
  local gitcfg="${real_repo}/.git/config"
  if [[ -f "${gitcfg}" ]]; then
    : > "${report}"
    if ! _betterleaks_run "${gitcfg}" "${report}" "${config}" "${ignore_path}"; then
      printf 'error\tbetterleaks scan of .git/config failed (exit %s)\n' "${LEAKSCAN_RC}"
      rm -f "${report}" "${config}"
      [[ -n "${empty_ignore_dir}" ]] && rmdir "${empty_ignore_dir}" 2>/dev/null || true
      return 0
    fi
    while IFS=$'\t' read -r file ruleid line match; do
      [[ -z "${file}" ]] && continue
      printf 'gitconfig\t.git/config\t%s\t%s\t%s\n' "${ruleid}" "${line}" "${match}"
    done < <(jq -r '.[] | [.File, .RuleID, (.StartLine|tostring), .Match] | @tsv' \
               "${report}" 2>/dev/null)
  fi

  rm -f "${report}" "${config}"
  [[ -n "${empty_ignore_dir}" ]] && rmdir "${empty_ignore_dir}" 2>/dev/null || true
}

# _print_unmasked_findings <entry>... — render "repo<TAB>relpath<TAB>rule<TAB>
# line<TAB>match" entries to stderr as a human-readable list.
_print_unmasked_findings() {
  local entry repo relpath ruleid ln match
  for entry in "$@"; do
    IFS=$'\t' read -r repo relpath ruleid ln match <<<"${entry}"
    echo "    ${relpath}  [${ruleid}, line ${ln}]" >&2
    [[ -n "${match}" ]] && echo "        match: ${match}" >&2
  done
}

# _print_mask_add_commands <entry>... — emit one ready-to-run
# `sandbox mask add` command per repo, listing that repo's unmasked paths.
_print_mask_add_commands() {
  local entry repo relpath rr rp r found e
  local -a seen_repos=()
  for entry in "$@"; do
    IFS=$'\t' read -r repo relpath _ _ _ <<<"${entry}"
    found=false
    for r in ${seen_repos[@]+"${seen_repos[@]}"}; do
      [[ "${r}" == "${repo}" ]] && { found=true; break; }
    done
    [[ "${found}" == true ]] && continue
    seen_repos+=("${repo}")

    local cmd="        sandbox mask add --repo ${repo}"
    for e in "$@"; do
      IFS=$'\t' read -r rr rp _ _ _ <<<"${e}"
      [[ "${rr}" == "${repo}" ]] && cmd+=" $(printf '%q' "${rp}")"
    done
    echo "${cmd}" >&2
  done
}

# secret_gate_repos <accept_flag> <repo>... — scan every workspace with
# betterleaks and refuse the launch if any secret lives in a file the mask
# would not hide. Fail closed: a missing betterleaks aborts. With
# accept_flag == "true" (the --i-accept-unmasked-secrets override) the
# findings are printed but the launch proceeds.
secret_gate_repos() {
  local accept="$1"; shift
  local -a repos=("$@")
  [[ "${#repos[@]}" -gt 0 ]] || return 0

  if ! command -v betterleaks &>/dev/null; then
    echo "" >&2
    echo "ERROR: betterleaks is required to scan workspaces for secrets, but it" >&2
    echo "       was not found on PATH. Tier 2/3 launches are gated on it so a" >&2
    echo "       workspace secret the mask would not hide cannot silently reach" >&2
    echo "       the agent. Install betterleaks and re-run." >&2
    echo "" >&2
    exit 1
  fi

  echo "  Scanning workspace(s) for secrets with betterleaks..."

  local -a unmasked=()
  local -a gitconfig=()
  local total_masked=0
  local total_encrypted=0
  local repo m relpath ruleid ln match
  for repo in "${repos[@]}"; do
    while IFS=$'\t' read -r m relpath ruleid ln match; do
      [[ -z "${relpath}" ]] && continue
      # An `error` sentinel means betterleaks could not be trusted to have
      # scanned this workspace. Fail closed: refuse the launch rather than
      # risk passing a repo whose secrets were never inspected. The override
      # does not apply here — it accepts *known* secrets, not an unknown scan.
      if [[ "${m}" == "error" ]]; then
        echo "" >&2
        echo "ERROR: betterleaks failed to scan ${repo} (${relpath})." >&2
        echo "       The workspace could not be verified free of unmasked" >&2
        echo "       secrets, so the launch is refused. Re-run, or check the" >&2
        echo "       betterleaks installation and any repo-local config." >&2
        echo "" >&2
        exit 1
      fi
      case "${m}" in
        yes) (( total_masked++ )) || true ;;
        sealed) (( total_encrypted++ )) || true ;;
        gitconfig) gitconfig+=("${repo}"$'\t'"${relpath}"$'\t'"${ruleid}"$'\t'"${ln}"$'\t'"${match}") ;;
        *) unmasked+=("${repo}"$'\t'"${relpath}"$'\t'"${ruleid}"$'\t'"${ln}"$'\t'"${match}") ;;
      esac
    done < <(scan_repo_secrets "${repo}")
  done

  if [[ "${total_masked}" -gt 0 ]]; then
    echo "  ${total_masked} secret finding(s) reside in masked paths (hidden from the agent)."
  fi
  if [[ "${total_encrypted}" -gt 0 ]]; then
    echo "  ${total_encrypted} secret finding(s) are encrypted at rest (SealedSecret/SOPS); the agent reads only ciphertext."
  fi

  if [[ "${#unmasked[@]}" -eq 0 && "${#gitconfig[@]}" -eq 0 ]]; then
    echo "  betterleaks: no unmasked secrets."
    return 0
  fi

  if [[ "${accept}" == "true" ]]; then
    echo "" >&2
    echo "  NOTICE: $(( ${#unmasked[@]} + ${#gitconfig[@]} )) unmasked secret(s) found. Proceeding anyway" >&2
    echo "  because --i-accept-unmasked-secrets was given — the agent WILL read these:" >&2
    [[ "${#unmasked[@]}" -gt 0 ]] && _print_unmasked_findings "${unmasked[@]}"
    [[ "${#gitconfig[@]}" -gt 0 ]] && _print_unmasked_findings "${gitconfig[@]}"
    echo "" >&2
    return 0
  fi

  echo "" >&2
  echo "ERROR: betterleaks found secret(s) the sandbox mask will NOT hide. The" >&2
  echo "       agent would be able to read them, so the launch is refused:" >&2

  if [[ "${#unmasked[@]}" -gt 0 ]]; then
    echo "" >&2
    _print_unmasked_findings "${unmasked[@]}"
    echo "" >&2
    echo "  Resolve this in one of these ways:" >&2
    echo "    - Remove or relocate the secret(s) above, or" >&2
    echo "    - Mask the file(s) so the agent sees an empty overlay (adds them to" >&2
    echo "      <repo>/.sandbox/config.yaml masked_paths:):" >&2
    echo "" >&2
    _print_mask_add_commands "${unmasked[@]}"
  fi

  if [[ "${#gitconfig[@]}" -gt 0 ]]; then
    echo "" >&2
    echo "  Secret(s) in .git/config (the agent can read .git in the workspace):" >&2
    _print_unmasked_findings "${gitconfig[@]}"
    echo "" >&2
    echo "  .git/config cannot be masked (an empty overlay would break git). Scrub" >&2
    echo "  the credential instead — e.g. set a credential-less remote URL and let" >&2
    echo "  a credential helper supply the secret:" >&2
    echo "        git -C <repo> remote set-url origin <https-url-without-credentials>" >&2
  fi

  echo "" >&2
  echo "    - Or launch anyway, accepting that the agent will see these secrets:" >&2
  echo "        re-run 'sandbox run' with --i-accept-unmasked-secrets" >&2
  echo "" >&2
  exit 1
}

# _path_type — return file / directory / symlink / other for a path.
_path_type() {
  local p="$1"
  if [[ -L "${p}" ]]; then echo "symlink"
  elif [[ -d "${p}" ]]; then echo "directory"
  elif [[ -f "${p}" ]]; then echo "file"
  else echo "other"
  fi
}

# _is_likely_mount_detritus — path looks like a leftover root-owned mountpoint
# from a prior sandbox run: it exists, is root-owned, is empty, and we are not
# root ourselves. Conservative on purpose; the kubelet creating a mount target
# inside a bind-mounted workspace leaves exactly this fingerprint.
_is_likely_mount_detritus() {
  local p="$1"
  [[ -e "${p}" ]] || return 1
  [[ "$(id -u)" -ne 0 ]] || return 1
  # `find -user root` works the same on GNU and BSD find.
  [[ -n "$(find "${p}" -maxdepth 0 -user root -print 2>/dev/null)" ]] || return 1
  if [[ -d "${p}" ]]; then
    [[ -z "$(ls -A "${p}" 2>/dev/null)" ]]
  elif [[ -f "${p}" ]]; then
    [[ ! -s "${p}" ]]
  else
    return 1
  fi
}

# classify_masking_paths — inspect every path the mask would touch and
# populate two globals:
#   MASKING_DETRITUS — paths that look like leftover root-owned mountpoint
#     directories (root-owned, empty). Offered for cleanup with a user prompt.
#   MASKING_MISMATCH — paths that exist with a type the mask cannot safely
#     handle (e.g. a file-overlay onto a directory path, which crashes the
#     gVisor sandbox at container start). Entries are "path|expected|actual"
#     so callers can print a precise error.
#
# Paths matching the detritus pattern go to MASKING_DETRITUS even if they
# would also be mismatches; cleanup removes them and a re-classify makes the
# mismatch vanish.
classify_masking_paths() {
  MASKING_DETRITUS=()
  MASKING_MISMATCH=()
  local repo
  for repo in "$@"; do
    _classify_one_repo_for_masking "${repo}"
  done
}

# _classify_one_repo_for_masking — append this repo's detritus and type
# mismatches to the MASKING_DETRITUS / MASKING_MISMATCH globals. Caller is
# expected to have reset both before iterating.
_classify_one_repo_for_masking() {
  local repo="$1"

  local p full
  for p in "${MASKED_FILE_PATHS[@]}"; do
    full="${repo}/${p}"
    [[ -e "${full}" ]] || continue
    if _is_likely_mount_detritus "${full}"; then
      MASKING_DETRITUS+=("${full}")
      continue
    fi
    if [[ ! -f "${full}" ]]; then
      MASKING_MISMATCH+=("${full}|file|$(_path_type "${full}")")
    fi
  done

  full="${repo}/${MASKED_DIR_PATH}"
  if [[ -e "${full}" ]]; then
    if _is_likely_mount_detritus "${full}"; then
      MASKING_DETRITUS+=("${full}")
    elif [[ ! -d "${full}" ]]; then
      MASKING_MISMATCH+=("${full}|directory|$(_path_type "${full}")")
    fi
  fi

  while IFS= read -r -d '' full; do
    if _is_likely_mount_detritus "${full}"; then
      MASKING_DETRITUS+=("${full}")
      continue
    fi
    if [[ ! -f "${full}" ]]; then
      MASKING_MISMATCH+=("${full}|file|$(_path_type "${full}")")
    fi
  done < <(find "${repo}" -maxdepth 1 -name "${MASKED_OPENRC_PATTERN}" -print0 2>/dev/null)

  # Configured masked_paths are file overlays (FileOrCreate). Validate each
  # that exists is a regular file, mirroring the built-in file checks above,
  # so the type-mismatch guard refuses a launch that would crash gVisor.
  local rel
  while IFS= read -r rel; do
    [[ -z "${rel}" ]] && continue
    full="${repo}/${rel}"
    [[ -e "${full}" ]] || continue
    if _is_likely_mount_detritus "${full}"; then
      MASKING_DETRITUS+=("${full}")
      continue
    fi
    if [[ ! -f "${full}" ]]; then
      MASKING_MISMATCH+=("${full}|file|$(_path_type "${full}")")
    fi
  done < <(load_repo_masked_paths "${repo}")
}

# check_masking_paths — orchestrate masking-path sanity. Detect detritus,
# prompt to clean it up (interactive only), re-classify, and refuse the
# launch if any non-detritus type mismatches remain. Exits non-zero on
# refusal.
check_masking_paths() {
  local -a repos=("$@")
  classify_masking_paths "${repos[@]}"

  if [[ "${#MASKING_DETRITUS[@]}" -gt 0 ]]; then
    echo ""
    echo "  Detected ${#MASKING_DETRITUS[@]} root-owned empty path(s) in the workspace that"
    echo "  look like leftover mountpoint directories from a prior sandbox run:"
    local p
    for p in "${MASKING_DETRITUS[@]}"; do
      echo "    ${p}"
    done
    echo ""
    echo "  These cause silent under-masking and, in some cases, a runtime crash"
    echo "  (gVisor refuses mismatched mount types). Cleaning them up is the fix."
    echo ""

    local answer=""
    if [[ -t 0 ]]; then
      read -r -p "  Delete these with 'sudo rm -rf'? [y/N]: " answer || true
    else
      echo "  (No interactive terminal; cannot prompt — skipping cleanup.)"
    fi

    case "${answer}" in
      [yY]|[yY][eE][sS])
        for p in "${MASKING_DETRITUS[@]}"; do
          sudo rm -rf -- "${p}"
          echo "    deleted ${p}"
        done
        # Reflect the cleanup so the mismatch check below sees the new state.
        classify_masking_paths "${repos[@]}"
        ;;
      *)
        echo "  Leaving the detritus in place. To clean up later:"
        printf "    sudo rm -rf"
        for p in "${MASKING_DETRITUS[@]}"; do
          printf " %q" "${p}"
        done
        printf "\n"
        ;;
    esac
  fi

  if [[ "${#MASKING_MISMATCH[@]}" -gt 0 ]]; then
    echo "" >&2
    echo "ERROR: workspace paths exist with a type the mask cannot safely apply" >&2
    echo "       (would crash gVisor at container start):" >&2
    local entry expected actual
    for entry in "${MASKING_MISMATCH[@]}"; do
      IFS='|' read -r p expected actual <<<"${entry}"
      echo "    ${p}" >&2
      echo "      mask expects ${expected}, found ${actual}" >&2
    done
    echo "" >&2
    echo "  Either remove these paths or convert them to the expected type." >&2
    echo " " >&2
    exit 1
  fi
}

# _load_workspace_audit_prune_dirs — read prune_dirs list from
# config/workspace-audit.yaml. Outputs one directory basename per line.
# Silent (returns empty) if config is missing — falls back to .git/objects only.
_load_workspace_audit_prune_dirs() {
  local config="${SANDBOX_ROOT}/config/workspace-audit.yaml"
  [[ -f "${config}" ]] || return 0

  awk '
    /^prune_dirs:/ { in_list=1; next }
    in_list && /^[^[:space:]#]/ { in_list=0 }
    in_list && /^[[:space:]]*-[[:space:]]/ {
      sub(/^[[:space:]]*-[[:space:]]*/, "")
      sub(/[[:space:]]*#.*$/, "")
      sub(/[[:space:]]+$/, "")
      gsub(/^["'"'"']|["'"'"']$/, "")
      if (length($0) > 0) print
    }
  ' "${config}"
}

# _hash_workspace — emit "sha256  path" lines for every file in workspace,
# excluding .git/objects and any directory listed in workspace-audit.yaml.
# Uses `find -exec <hasher> {} +` (batched) so large repos don't spawn one
# process per file, handles arbitrary filenames without a shell round-trip, and
# — unlike `xargs -0 -r` — needs no GNU-only flag, so it runs on macOS's BSD
# find too. The hasher is sha256sum on GNU or shasum on macOS (see
# sha256_hash_cmd). Sorted output for stable diffs.
_hash_workspace() {
  local workspace="$1"

  local -a sha_cmd=()
  read_into_array sha_cmd < <(sha256_hash_cmd)
  if [[ "${#sha_cmd[@]}" -eq 0 ]]; then
    echo "WARN: no sha256 hasher (sha256sum/shasum) found; cannot capture workspace" >&2
    echo "      state for drift detection." >&2
    return 0
  fi

  local -a prune_dirs=()
  read_into_array prune_dirs < <(_load_workspace_audit_prune_dirs)

  # find expression: prune .git/objects (always) + configured dirs (any depth),
  # then hash the remaining files in batches. Grouping with \( ... \) is
  # required so the -prune applies to the whole alternation. `-exec ... +`
  # skips the command entirely when nothing matches (no empty-input footgun).
  local -a expr=( '(' -path "${workspace}/.git/objects" )
  for dir in "${prune_dirs[@]}"; do
    expr+=( -o -name "${dir}" )
  done
  expr+=( ')' -prune -o -type f -exec "${sha_cmd[@]}" '{}' '+' )

  find "${workspace}" "${expr[@]}" 2>/dev/null \
    | sort
}

# capture_workspace_baseline — sha256sum every file across one or more
# workspaces; concatenates per-repo hashes into a single baseline file.
# Signature: capture_workspace_baseline <log_dir> <repo1> [<repo2> ...]
capture_workspace_baseline() {
  local log_dir="$1"
  shift

  local baseline_file="${log_dir}/baseline.sha256"
  : > "${baseline_file}"

  local r
  for r in "$@"; do
    _hash_workspace "${r}" >> "${baseline_file}" || true
  done

  local file_count
  file_count="$(wc -l < "${baseline_file}" | tr -d ' ')"
  echo "  Baseline: ${file_count} files."
}

# capture_workspace_diff — compare current state to baseline across one or
# more workspaces.
# Signature: capture_workspace_diff <log_dir> <repo1> [<repo2> ...]
capture_workspace_diff() {
  local log_dir="$1"
  shift

  local baseline_file="${log_dir}/baseline.sha256"
  local current_file="${log_dir}/current.sha256"
  local files_log="${log_dir}/files.log"

  if [[ ! -f "${baseline_file}" ]]; then
    echo "  No baseline found; skipping diff."
    return 0
  fi

  : > "${current_file}"
  local r
  for r in "$@"; do
    _hash_workspace "${r}" >> "${current_file}" || true
  done

  {
    echo "=== Workspace diff for session (files modified/added/deleted) ==="
    echo "Baseline: ${baseline_file}"
    echo "Current:  ${current_file}"
    echo "Diff:"
    diff "${baseline_file}" "${current_file}" || true
  } > "${files_log}"

  local changed_count
  changed_count="$(diff "${baseline_file}" "${current_file}" 2>/dev/null | grep -c '^[<>]' || echo 0)"
  echo "  Workspace diff: ${changed_count} line(s) changed."

  rm -f "${current_file}"
}
