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

# _betterleaks_run <target> <report> — run one trustworthy betterleaks scan of
# <target> into <report>. Returns 0 if the run can be trusted (a clean run, or
# leaks-found with a valid JSON-array report); returns 1 if it failed and the
# caller must fail closed. The exit code is left in LEAKSCAN_RC for the error
# message.
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
_betterleaks_run() {
  local target="$1" report="$2"
  LEAKSCAN_RC=0
  betterleaks dir "${target}" --no-banner -f json -r "${report}" \
    --validation=false --redact >/dev/null 2>&1 || LEAKSCAN_RC=$?
  [[ "${LEAKSCAN_RC}" == 0 ]] && return 0
  [[ "${LEAKSCAN_RC}" == 1 ]] && jq -e 'type == "array"' "${report}" >/dev/null 2>&1 && return 0
  return 1
}

# scan_repo_secrets <repo> — scan a workspace with betterleaks and emit one TSV
# line per finding: "<class>\t<relpath>\t<RuleID>\t<line>\t<match>", where class
# is one of: yes (secret in a masked path, hidden from the agent), no (secret in
# an unmasked path), gitconfig (secret in .git/config), or error (scan failed).
# Secret values are redacted (--redact).
#
# Two scans run. (1) A whole-workspace directory scan — betterleaks excludes
# .git/ from directory walks, so this never sees anything under .git. (2) An
# explicit scan of .git/config: the repo is mounted into the pod *including*
# .git, the mask does not (and cannot — emptying it breaks git) hide it, and it
# commonly carries credentials in remote URLs and http.<url>.extraheader. Such a
# finding cannot be masked, so it gets its own `gitconfig` class for tailored
# remediation. Git history/objects remain out of scope for this gate.
#
# On scanner failure either scan emits an `error` sentinel line; the caller
# (secret_gate_repos) aborts on it. A bare return/exit here would be swallowed
# by the process substitution the caller reads us through.
scan_repo_secrets() {
  local repo="$1"
  local real_repo
  real_repo="$(realpath "${repo}")"

  local report
  report="$(mktemp "${TMPDIR:-/tmp}/sandbox-leakscan-XXXXXX")"

  local file ruleid line match relpath

  # (1) Whole-workspace scan.
  if ! _betterleaks_run "${real_repo}" "${report}"; then
    printf 'error\tbetterleaks scan failed (exit %s)\n' "${LEAKSCAN_RC}"
    rm -f "${report}"
    return 0
  fi
  while IFS=$'\t' read -r file ruleid line match; do
    [[ -z "${file}" ]] && continue
    relpath="${file#${real_repo}/}"
    [[ "${relpath}" == .git/* ]] && continue
    if is_path_masked "${repo}" "${relpath}"; then
      printf 'yes\t%s\t%s\t%s\t%s\n' "${relpath}" "${ruleid}" "${line}" "${match}"
    else
      printf 'no\t%s\t%s\t%s\t%s\n' "${relpath}" "${ruleid}" "${line}" "${match}"
    fi
  done < <(jq -r '.[] | [.File, .RuleID, (.StartLine|tostring), .Match] | @tsv' \
             "${report}" 2>/dev/null)

  # (2) .git/config — readable in the pod, unmaskable, common credential home.
  local gitcfg="${real_repo}/.git/config"
  if [[ -f "${gitcfg}" ]]; then
    : > "${report}"
    if ! _betterleaks_run "${gitcfg}" "${report}"; then
      printf 'error\tbetterleaks scan of .git/config failed (exit %s)\n' "${LEAKSCAN_RC}"
      rm -f "${report}"
      return 0
    fi
    while IFS=$'\t' read -r file ruleid line match; do
      [[ -z "${file}" ]] && continue
      printf 'gitconfig\t.git/config\t%s\t%s\t%s\n' "${ruleid}" "${line}" "${match}"
    done < <(jq -r '.[] | [.File, .RuleID, (.StartLine|tostring), .Match] | @tsv' \
               "${report}" 2>/dev/null)
  fi

  rm -f "${report}"
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
        gitconfig) gitconfig+=("${repo}"$'\t'"${relpath}"$'\t'"${ruleid}"$'\t'"${ln}"$'\t'"${match}") ;;
        *) unmasked+=("${repo}"$'\t'"${relpath}"$'\t'"${ruleid}"$'\t'"${ln}"$'\t'"${match}") ;;
      esac
    done < <(scan_repo_secrets "${repo}")
  done

  if [[ "${total_masked}" -gt 0 ]]; then
    echo "  ${total_masked} secret finding(s) reside in masked paths (hidden from the agent)."
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
# Uses find -print0 | xargs -0 sha256sum (batched) so large repos don't
# spawn one process per file. Sorted output for stable diffs.
_hash_workspace() {
  local workspace="$1"

  local -a prune_dirs=()
  read_into_array prune_dirs < <(_load_workspace_audit_prune_dirs)

  # find expression: prune .git/objects (always) + configured dirs (any depth),
  # then -type f -print0 the rest. Grouping with \( ... \) is required so the
  # -prune applies to the whole alternation.
  local -a expr=( '(' -path "${workspace}/.git/objects" )
  for dir in "${prune_dirs[@]}"; do
    expr+=( -o -name "${dir}" )
  done
  expr+=( ')' -prune -o -type f -print0 )

  find "${workspace}" "${expr[@]}" 2>/dev/null \
    | xargs -0 -r sha256sum 2>/dev/null \
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
