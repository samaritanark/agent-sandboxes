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

  # Run gitleaks if available
  if command -v gitleaks &>/dev/null; then
    echo "  Running gitleaks scan..."
    if ! gitleaks detect \
         --source "${workspace}" \
         --no-git \
         --quiet \
         --exit-code 0 \
         2>/dev/null; then
      echo "  WARN: gitleaks detected potential secrets in workspace."
      (( issues_found++ )) || true
    else
      echo "  gitleaks: no secrets detected."
    fi
  else
    echo "  WARN: gitleaks not found; skipping secret scan."
  fi

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
  mapfile -t prune_dirs < <(_load_workspace_audit_prune_dirs)

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
