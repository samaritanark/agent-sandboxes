#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/link.sh — Git-backed team overlays ("sandbox link")
#
# A team overlay (examples/overlay-template/) is a directory that ships
# profiles, an additional blocked-destinations list, a vetted catalogue of
# MCPs/services, and extra CA certs. Until now the operator had to clone that
# directory somewhere by hand and point `overlay:` at it in
# ~/.sandbox/config.yaml. `sandbox link` automates exactly that: it clones a
# (typically private) git repo into a managed location, PINS it to an explicit
# ref, validates its shape, and wires the `overlay:` pointer. Nothing about how
# overlays are *consumed* changes — lib/profile.sh, lib/catalogue.sh, and
# lib/checks.sh keep reading whatever the overlay directory contains.
#
# Trust model (see PRINCIPLES.md — supply-chain compromise is out of scope):
#   * Overlays are additive-only on the safety side; that invariant is enforced
#     at consume-time and cannot be weakened here.
#   * A link is PINNED to a ref (tag/branch/commit) the operator names, and the
#     checked-out commit only ever moves to that ref's tip. `sandbox link sync`
#     is the deliberate, reviewed form (prints a `git diff --stat` of what
#     changes); `sandbox run` performs the same sync automatically before every
#     launch, so a team never drifts across members (one launching from last
#     month's overlay, another from today's). Every advance — deliberate or
#     run-path — re-validates shape and rolls back a failing tree.
#   * The run-path sync is fail-safe: offline, a dirty clone, or an invalid new
#     tree warns and the launch proceeds on the previously validated commit.
#     The one hard stop is an overlay that now requires a newer CLI
#     (`min_sandbox_version:` in its config.yaml) — that blocks the launch
#     until `sandbox upgrade`, because an older CLI would silently ignore
#     whatever the new version gates. Set SANDBOX_NO_LINK_CHECK=1 to skip the
#     run-path sync entirely (air-gapped / CI).
#
# State recorded in ~/.sandbox/config.yaml (flat keys, parsed by lib/config.sh):
#   overlay:      <managed dir>          # the pointer the rest of the CLI reads
#   link_url:     <git remote URL>       # provenance
#   link_ref:     <tag|branch|commit>    # what we track; bumped only by `sync`
#   link_commit:  <resolved sha>         # what is actually checked out (audit)
set -euo pipefail

# Where managed clones live. One subdirectory per link, named for the link.
LINK_OVERLAYS_DIR="${LINK_OVERLAYS_DIR:-${HOME}/.sandbox/overlays}"
# Best-effort timeout (seconds) on the run-path fetch so a slow or unreachable
# remote can never wedge a launch.
LINK_FETCH_TIMEOUT_SECONDS="${LINK_FETCH_TIMEOUT_SECONDS:-10}"

# link_is_valid_name <name> — same ruleset as is_valid_profile_name /
# catalogue_is_valid_name: safe as a directory name, no traversal, no leading
# dot. Kept local so lib/link.sh doesn't depend on profile.sh load order.
link_is_valid_name() {
  local name="$1"
  [[ -n "${name}" ]]                   || return 1
  [[ "${name}" == *"/"* ]]             && return 1
  [[ "${name}" == *".."* ]]            && return 1
  [[ "${name}" == .* ]]                && return 1
  [[ "${name}" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  return 0
}

# link_name_from_url <url> — derive a link name from a git URL's repo basename.
# Strips a trailing "/", a ".git" suffix, and any "user@host:" / scheme prefix.
# Prints nothing if the result isn't a valid name (caller then requires --name).
link_name_from_url() {
  local url="$1" base
  base="${url%/}"          # trailing slash
  base="${base##*/}"       # path basename
  base="${base##*:}"       # scp-style host:path with no slash (git@host:repo)
  base="${base%.git}"      # .git suffix
  if link_is_valid_name "${base}"; then
    echo "${base}"
  fi
}

# link_managed_dir <name> — absolute path of a managed clone.
link_managed_dir() {
  echo "${LINK_OVERLAYS_DIR}/$1"
}

# link_url_config / link_ref_config / link_commit_config — read the recorded
# link fields from the user config. Empty when no link is active.
link_url_config()    { extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_url; }
link_ref_config()    { extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_ref; }
link_commit_config() { extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_commit; }

# link_is_active — true when a managed link is recorded in the user config.
link_is_active() {
  [[ -n "$(link_url_config)" ]]
}

# link_active_dir — the managed overlay directory for the active link, derived
# from the `overlay:` pointer and tilde-expanded. Empty when no link is active
# or the pointer is missing. Guards that the path is a git working tree so we
# never operate on a hand-set (non-managed) overlay path.
link_active_dir() {
  link_is_active || return 0
  local dir
  dir="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay)"
  [[ -n "${dir}" ]] || return 0
  dir="${dir/#\~/${HOME}}"
  [[ -d "${dir}/.git" ]] && echo "${dir}"
}

# _link_require_git — die with a helpful message if git isn't on PATH.
_link_require_git() {
  command -v git >/dev/null 2>&1 \
    || die "'git' is required for 'sandbox link' but was not found on PATH."
}

# _link_fetch_stamp <dir> — path to the last-fetch timestamp (informational —
# records when the run path last reached the remote). Stored under .git/ so it
# never shows up as an untracked file (which would trip the working-tree-dirty
# guard in sync) and is removed with the clone.
_link_fetch_stamp() {
  echo "$1/.git/sandbox-last-fetch"
}

# _link_target_commit <dir> <ref> — resolve <ref> to a commit SHA after a
# fetch, preferring the remote-tracking form (origin/<ref>) so a branch ref
# resolves to the fetched tip, then falling back to a tag/commit. Empty on miss.
_link_target_commit() {
  local dir="$1" ref="$2"
  git -C "${dir}" rev-parse --verify --quiet "origin/${ref}^{commit}" 2>/dev/null \
    || git -C "${dir}" rev-parse --verify --quiet "${ref}^{commit}" 2>/dev/null \
    || true
}

# _link_head_commit <dir> — the currently checked-out commit SHA.
_link_head_commit() {
  git -C "$1" rev-parse --verify --quiet HEAD 2>/dev/null || true
}

# _link_fetch <dir> — fetch remote refs + tags. Best-effort timeout so a slow
# remote can't wedge the caller. Returns git's exit status (0 on success).
_link_fetch() {
  local dir="$1"
  if command -v timeout >/dev/null 2>&1; then
    timeout "${LINK_FETCH_TIMEOUT_SECONDS}" git -C "${dir}" fetch --quiet --tags origin
  else
    git -C "${dir}" fetch --quiet --tags origin
  fi
}

# _link_worktree_dirty <dir> — true if the clone has uncommitted local changes.
# Protects operator hand-edits: sync refuses rather than blowing them away.
_link_worktree_dirty() {
  [[ -n "$(git -C "$1" status --porcelain 2>/dev/null)" ]]
}

# _link_normalize_path <path> — lexically canonicalize a path the way the
# kernel resolves it at mount time, WITHOUT touching the filesystem. The value
# is validated on the operator's machine where it need not exist, and realpath
# is neither reliably present nor consistent across GNU/BSD, so we normalize by
# hand: expand a leading `~` (exactly as the run path does), collapse runs of
# slashes, and drop bare "." components. A trailing slash is likewise dropped
# ("/" itself excepted). We deliberately do NOT resolve ".." — a legitimate
# default_repo never contains one, and _link_default_repo_is_sensitive treats
# any "." component (including "..") as sensitive, so leaving it in place keeps
# it caught rather than silently collapsed. This is what closes the reported
# bypass: `~/.`, `~//`, `/.`, `/home/u/.`, `/home/u//` all normalize to their
# true sensitive target instead of slipping past a literal string compare.
# bash 3.2-safe (no arrays needed; parameter expansion only, no word-splitting
# so a glob char in a component can never be expanded).
_link_normalize_path() {
  local path="${1/#\~/${HOME}}"
  local absolute=0
  case "${path}" in /*) absolute=1 ;; esac

  local rest="${path}" comp out=""
  while [[ -n "${rest}" ]]; do
    comp="${rest%%/*}"                       # first path component
    if [[ "${rest}" == */* ]]; then rest="${rest#*/}"; else rest=""; fi
    case "${comp}" in
      ''|.) ;;                               # empty (// or leading/trailing /) or "." → drop
      *) out="${out}/${comp}" ;;
    esac
  done

  if [[ "${absolute}" -eq 1 ]]; then
    printf '%s\n' "${out:-/}"
  else
    out="${out#/}"; printf '%s\n' "${out:-.}"
  fi
}

# _link_default_repo_is_sensitive <value> — true when a profile's default_repo
# points at a location no legitimate repo lives in and that would hand the
# agent host credentials or kernel/system state. Shape validation alone lets a
# linked overlay ship `default_repo: ~/.ssh`, which the run path tilde-expands
# and mounts into the sandbox when the user passes no --repo (bin/sandbox); at
# tier 1 there is no secret scan to catch it. So we reject the value itself,
# not just the filename. The value is normalized the way the run path expands
# and the kernel resolves it (see _link_normalize_path) so a caller cannot slip
# a sensitive path past this with slash/dot noise (~/. , ~// , /home/u/. , …).
# Rejects: the whole home dir or filesystem root; any hidden path component
# (~/.ssh, ~/.aws, ~/.config, .., …); and sensitive absolute system dirs.
# bash 3.2-safe.
_link_default_repo_is_sensitive() {
  local val
  val="$(_link_normalize_path "$1")"

  # Whole home or filesystem root — mounting either exposes everything.
  [[ "${val}" == "/" || "${val}" == "${HOME}" ]] && return 0

  # A hidden component anywhere in the path (leading, or after any slash).
  # `.?*` requires a dot plus at least one more char, so a bare "." has already
  # been normalized away and a plain slash is unaffected, but ".ssh"/".aws"/
  # ".config"/".." all match — catching both ~/.ssh and a hard-coded
  # /home/<user>/.ssh.
  case "${val}" in
    .?*|*/.?*) return 0 ;;
  esac

  # Sensitive absolute system locations: host credentials / kernel state.
  local d
  for d in /etc /root /proc /sys /boot; do
    [[ "${val}" == "${d}" || "${val}" == "${d}/"* ]] && return 0
  done
  return 1
}

# link_validate_shape <dir> — the safety gate, run on clone AND every sync.
# Pinning defends against silent drift but not against a bad pinned commit, so
# we re-check structure every time the checked-out tree changes. Hard failures
# (return 1): a profile/catalogue filename that isn't a valid name, a profile
# missing/!valid tier, or a default_repo pointing at a sensitive path, or a
# symlink escaping the overlay dir. Unknown top-level entries only warn. Any
# profile-requested extra egress domains are surfaced (non-fatal) so the
# operator reviews them before they widen the sandbox allow-list. Prints a
# one-line content summary to stderr on success.
link_validate_shape() {
  local dir="$1"
  local -a problems=()

  # Reject symlinks whose target is absolute or escapes the overlay via "..".
  # A tracked symlink is the one way a committed tree could point the CLI at a
  # path outside the overlay, so it's a hard failure rather than a warning.
  local f
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    case "$(readlink "${dir}/${f}" 2>/dev/null)" in
      /*|*..*) problems+=("symlink escapes overlay: ${f}") ;;
    esac
  done < <(cd "${dir}" && find . -type l 2>/dev/null | sed 's|^\./||')

  # profiles/*.yaml — valid name + a valid tier + a non-sensitive default_repo.
  # extra_allowed_domains are collected (not rejected) for operator review.
  local p name tier repo dom count_profiles=0
  local -a extra_domains=()
  if [[ -d "${dir}/profiles" ]]; then
    for p in "${dir}/profiles"/*.yaml; do
      [[ -e "${p}" ]] || continue
      count_profiles=$((count_profiles + 1))
      name="$(basename "${p}" .yaml)"
      if ! link_is_valid_name "${name}"; then
        problems+=("invalid profile name: profiles/${name}.yaml")
        continue
      fi
      tier="$(extract_yaml_scalar_from_file "${p}" tier)"
      case "${tier}" in
        1|2|3) ;;
        *) problems+=("profile '${name}' has invalid/missing tier: '${tier:-<none>}'") ;;
      esac

      # default_repo is mounted into the sandbox on a --repo-less run; reject a
      # value that would expose credentials or host/system state.
      repo="$(extract_yaml_scalar_from_file "${p}" default_repo)"
      if [[ -n "${repo}" ]] && _link_default_repo_is_sensitive "${repo}"; then
        problems+=("profile '${name}' default_repo points at a sensitive path: '${repo}'")
      fi

      # Collect extra_allowed_domains for the review notice below. These widen
      # the egress allow-list at consume time and pass unless explicitly
      # blocked (lib/checks.sh), so the operator must see them before use.
      while IFS= read -r dom; do
        [[ -z "${dom}" ]] && continue
        extra_domains+=("${name}: ${dom}")
      done < <(extract_yaml_list_from_file "${p}" extra_allowed_domains)
    done
  fi

  # catalogue/*.yaml — valid name (spec fields are validated at deploy time).
  local c count_catalogue=0
  if [[ -d "${dir}/catalogue" ]]; then
    for c in "${dir}/catalogue"/*.yaml; do
      [[ -e "${c}" ]] || continue
      count_catalogue=$((count_catalogue + 1))
      name="$(basename "${c}" .yaml)"
      link_is_valid_name "${name}" \
        || problems+=("invalid catalogue name: catalogue/${name}.yaml")
    done
  fi

  # config.yaml — an overlay may ship one to ratchet the vetting posture UP
  # (advisory → required). This is NOT ignored: the consume path
  # (lib/vetting.sh resolve_vetting_posture) reads its `vetting:` key at run
  # time. Read it here so the summary can positively confirm what will apply,
  # and warn on an unrecognized value so a typo ("requird") is visible rather
  # than silently downgraded to advisory at consume time.
  local overlay_vetting=""
  if [[ -f "${dir}/config.yaml" ]]; then
    overlay_vetting="$(extract_yaml_scalar_from_file "${dir}/config.yaml" vetting)"
    case "${overlay_vetting}" in
      off|advisory|required|"") ;;
      *) warn "overlay config.yaml sets an unrecognized vetting posture '${overlay_vetting}' — it will be treated as 'advisory' at run time." ;;
    esac
  fi

  # Unknown top-level entries only warn — an overlay may legitimately carry a
  # README, GOVERNANCE.md, etc. We flag the unexpected so a typo'd dir name
  # (e.g. "profile/" instead of "profiles/") doesn't silently do nothing.
  local entry base
  for entry in "${dir}"/*; do
    [[ -e "${entry}" ]] || continue
    base="$(basename "${entry}")"
    case "${base}" in
      profiles|catalogue|extra-ca-certs|blocked-destinations.yaml|config.yaml|\
      README.md|GOVERNANCE.md|README|LICENSE|NOTICE|docs|\
      allowed_signers|signers.txt|gen-allowed-signers.sh|.betterleaksignore|.gitleaksignore) ;;
      *) warn "overlay ships an unrecognized top-level entry: ${base} (ignored by the CLI)" ;;
    esac
  done

  if [[ "${#problems[@]}" -gt 0 ]]; then
    warn "overlay failed validation:"
    local msg
    for msg in "${problems[@]}"; do
      echo "         - ${msg}" >&2
    done
    return 1
  fi

  # Non-fatal: surface every extra egress domain the overlay's profiles grant,
  # so the operator reviews new allow-list entries at link/sync time rather
  # than discovering them silently applied on a later run.
  if [[ "${#extra_domains[@]}" -gt 0 ]]; then
    warn "overlay profiles request ${#extra_domains[@]} extra allowed egress domain(s) — review before use:"
    for dom in "${extra_domains[@]}"; do
      echo "         - ${dom}" >&2
    done
  fi

  # Confirm a shipped trust root the same way the posture is confirmed: it is
  # consumed at run time (lib/vetting.sh vetting_trust_roots), and the signer
  # count makes an empty or unreadable list visible at link time.
  local overlay_troot="" troot_note=""
  if [[ -f "${dir}/config.yaml" ]]; then
    overlay_troot="$(extract_yaml_scalar_from_file "${dir}/config.yaml" vetting_trust_root)"
  fi
  if [[ -n "${overlay_troot}" ]]; then
    local troot_path="${overlay_troot/#\~/${HOME}}"
    [[ "${troot_path}" != /* ]] && troot_path="${dir}/${troot_path}"
    if [[ -f "${troot_path}" ]]; then
      troot_note=", trust root: ${overlay_troot} ($(grep -Ecv '^[[:space:]]*($|#)' "${troot_path}" 2>/dev/null || echo 0) signer(s))"
    else
      troot_note=", trust root: ${overlay_troot} (MISSING)"
      warn "overlay config.yaml names vetting_trust_root: ${overlay_troot}, but no such file ships in the overlay."
    fi
  fi
  # Surface a declared minimum CLI version the same way: it is enforced by the
  # callers (clone/sync/run), so the summary only has to make it visible.
  local overlay_minver="" minver_note=""
  overlay_minver="$(overlay_min_sandbox_version "${dir}")"
  [[ -n "${overlay_minver}" ]] && minver_note=", min CLI: ${overlay_minver}"

  # An overlay-shipped drift cap (lib/vetting.sh vetting_max_commits_behind) is a
  # run-time control too, so confirm it at link/sync time alongside the posture.
  local overlay_cap="" cap_note=""
  if [[ -f "${dir}/config.yaml" ]]; then
    overlay_cap="$(extract_yaml_scalar_from_file "${dir}/config.yaml" vetting_max_commits_behind)"
  fi
  if [[ "${overlay_cap}" =~ ^[0-9]+$ ]]; then
    cap_note=", max commits behind HEAD: ${overlay_cap}"
  elif [[ -n "${overlay_cap}" ]]; then
    warn "overlay config.yaml sets a non-integer vetting_max_commits_behind: '${overlay_cap}' — it will be ignored (no cap) at run time."
  fi
  # An overlay-shipped recency window (lib/vetting.sh vetting_max_age_days) is a
  # run-time control too; confirm it alongside the commit cap.
  local overlay_age="" age_note=""
  if [[ -f "${dir}/config.yaml" ]]; then
    overlay_age="$(extract_yaml_scalar_from_file "${dir}/config.yaml" vetting_max_age_days)"
  fi
  if [[ "${overlay_age}" =~ ^[0-9]+$ ]]; then
    age_note=", max attestation age: ${overlay_age} day(s)"
  elif [[ -n "${overlay_age}" ]]; then
    warn "overlay config.yaml sets a non-integer vetting_max_age_days: '${overlay_age}' — it will be ignored (no expiry) at run time."
  fi
  # An overlay-shipped strict-exceptions knob (lib/vetting.sh
  # vetting_exceptions_require_head) is a run-time security control as well;
  # confirm it at link/sync time so an operator sees the overlay tightening how
  # committed secret exceptions are honored under drift.
  local overlay_reqhead="" reqhead_note=""
  if [[ -f "${dir}/config.yaml" ]]; then
    overlay_reqhead="$(extract_yaml_scalar_from_file "${dir}/config.yaml" vetting_exceptions_require_head)"
  fi
  if [[ "${overlay_reqhead}" == "true" ]]; then
    reqhead_note=", exceptions require attestation at HEAD"
  elif [[ -n "${overlay_reqhead}" && "${overlay_reqhead}" != "false" ]]; then
    warn "overlay config.yaml sets vetting_exceptions_require_head: '${overlay_reqhead}' — only 'true' tightens; any other value leaves the permissive default."
  fi
  # Same for the exception-source knob (vetting_exceptions_from_commit): true
  # tightens the source from the working copy to the attested commit's blob.
  local overlay_fromcommit="" fromcommit_note=""
  if [[ -f "${dir}/config.yaml" ]]; then
    overlay_fromcommit="$(extract_yaml_scalar_from_file "${dir}/config.yaml" vetting_exceptions_from_commit)"
  fi
  if [[ "${overlay_fromcommit}" == "true" ]]; then
    fromcommit_note=", exceptions read from attested commit"
  elif [[ -n "${overlay_fromcommit}" && "${overlay_fromcommit}" != "false" ]]; then
    warn "overlay config.yaml sets vetting_exceptions_from_commit: '${overlay_fromcommit}' — only 'true' tightens; any other value leaves the working-copy default."
  fi
  echo "  overlay contents: ${count_profiles} profile(s), ${count_catalogue} catalogue entr$( [[ ${count_catalogue} -eq 1 ]] && echo y || echo ies )$( [[ -f "${dir}/blocked-destinations.yaml" ]] && echo ", blocked-destinations.yaml" )$( [[ -n "${overlay_vetting}" ]] && echo ", vetting: ${overlay_vetting}" )${troot_note}${minver_note}${cap_note}${age_note}${reqhead_note}${fromcommit_note}" >&2
  return 0
}

# link_write_config <dir> <url> <ref> <commit> — persist the link pointer +
# provenance into ~/.sandbox/config.yaml.
link_write_config() {
  local dir="$1" url="$2" ref="$3" commit="$4"
  upsert_yaml_scalar_in_file "${USER_SANDBOX_CONFIG}" overlay     "${dir}"
  upsert_yaml_scalar_in_file "${USER_SANDBOX_CONFIG}" link_url    "${url}"
  upsert_yaml_scalar_in_file "${USER_SANDBOX_CONFIG}" link_ref    "${ref}"
  upsert_yaml_scalar_in_file "${USER_SANDBOX_CONFIG}" link_commit "${commit}"
}

# link_clear_config — remove the link pointer + provenance. Only clears the
# `overlay:` pointer when it still points at the managed clone (so we never
# strip a hand-set overlay the operator later added).
link_clear_config() {
  local managed_dir="$1"
  local current
  current="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay)"
  current="${current/#\~/${HOME}}"
  if [[ "${current}" == "${managed_dir}" ]]; then
    remove_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay
  fi
  remove_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_url
  remove_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_ref
  remove_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_commit
}

# link_sync_on_run — run-path hook: sync the linked overlay to its pinned
# ref's current tip before a launch, so every team member launches from the
# same overlay commit. This replaces the old notify-only hint — drift between
# team members proved the worse failure mode than an unreviewed fast-forward,
# and the advance is still bounded: it only ever moves to the tip of the ref
# the operator pinned, it re-validates shape, and it rolls back a failing
# tree.
#
# Fail-safe so a launch is never wedged by the network or by overlay content:
#   * fetch failure (offline/slow; bounded by LINK_FETCH_TIMEOUT_SECONDS)
#       -> warn, launch from the current commit
#   * local uncommitted edits in the clone
#       -> warn, launch from the current tree (never clobber operator edits)
#   * new tree fails shape validation
#       -> roll back, warn, launch from the previous commit
# The one deliberate hard stop: a new tree that requires a newer CLI
# (min_sandbox_version) rolls back and DIES — launching anyway would mean
# staying on an overlay the team has moved past, on a tool that would silently
# ignore whatever the new version gates. 'sandbox upgrade' is the fix.
# SANDBOX_NO_LINK_CHECK=1 skips the hook entirely (air-gapped / CI).
link_sync_on_run() {
  [[ -n "${SANDBOX_NO_LINK_CHECK:-}" ]] && return 0
  command -v git >/dev/null 2>&1 || return 0
  link_is_active || return 0

  local dir ref
  dir="$(link_active_dir)" || return 0
  [[ -n "${dir}" ]] || return 0
  ref="$(link_ref_config)"
  [[ -n "${ref}" ]] || return 0

  local head
  head="$(_link_head_commit "${dir}")"
  if ! _link_fetch "${dir}" >/dev/null 2>&1; then
    warn "linked overlay: could not fetch '$(link_url_config)' — launching from the current commit ${head:0:12}."
    return 0
  fi
  : > "$(_link_fetch_stamp "${dir}")" 2>/dev/null || true

  local target
  target="$(_link_target_commit "${dir}" "${ref}")"
  [[ -n "${head}" && -n "${target}" ]] || return 0
  [[ "${head}" == "${target}" ]] && return 0

  if _link_worktree_dirty "${dir}"; then
    warn "linked overlay is behind '${ref}' but has local uncommitted edits at ${dir/#${HOME}/\~}; not auto-syncing. Commit, stash, or discard them, then run 'sandbox link sync'."
    return 0
  fi

  echo "==> Syncing linked overlay to '${ref}' (${head:0:12} -> ${target:0:12})"
  git -C "${dir}" --no-pager diff --stat "${head}" "${target}" 2>/dev/null || true

  git -C "${dir}" checkout --quiet "${ref}" 2>/dev/null || true
  if ! git -C "${dir}" reset --hard --quiet "${target}"; then
    git -C "${dir}" reset --hard --quiet "${head}" 2>/dev/null || true
    warn "could not advance the linked overlay to ${target:0:12}; launching from ${head:0:12}."
    return 0
  fi

  if ! link_validate_shape "${dir}"; then
    git -C "${dir}" reset --hard --quiet "${head}" 2>/dev/null || true
    warn "updated overlay tree ('${ref}' @ ${target:0:12}) failed validation; rolled back — launching from ${head:0:12}. Review with 'sandbox link sync' once the overlay is fixed."
    return 0
  fi

  local min_unmet
  min_unmet="$(overlay_min_version_unmet "${dir}")"
  if [[ -n "${min_unmet}" ]]; then
    git -C "${dir}" reset --hard --quiet "${head}" 2>/dev/null || true
    die "linked overlay '${ref}' now requires agent-sandboxes >= ${min_unmet}, but this is ${SANDBOX_VERSION:-dev}. Run 'sandbox upgrade', then launch again. (Rolled back to ${head:0:12}; SANDBOX_NO_LINK_CHECK=1 skips the run-path sync entirely.)"
  fi

  link_write_config "${dir}" "$(link_url_config)" "${ref}" "${target}"
  echo "    linked overlay updated to '${ref}' (${target:0:12})"
}
