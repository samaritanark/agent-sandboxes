#!/usr/bin/env bash
# Bash oracle for the committed-exception readers and the signing-key state. Run on LINUX with
# LC_ALL=C.UTF-8:  LC_ALL=C.UTF-8 oracle.sh > golden-exc.txt
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$here/setup.sh" "$T/fx"; fx="$T/fx"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
us=$'\037'
j() { tr '\n' '|'; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r kind id repo uc acc honor; do
  (
    export HOME="$fx/home" USER_SANDBOX_CONFIG="$fx/$uc.yaml"; unset SANDBOX_OVERLAY
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/platform.sh"; source "$root/lib/vetting.sh"; source "$root/lib/filesystem.sh"
    set +e +u
    rm -f "$fx"/markers/*
    printf '### %s\n' "$id"
    r="$fx/$repo"
    if [[ "$kind" == exc ]]; then
      [[ "$acc" == EMPTY ]] && acc=""; [[ "$honor" == EMPTY ]] && honor=""
      printf 'vaf=%s\n' "$(vetted_accepted_fingerprints "$r" "$acc" 2>/dev/null | j)"
      printf 'granted=%s\n' "$(repo_granted_allowed_domains "$honor" "$r" 2>/dev/null | j)"
      printf 'vrad=%s\n' "$(vetted_repo_allowed_domains "$r" 2>/dev/null | j)"
      printf 'domains=%s\n' "$(vetting_committed_allowed_domains "$r" 2>/dev/null | j)"
      printf 'ci_head=%s\n' "$(vetting_committed_ignore_fingerprints "$r" 2>/dev/null | j)"
      printf 'ci_tag=%s\n' "$(vetting_committed_ignore_fingerprints "$r" agent-vetted/t1 2>/dev/null | j)"
      printf 'ci_prev=%s\n' "$(vetting_committed_ignore_fingerprints "$r" 'HEAD~1' 2>/dev/null | j)"
      printf 'ci_bad=%s\n' "$(vetting_committed_ignore_fingerprints "$r" nonexistent 2>/dev/null | j)"
      printf 'legacy=%s\n' "$(vetting_committed_legacy_accepted_secrets "$r" 2>/dev/null | j)"
      printf 'load=%s\n' "$(load_repo_ignore_fingerprints "$r" 2>/dev/null | j)"
    else
      printf 'state=%s\n' "$(_vetting_ssh_signingkey_state "$r" 2>/dev/null)"
      _vetting_signing_configured "$r" 2>/dev/null; printf 'configured_rc=%s\n' "$?"
    fi
    printf 'markers=%s\n' "$(ls "$fx/markers" | tr '\n' ' ')"
  )
done | sed "s|$fx|<T>|g"
