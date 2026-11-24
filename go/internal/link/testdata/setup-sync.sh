#!/usr/bin/env bash
# Builds a link sync scenario under $2 (an empty directory): a bare origin, a managed clone at
# $2/home/.sandbox/overlays/team pinned to a ref, and $2/home/.sandbox/config.yaml recording the
# link. Fixed identities and dates make every commit ID the same on every machine.
#   setup-sync.sh <scenario> <dir>
set -eu
s="$1" C="$2"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
export GIT_AUTHOR_DATE="@1700000000 +0000" GIT_COMMITTER_DATE="@1700000000 +0000"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
H="$C/home" O="$C/origin.git" W="$C/work" D="$C/home/.sandbox/overlays/team"
mkdir -p "$H/.sandbox/overlays"
git init -q --bare -b main "$O"
git init -q -b main "$W"
put() { mkdir -p "$(dirname "$W/$1")"; printf '%b' "$2" > "$W/$1"; }
commit() { git -C "$W" add -A; git -C "$W" commit -q -m "$1"; }
put profiles/dev.yaml 'tier: 2\n'
put config.yaml 'vetting: advisory\n'
commit one
git -C "$W" tag v1
git -C "$W" push -q "$O" main v1
git clone -q "$O" "$D"
ref=main
case "$s" in
  same) ;;
  advance)        put profiles/ops.yaml 'tier: 3\nextra_allowed_domains:\n  - ops.example.com\n'; commit two ;;
  advance-tag)    put README.md 'hi\n'; commit two; git -C "$W" tag v2; ref=v2 ;;
  invalid)        put profiles/bad.yaml 'tier: 9\n'; commit bad ;;
  sensitive)      put profiles/home.yaml 'tier: 1\ndefault_repo: /home\n'; commit home ;;
  minver)         put config.yaml 'min_sandbox_version: 99.0\n'; commit minver ;;
  minver-ok)      put config.yaml 'min_sandbox_version: 1.0\n'; commit minver ;;
  minver-bad)     put config.yaml 'min_sandbox_version: 1.x\n'; commit minver ;;
  dirty)          put README.md 'x\n'; commit two; printf 'local\n' >> "$D/profiles/dev.yaml" ;;
  untracked)      put README.md 'x\n'; commit two; printf 'u\n' > "$D/scratch.txt" ;;
  offline)        put README.md 'x\n'; commit two; rm -rf "$O" ;;
  missing-ref)    ref=nosuch ;;
  sha-ref)        ref="$(git -C "$W" rev-parse HEAD)" ;;
  no-check)       put README.md 'x\n'; commit two ;;
  inactive)       ;;
  not-git)        rm -rf "$D/.git" ;;
  tilde)          put README.md 'x\n'; commit two ;;
esac
git -C "$W" push -q -f "$O" main --tags 2>/dev/null || true
overlay="$D"; [[ "$s" == tilde ]] && overlay="~/.sandbox/overlays/team"
if [[ "$s" != inactive ]]; then
  printf 'overlay: %s\nlink_url: %s\nlink_ref: %s\nlink_commit: %s\n' "$overlay" "$O" "$ref" "$(git -C "$D" rev-parse HEAD 2>/dev/null || echo none)" > "$H/.sandbox/config.yaml"
else
  printf 'overlay: %s\n' "$overlay" > "$H/.sandbox/config.yaml"
fi
