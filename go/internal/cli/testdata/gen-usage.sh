#!/usr/bin/env bash
# Captures every usage text of bin/sandbox into go/internal/cli/usage/<function>.txt (the
# secret command's into go/internal/secretcmd, which the host binary shares), with
# @VERSION@ and @LOGS_DIR@ in place of the values the bash expands. Run on Linux from anywhere:
#   go/internal/cli/testdata/gen-usage.sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
out="$here/../usage"
(
  source "$root/bin/sandbox"
  set +e +u
  SANDBOX_VERSION=@VERSION@
  SANDBOX_LOGS_DIR=@LOGS_DIR@
  for f in usage usage_run usage_rebuild usage_upgrade usage_onboard usage_allow usage_mask \
           usage_exceptions usage_vet usage_link usage_profile; do
    ( "$f" ) > "$out/$f.txt"
  done
  ( usage_secret ) > "$here/../../secretcmd/usage_secret.txt"
)
