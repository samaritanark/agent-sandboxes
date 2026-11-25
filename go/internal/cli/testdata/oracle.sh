#!/usr/bin/env bash
# Bash oracle for the in-VM CLI: runs bin/sandbox with each case's arguments. Run on LINUX:
#   LC_ALL=C oracle.sh > golden-cli.tsv
# Each case in cases.tsv is "id version args tree stdin env" (all but id and version are
# "=" + base64): args are NUL-separated words; tree builds $HOME from lines "f path content",
# "d path", "l path target", "g path" (git init), "c path" (commit everything in that repo),
# "r path" (remove), "p path" (a FIFO), "t path days" (set its mtime that many days ago), "L name origin" (clone <HOME>/origin as the linked overlay
# <name> and record the link) (base64 words); "<HOME>" in an argument is the case home; env is NAME=VALUE lines added to a
# clean environment (PATH, HOME, LC_ALL, SANDBOX_LOGS_DIR, GIT_CONFIG_NOSYSTEM, a fixed git committer
# identity and date, and a `date` shim
# answering `date +%s` with FAKE_NOW=1800000000); the line STUB=1 instead puts the gate's stub
# scanner on PATH as betterleaks, answering from <HOME>/scen. Commits ("c") have fixed dates, and
# "v path" signs agent-vetted/<HEAD> there with the key at <HOME>/.testkey/k, so commit and tag
# names are the same on every machine. version is none | full (a .version file in the copied
# install). Output: "id rc stdout stderr home", "=" + base64 each, home a sorted listing of $HOME
# (paths as printf %q prints them; file contents with the case home written as <HOME>; .git
# directories left out, since git versions populate them differently).
# Normalized: the install root as <ROOT>, the case home as <HOME>, the bash version as <RT>, the
# JSON "bash" key as "runtime", and bash's own "<script>: line N:" prefix as "sandbox: line 0:".
# bash's arithmetic error for an octal-invalid number ("value too great for base") is dropped: it
# is interpreter noise, and its effect shows in the output (DecimalNumbers fixes it).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
for v in none full; do
  mkdir -p "$T/$v"; cp -R "$src/bin" "$src/lib" "$src/setup" "$src/config" "$T/$v/"
done
printf 'VERSION=v3.0.0-test\nCOMMIT=0123456789ab\nCOMMIT_DATE=2026-11-24\nBUILD_DATE=2026-11-25\nTREE_STATE=clean\n' > "$T/full/.version"
bv="${BASH_VERSION%%(*}"
umask 022
us=$'\037'
dec() { local _dv; _dv="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${_dv%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id ver eargs etree estdin eenv; do
  c="$T/c/$id"; H="$c/home"; mkdir -p "$H"
  args=()
  while IFS= read -r -d '' a; do args+=("${a//<HOME>/$H}"); done < <(printf '%s' "${eargs#=}" | base64 -d)
  dec tree "$etree"; dec input "$estdin"; dec envs "$eenv"
  while IFS= read -r line; do
    read -ra w <<<"$line"; [[ ${#w[@]} -gt 0 ]] || continue
    dec k "${w[0]}"; dec p "${w[1]}"; t=""; [[ ${#w[@]} -gt 2 ]] && dec t "${w[2]}"
    case "$k" in
      f) mkdir -p "$(dirname "$H/$p")"; printf '%s' "$t" > "$H/$p" ;;
      F) mkdir -p "$(dirname "$H/$p")"; printf '%s' "${t//<HOME>/$H}" > "$H/$p" ;;  # <HOME> filled in
      d) mkdir -p "$H/$p" ;;
      l) mkdir -p "$(dirname "$H/$p")"; ln -s "$t" "$H/$p" ;;
      g) mkdir -p "$H/$p"; GIT_CONFIG_GLOBAL=/dev/null git init -q -b main "$H/$p" ;;
      L) GIT_CONFIG_GLOBAL=/dev/null git clone -q "$H/$t" "$H/.sandbox/overlays/$p"
         mkdir -p "$H/.sandbox"
         printf 'overlay: %s\nlink_url: %s\nlink_ref: main\nlink_commit: %s\n' "$H/.sandbox/overlays/$p" "$H/$t" \
           "$(git -C "$H/.sandbox/overlays/$p" rev-parse HEAD)" >> "$H/.sandbox/config.yaml" ;;
      a) GIT_CONFIG_GLOBAL=/dev/null git -C "$H/$p" add -A ;;  # staged, not committed
      c) GIT_CONFIG_GLOBAL=/dev/null git -C "$H/$p" add -A
         GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x \
           GIT_AUTHOR_DATE="@1700000000 +0000" GIT_COMMITTER_DATE="@1700000000 +0000" git -C "$H/$p" commit -q -m c ;;
      v) chmod 600 "$H/.testkey/k"
         GIT_CONFIG_GLOBAL=/dev/null GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x GIT_COMMITTER_DATE="@1700000100 +0000" \
           git -C "$H/$p" -c gpg.format=ssh -c user.signingkey="$H/.testkey/k" tag -s -m "vetted for agent use" \
           "agent-vetted/$(git -C "$H/$p" rev-parse HEAD)" ;;
      r) rm -rf "$H/$p" ;;
      p) mkdir -p "$(dirname "$H/$p")"; mkfifo "$H/$p" ;;
      t) touch -h -d "@$(( $(date +%s) - t * 86400 ))" "$H/$p" ;;
      T) touch -d "@$t" "$H/$p" ;;  # an absolute mtime (epoch seconds; not for a symlink)
    esac
  done <<<"$tree"
  [[ -f "$H/.testkey/k" ]] && chmod 600 "$H/.testkey/k"
  extra=() path=/usr/bin:/bin
  while IFS= read -r kv; do
    [[ -n "$kv" ]] || continue
    if [[ "$kv" == STUB=1 ]]; then  # the gate's stub scanner as betterleaks, answering from <HOME>/scen
      path="$src/go/internal/gate/testdata/scan/stub:$path"
      extra+=("STUB_SCEN=$H/scen" "STUB_LOG=$c/stub.log" "STUB_ROOT=$H")
      continue
    fi
    extra+=("${kv//<HOME>/$H}")
  done <<<"$envs"
  out="$c/.out" err="$c/.err"
  # `run`, `allow`, and `resume` stop where the cluster work begins (see cmd-stub.sh).
  runner=("$T/$ver/bin/sandbox")
  case "${args[0]:-}" in run|allow|resume) runner=(bash "$here/cmd-stub.sh" "$T/$ver") ;; esac
  cd "$H"
  printf '%s' "$input" | env -i PATH="$src/go/internal/vetting/testdata/config/shim:$path" FAKE_NOW=1800000000 \
    GIT_CONFIG_NOSYSTEM=1 GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x GIT_COMMITTER_DATE="@1700000200 +0000" \
    HOME="$H" LC_ALL=C SANDBOX_LOGS_DIR="$H/logs" "${extra[@]}" \
    "${runner[@]}" "${args[@]}" > "$out" 2> "$err"
  rc=$?
  cd "$T"  # the next case's tree is built from a directory that still exists
  norm() {
    sed -e '/value too great for base/d' \
        -e "s|$T/$ver/bin/sandbox: line [0-9]*:|sandbox: line 0:|g" -e "s|$T/$ver|<ROOT>|g" -e "s|$H|<HOME>|g" \
        -e "s|bash $bv|<RT>|g" -e "s|\"bash\":\"$bv\"|\"runtime\":\"<RT>\"|g" "$1" | base64 -w0
  }
  listing="$(cd "$H" && find . -mindepth 1 -name .git -prune -o -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' p; do
    q="$(printf '%q' "$p")"
    if [[ -L "$p" ]]; then printf 'l %s -> %s\n' "$q" "$(readlink "$p")"
    elif [[ -d "$p" ]]; then printf 'd %s %s\n' "$q" "$(stat -c %a "$p")"
    elif [[ -p "$p" ]]; then printf 'p %s\n' "$q"
    else printf 'f %s %s %s\n' "$q" "$(stat -c %a "$p")" "$(sed "s|$H|<HOME>|g" "$p" | base64 -w0)"; fi
  done | base64 -w0)"
  printf '%s\t%s\t=%s\t=%s\t=%s\n' "$id" "$rc" "$(norm "$out")" "$(norm "$err")" "$listing"
  rm -rf "$c"
done
