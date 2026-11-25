#!/usr/bin/env bash
# Bash oracle for the Linux trust-store search of setup-proxy-cert (lib/certs.sh). Run on LINUX
# with OpenSSL 3 and LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-stores.tsv
# One line per case in cases.tsv (see internal/genstores): "id rc pem describe", the last two as
# "=" + base64: extract_proxy_cert_linux with the vendor list (and the case's --vendor), its
# output file, and describe_pems of it. The trust-store paths are rewritten to the case's tree.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
us=$'\037'
dec() { local v; v="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${v%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id evendor etree; do
  H="$T/$id"; mkdir -p "$H/U" "$H/E"
  dec vendor "$evendor"; dec tree "$etree"
  while IFS= read -r line; do
    read -ra w <<<"$line"; [[ ${#w[@]} -gt 0 ]] || continue
    dec k "${w[0]}"; dec p "${w[1]}"; t=""; [[ ${#w[@]} -gt 2 && $k == l ]] && dec t "${w[2]}"
    case "$k" in
      f) mkdir -p "$(dirname "$H/$p")"; printf '%s' "${w[2]#=}" | base64 -d > "$H/$p" ;;
      d) mkdir -p "$H/$p" ;;
      l) mkdir -p "$(dirname "$H/$p")"; ln -s "$t" "$H/$p" ;;
    esac
  done <<<"$tree"
  sed -e "s|/usr/local/share/ca-certificates|$H/U|g" -e "s|/etc/ssl/certs/ca-certificates.crt|$H/B|g" \
      -e "s|/etc/ssl/certs|$H/E|g" "$src/lib/certs.sh" > "$H.sh"
  (
    set +eu
    source "$H.sh"
    set +e
    extract_proxy_cert_linux "$(proxy_ca_vendor_regex "$vendor")" "$H.out" >/dev/null 2>&1
    rc=$?
    [[ -f "$H.out" ]] || : > "$H.out"
    describe_pems "$H.out" > "$H.desc" 2>/dev/null
    printf '%s\t%s\t=%s\t=%s\n' "$id" "$rc" "$(base64 -w0 < "$H.out")" "$(base64 -w0 < "$H.desc")"
  )
  rm -rf "$H" "$H.sh" "$H.out" "$H.desc"
done
