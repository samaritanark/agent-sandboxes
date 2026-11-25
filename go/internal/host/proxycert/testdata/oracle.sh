#!/usr/bin/env bash
# Oracle for the subject format: each certificate of subjects.pem through OpenSSL 3, as v2's
# lib/certs.sh read it (`openssl x509 -noout -subject | sed 's/^subject= *//'`, and the same for
# the issuer). Run on LINUX with OpenSSL 3 and LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-subjects.txt
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
awk -v dir="$T" '/-----BEGIN CERTIFICATE-----/ { idx++; f = sprintf("%s/c%05d.pem", dir, idx) } idx { print > f }' "$here/subjects.pem"
for f in "$T"/c*.pem; do
  s="$(openssl x509 -noout -subject -in "$f" 2>/dev/null | sed 's/^subject= *//')"
  i="$(openssl x509 -noout -issuer -in "$f" 2>/dev/null | sed 's/^issuer= *//')"
  printf '%s\t%s\n' "$s" "$i"
done
