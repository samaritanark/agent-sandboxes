#!/usr/bin/env bash
# Fixture tree for the vetting config differential: $1/{home-a,home-b,uc,ov,abs_signers,...}.
# home-a has the default trust root; home-b does not. "@T@" in configs becomes the fixture root.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
T="$1"; rm -rf "$T"; mkdir -p "$T/home-a/.sandbox/vetting" "$T/home-b" "$T/uc" "$T/ov"
: > "$T/home-a/.sandbox/vetting/allowed_signers"
: > "$T/abs_signers"; : > "$T/home-a/home_signers"; : > "$T/home-b/home_signers"
mkdir -p "$T/ov/signers.d"; : > "$T/ov/signers"
for f in "$here"/user/*.yaml; do sed "s|@T@|$T|g" "$f" > "$T/uc/$(basename "$f")"; done
for f in "$here"/overlay/*.yaml; do
  n="$(basename "$f" .yaml)"; mkdir -p "$T/ov/$n"; sed "s|@T@|$T|g" "$f" > "$T/ov/$n/config.yaml"; : > "$T/ov/$n/rel_signers"
done
mkdir -p "$T/ov/noconfig"; : > "$T/ov/noconfig/rel_signers"
