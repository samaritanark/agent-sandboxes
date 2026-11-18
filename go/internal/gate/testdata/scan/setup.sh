#!/usr/bin/env bash
# Builds the fixture tree for the scan_repo_secrets differential under $1:
#   repos r-*, overlays ov-*, user configs uc-*, accept files acc-*, cache, home, tmp, log.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
fx="$here/../encrypted/fixtures"
T="$1"; rm -rf "$T"; mkdir -p "$T"/{ov,uc,acc,cache,home,tmp,log}
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

mkrepo() {
  local r="$T/$1"; mkdir -p "$r"; ( cd "$r"
    git init -q -b main .; git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false
    printf 'node_modules/\n.venv/\npackages/*/.venv/\n*.egg-info/\nbuild/\nignored-dir/\nign.txt\n' > .gitignore
    mkdir -p src vendor privdir .kube
    : > a.txt; : > .env; : > secret.txt; : > x-openrc.sh; : > src/x.py; : > vendor/v.js; : > privdir/x; : > .kube/config
    cp "$fx/sealed.yaml" "$fx/sops.yaml" .
    git add -A -f; git commit -q -m init
    mkdir -p node_modules/p .venv packages/a/.venv packages/b/.venv pkg.egg-info build ignored-dir lib/.cache "ünï/.venv"
    : > node_modules/p/i.js; : > .venv/x; : > packages/a/.venv/x; : > pkg.egg-info/PKG; : > build/o; : > ignored-dir/z; : > lib/.cache/c; : > "ünï/.venv/x"
    : > u.txt; : > ign.txt; : > .secrets.baseline )
}
for n in r-base r-exclusions-off r-ign-rel r-ign-abs r-ign-dotdot r-ign-mid r-gl-abs r-gl-rel r-both r-nocfg r-masked; do mkrepo $n; done
ln -s r-base "$T/r-link"; ln -s r-masked "$T/r-masked-link"
mkdir -p "$T/r-exclusions-off/.sandbox"; printf 'leakscan_dep_exclusions: "No"  # strict\n' > "$T/r-exclusions-off/.sandbox/config.yaml"
mkdir -p "$T/r-masked/.sandbox"; printf 'masked_paths:\n  - secret.txt\n  - privdir/\n' > "$T/r-masked/.sandbox/config.yaml"
printf '# note\na.txt:rule-a:3\n\n  src/x.py:generic-api-key:10  \n' > "$T/r-ign-rel/.betterleaksignore"
printf 'a.txt:rule-a:3\n/abs/a.txt:rule-a:3\n' > "$T/r-ign-abs/.betterleaksignore"
printf '../a.txt:rule-a:3\n' > "$T/r-ign-dotdot/.betterleaksignore"
printf 'x/../a.txt:rule-a:3\n' > "$T/r-ign-mid/.betterleaksignore"
printf '/etc/passwd:r:1\n' > "$T/r-gl-abs/.gitleaksignore"
printf 'a.txt:rule-a:3\n' > "$T/r-gl-rel/.gitleaksignore"
printf 'a.txt:rule-a:3\n' > "$T/r-both/.betterleaksignore"; printf '../z:r:1\n' > "$T/r-both/.gitleaksignore"
rm -f "$T/r-nocfg/.git/config"

# overlays
mkov() { mkdir -p "$T/ov/$1"; }
mkov plain;     : > "$T/ov/plain/config.yaml"
mkov noconfig
mkov extra;     printf 'leakscan_extra_dep_dirs:\n  - build\n  - "*.cache"\n  - "[pv]kg*"\n  - ignored-dir  # note\nother: 1\n' > "$T/ov/extra/config.yaml"
mkov inlineoff; printf 'leakscan_inline_allow: off\n' > "$T/ov/inlineoff/config.yaml"
mkov inlineon;  printf 'leakscan_inline_allow: "yes"\n' > "$T/ov/inlineon/config.yaml"
mkov inlinefalse; printf "leakscan_inline_allow: 'False'\n" > "$T/ov/inlinefalse/config.yaml"
mkov url;       printf 'leakscan_config_url: https://example.invalid/betterleaks.toml\n' > "$T/ov/url/config.yaml"
mkov url-toml;  printf 'leakscan_config_url: https://example.invalid/betterleaks.toml\n' > "$T/ov/url-toml/config.yaml"; printf '[extend]\nuseDefault = true\n' > "$T/ov/url-toml/betterleaks.toml"
mkov toml;      : > "$T/ov/toml/config.yaml"; printf '[extend]\nuseDefault = true\n' > "$T/ov/toml/betterleaks.toml"
mkov dottoml;   printf '[extend]\nuseDefault = true\n' > "$T/ov/dottoml/.betterleaks.toml"
mkov ign;       printf 'x:y:1\n' > "$T/ov/ign/.betterleaksignore"; printf 'x:y:2\n' > "$T/ov/ign/.gitleaksignore"
mkov ign-fallback; printf 'x:y:2\n' > "$T/ov/ign-fallback/.gitleaksignore"
# a valid cached operator config, pinned from the user config
printf '[extend]\nuseDefault = true\n[allowlist]\npaths = [ "x" ]\n' > "$T/cache/betterleaks.toml"
pin="$(sha256sum "$T/cache/betterleaks.toml" | awk '{print $1}')"
# user configs
printf 'leakscan_config_sha256: %s\nleakscan_config_source: https://example.invalid/betterleaks.toml\n' "$pin" > "$T/uc/pin.yaml"
printf 'leakscan_config_sha256: %s\nleakscan_config_source: https://other.invalid/x.toml\n' "$pin" > "$T/uc/pin-wrong-src.yaml"
printf 'leakscan_config_sha256: deadbeef\nleakscan_config_source: https://example.invalid/betterleaks.toml\n' > "$T/uc/pin-wrong-hash.yaml"
printf 'leakscan_dep_exclusions: off\n' > "$T/uc/excl-off.yaml"
printf 'overlay: %s\n' "$T/ov/extra" > "$T/uc/overlay-extra.yaml"
printf 'overlay: ~/ovhome\n' > "$T/uc/overlay-tilde.yaml"; mkdir -p "$T/home/ovhome"; printf 'leakscan_extra_dep_dirs:\n  - build\n' > "$T/home/ovhome/config.yaml"
# accepted fingerprints
printf 'a.txt:rule-a:3\nsrc/x.py:generic-api-key:10\nu.txt:rule-a:3\nign.txt:rule-a:3\nsecret.txt:rule-a:3\n' > "$T/acc/fp"
: > "$T/acc/empty"
