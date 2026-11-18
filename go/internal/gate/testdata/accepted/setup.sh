#!/usr/bin/env bash
# Builds the fixture for the _leakscan_finding_accepted differential under $1:
#   $1/repo   a git repo (tracked, untracked and ignored files)
#   $1/acc/*  ignore-file variants listing fingerprints for every path in relpaths.txt
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
d="$1"; rm -rf "$d"; mkdir -p "$d/repo" "$d/acc"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
cd "$d/repo"
git init -q -b main .
git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false
mkdir -p dir sub/deep
: > a.txt; : > dir/b.txt; : > "sp ace.txt"; : > "glob[1].txt"; : > "star*.txt"; : > "é.txt"; : > sub/deep/c.txt; : > .env
printf 'ign.txt\n' > .gitignore
git add -A -f && git commit -q -m init
: > u.txt; : > dir/u.txt; : > ign.txt
fp() { while IFS= read -r p; do printf '%s:%s:%s' "$p" "$1" "$2"; printf '%s\n' "$3"; done < "$here/relpaths.txt"; }
fp generic-api-key 3 ''                > "$d/acc/exact"
fp generic-api-key 3 $'\r'             > "$d/acc/crlf"
fp generic-api-key 3 ' '               > "$d/acc/trailing-space"
fp generic-api-key 3 'x'               > "$d/acc/suffixed"
{ fp generic-api-key 3 ''; fp other-rule 4 ''; } | sed 's/^/ /' > "$d/acc/leading-space"
{ fp generic-api-key 4 ''; fp other-rule 3 ''; } > "$d/acc/other-lines"
fp generic-api-key 3 '' | head -c -1  > "$d/acc/no-final-newline"
{ printf '# comment\n\n'; fp generic-api-key 3 ''; } > "$d/acc/with-comments"
: > "$d/acc/empty"
printf '\n' > "$d/acc/just-newline"
mkdir "$d/acc/is-a-directory"
ln -s exact "$d/acc/symlink-ok"; ln -s nowhere "$d/acc/symlink-dangling"
