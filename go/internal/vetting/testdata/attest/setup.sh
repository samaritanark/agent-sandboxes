#!/usr/bin/env bash
# Fixture tree for the attestation differential under $1: keys, scripts, home-*, uc-*.yaml, and
# tpl/<repo> templates that each case copies into run/.
set -eu
T="$1"; rm -rf "$T"; mkdir -p "$T"/{keys,scripts,markers,tpl}
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
for k in a evil; do ssh-keygen -q -t ed25519 -N '' -C 'c' -f "$T/keys/$k"; done
ssh-keygen -q -t rsa -b 2048 -N '' -C 'rsa' -f "$T/keys/rsa"
for h in ed none rsa empty blank; do mkdir -p "$T/home-$h/.sandbox/vetting" "$T/home-$h/.ssh"; echo "alice@example.com $(cut -d' ' -f1,2 "$T/keys/a.pub")" > "$T/home-$h/.sandbox/vetting/allowed_signers"; done
printf "" > "$T/home-empty/.ssh/id_ed25519.pub"; printf "\nssh-ed25519 AAAA c\n" > "$T/home-blank/.ssh/id_ed25519.pub"
cp "$T/keys/a.pub" "$T/home-ed/.ssh/id_ed25519.pub"; cp "$T/keys/rsa.pub" "$T/home-ed/.ssh/id_rsa.pub"; cp "$T/keys/rsa.pub" "$T/home-rsa/.ssh/id_rsa.pub"
for s in ssh gpg x509 fsmon; do printf '#!/bin/sh\n: > "%s/markers/%s"\nexit 1\n' "$T" "$s" > "$T/scripts/$s.sh"; chmod +x "$T/scripts/$s.sh"; done
printf 'vetting_signing_key: %s/keys/a\n' "$T" > "$T/uc-vsk-a.yaml"
printf 'vetting_signing_key: %s/keys/evil\n' "$T" > "$T/uc-vsk-evil.yaml"
printf 'vetting_signing_key: ABCD1234\n' > "$T/uc-vsk-bad.yaml"
printf 'vetting_require_clean_worktree: true\n' > "$T/uc-clean.yaml"
printf 'vetting_trust_format: gpg\n' > "$T/uc-gpg.yaml"
printf 'vetting_signing_key: %s/keys/a\nvetting_require_clean_worktree: true\n' "$T" > "$T/uc-vsk-a-clean.yaml"
: > "$T/uc-base.yaml"
printf 'vetting: required\nother: 1\n' > "$T/uc-existing.yaml"
printf 'vetting_signing_key: old\nvetting: required\n' > "$T/uc-has-vsk-line.yaml"   # a stale key line to be replaced

D0=1700000000; n=0
newrepo() { mkdir -p "$T/tpl/$1"; cd "$T/tpl/$1"; git init -q -b main .; git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false; n=0; }
commit() { n=$((n+1)); local d=$((D0+n*3600)); git add -A; GIT_AUTHOR_DATE="@$d +0000" GIT_COMMITTER_DATE="@$d +0000" git commit -q -m "$1"; }
key() { git config user.signingkey "$1"; }
exc() { printf 'src/a.py:generic-api-key:3\n' > .betterleaksignore; mkdir -p src; echo 'x' > src/a.py; }

newrepo at-clean; echo x > x; commit c1; key "$T/keys/a"
newrepo at-nokey; echo x > x; commit c1
newrepo at-gpgid; echo x > x; commit c1; key ABCD1234EF
newrepo at-evilkey; echo x > x; commit c1; key "$T/keys/evil"
newrepo at-dirty; echo x > x; commit c1; key "$T/keys/a"; echo u > untracked
newrepo at-tagged; echo x > x; commit c1; key "$T/keys/a"; GIT_COMMITTER_DATE="@$((D0+99999)) +0000" git -c gpg.format=ssh -c user.signingkey="$T/keys/a" tag -s -m pre "agent-vetted/$(git rev-parse HEAD)"
newrepo at-exc; exc; commit c1; key "$T/keys/a"
newrepo at-exc-legacy; exc; mkdir -p .sandbox; printf 'accepted_secrets:\n  - old/p:r:1:h\n  - old/q:r:2:h\n' > .sandbox/config.yaml; commit c1; key "$T/keys/a"
newrepo at-evil-config; echo x > x; commit c1; key "$T/keys/a"
git config gpg.ssh.program "$T/scripts/ssh.sh"; git config gpg.program "$T/scripts/gpg.sh"; git config gpg.x509.program "$T/scripts/x509.sh"
git config core.fsmonitor "$T/scripts/fsmon.sh"; git config gpg.ssh.defaultKeyCommand "$T/scripts/ssh.sh"; git config gpg.format openpgp
newrepo at-evil-defaultkey; echo x > x; commit c1
git config gpg.ssh.defaultKeyCommand "$T/scripts/ssh.sh"; git config gpg.ssh.program "$T/scripts/ssh.sh"
cd "$T/tpl"; mkdir not-a-repo
