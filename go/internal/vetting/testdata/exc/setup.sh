#!/usr/bin/env bash
# Fixture tree for the exceptions / signing-key differential, under $1.
set -eu
T="$1"; rm -rf "$T"; mkdir -p "$T"/{keys,scripts,markers,home/.sandbox/vetting,home/.ssh}
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
ssh-keygen -q -t ed25519 -N '' -C '' -f "$T/keys/a"
echo "alice@example.com $(cut -d' ' -f1,2 "$T/keys/a.pub")" > "$T/home/.sandbox/vetting/allowed_signers"
cp "$T/keys/a.pub" "$T/home/id.pub"
printf '#!/bin/sh\n: > "%s/markers/clean"\ncat\n' "$T" > "$T/scripts/clean.sh"; chmod +x "$T/scripts/clean.sh"
D0=1700000000; n=0; tagn=0; P=agent-vetted
newrepo() { mkdir -p "$T/$1"; cd "$T/$1"; git init -q -b main .; git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false; n=0; }
commit() { n=$((n+1)); local d=$((D0+n*3600)); git add -A; GIT_AUTHOR_DATE="@$d +0000" GIT_COMMITTER_DATE="@$d +0000" git commit -q -m "$1"; }
signtag() { tagn=$((tagn+1)); GIT_COMMITTER_DATE="@$((D0+100000+tagn*60)) +0000" git -c gpg.format=ssh -c user.signingkey="$T/keys/a" tag -s -m attest "$1" "${2:-HEAD}"; }
ign_a() { printf '# reviewed\nsrc/a.py:generic-api-key:3\n\n  b.txt:rule:9  \n' > .betterleaksignore; }
ign_b() { printf 'src/a.py:generic-api-key:3\nnew/c.py:rule:1\n' > .betterleaksignore; }
cfg_a() { mkdir -p .sandbox; printf 'extra_allowed_domains:\n  - registry.example.com   # internal\n  - "quoted.example.com"\naccepted_secrets:\n  - old/path:rule:1:hash\nmasked_paths:\n  - x\n' > .sandbox/config.yaml; }
cfg_b() { mkdir -p .sandbox; printf 'extra_allowed_domains:\n  - other.example.com\n' > .sandbox/config.yaml; }

newrepo ra-vetted; ign_a; cfg_a; echo r > README; commit c1; echo r2 >> README; commit c2; signtag $P/t1
printf 'wc/only:rule:1\n' >> .betterleaksignore; printf '  - evil.example.com\n' >> .sandbox/config.yaml
newrepo ra-drift; ign_a; cfg_a; commit c1; signtag $P/t1; ign_b; cfg_b; commit c2
newrepo ra-drift3; ign_a; cfg_a; commit c1; signtag $P/t1; ign_b; commit c2; echo x > x; commit c3; echo y > y; commit c4
newrepo ra-drift-dirty; ign_a; cfg_a; commit c1; signtag $P/t1; ign_b; cfg_b; commit c2; printf 'dirty:r:1\n' >> .betterleaksignore
newrepo ra-unvetted; ign_a; cfg_a; commit c1
newrepo ra-gitleaks; printf 'g/a:rule:1\n' > .gitleaksignore; cfg_a; commit c1; signtag $P/t1
newrepo ra-both; ign_a; printf 'g/b:rule:2\n' > .gitleaksignore; cfg_b; commit c1; signtag $P/t1
newrepo ra-ign-dir; mkdir .betterleaksignore; printf 'inner:rule:1\n' > .betterleaksignore/f; commit c1; signtag $P/t1
newrepo ra-none; echo x > x; commit c1; signtag $P/t1
newrepo ra-uncommitted-ign; echo x > x; commit c1; signtag $P/t1; ign_a
newrepo ra-ignored-ign; printf '.betterleaksignore\n' > .gitignore; echo x > x; commit c1; signtag $P/t1; ign_a
newrepo ra-empty-ign; : > .betterleaksignore; printf '# only a comment\n' > .gitleaksignore; commit c1; signtag $P/t1
newrepo ra-crlf-ign; printf 'a:r:1\r\n# c\r\n\r\nb:r:2\r\n' > .betterleaksignore; commit c1; signtag $P/t1
newrepo ra-evil; ign_a; cfg_a; printf '.betterleaksignore filter=x\n.sandbox/config.yaml filter=x\n' > .gitattributes; commit c1; signtag $P/t1
git config filter.x.clean "$T/scripts/clean.sh"; git config filter.x.smudge "$T/scripts/clean.sh"; git config filter.x.required true; sleep 1; touch .betterleaksignore .sandbox/config.yaml
cd "$T"; mkdir ra-notgit; newrepo ra-nocommit
cd "$T"; ln -s ra-vetted ra-link

# signing-key states: one repo per user.signingkey value
mk_sk() { newrepo "$1"; echo x > x; commit c1; if [[ $# -ge 2 ]]; then git config user.signingkey "$2"; fi; }
mk_sk sk-unset
mk_sk sk-empty ""
mk_sk sk-ssh "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
mk_sk sk-sk "sk-ssh-ed25519@openssh.com AAAA"
mk_sk sk-ecdsa "ecdsa-sha2-nistp256 AAAA"
mk_sk sk-keycolon "key::ssh-ed25519 AAAA"
mk_sk sk-file "$T/home/id.pub"
mk_sk sk-missing "$T/home/nope.pub"
mk_sk sk-tilde-ok "~/id.pub"
mk_sk sk-tilde-missing "~/nope.pub"
mk_sk sk-gpg "ABCD1234EF567890"
mk_sk sk-dir "$T/home"
mk_sk sk-prefix-lookalike "ssh"
mk_sk sk-space " ssh-ed25519 AAAA"

cd "$T"
# user configs
printf 'vetting_exceptions_from_commit: true\n' > "$T/uc-fc.yaml"
printf 'vetting_exceptions_require_head: true\n' > "$T/uc-rh.yaml"
printf 'vetting_exceptions_from_commit: true\nvetting_exceptions_require_head: true\n' > "$T/uc-both.yaml"
: > "$T/uc-none.yaml"
for fmt in ssh gpg; do
  for v in none ok literal bad missing tilde; do
    f="$T/uc-vsk-$v-$fmt.yaml"; : > "$f"
    case "$v" in
      ok) echo "vetting_signing_key: $T/home/id.pub" >> "$f" ;;
      literal) echo "vetting_signing_key: ssh-ed25519 AAAAC3" >> "$f" ;;
      bad) echo "vetting_signing_key: ABCD1234" >> "$f" ;;
      missing) echo "vetting_signing_key: $T/home/nope.pub" >> "$f" ;;
      tilde) echo "vetting_signing_key: ~/id.pub" >> "$f" ;;
    esac
    [[ "$fmt" == gpg ]] && echo "vetting_trust_format: gpg" >> "$f"
  done
done
