#!/usr/bin/env bash
# Fixture tree for the vetting verification differential, under $1:
#   keys/, signers-a (alice), signers-b (bob), scripts/ (markers prove a program ran), markers/,
#   home-a (default trust root = signers-a), home-b (none), uc-*.yaml, ov-*/, and repos r-*.
# All dates are fixed so commit hashes, tag dates, and "behind" counts are reproducible.
set -eu
T="$1"; rm -rf "$T"; mkdir -p "$T"/{keys,scripts,markers,hooks,home-a/.sandbox/vetting,home-b,ov}
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
for k in a b evil; do ssh-keygen -q -t ed25519 -N '' -C '' -f "$T/keys/$k"; done
pub() { cut -d' ' -f1,2 "$T/keys/$1.pub"; }
echo "alice@example.com $(pub a)" > "$T/signers-a"
echo "bob@example.com $(pub b)" > "$T/signers-b"
echo "mallory@example.com $(pub evil)" > "$T/signers-evil"
cp "$T/signers-a" "$T/home-a/.sandbox/vetting/allowed_signers"
# scripts that leave a marker when (wrongly) executed
for s in ssh gpg x509 fsmon clean smudge filter-eq filter-empty filter-inc filter-dot hook; do
  printf '#!/bin/sh\n: > "%s/markers/%s"\ncat\n' "$T" "$s" > "$T/scripts/$s.sh"; chmod +x "$T/scripts/$s.sh"
done
# user and overlay configs
: > "$T/uc-base.yaml"
printf 'vetting_require_clean_worktree: true\n' > "$T/uc-clean.yaml"
printf 'vetting_trust_root: %s/signers-b\n' "$T" > "$T/uc-rootb.yaml"
printf 'vetting_trust_root: %s/missing\n' "$T" > "$T/uc-rootmissing.yaml"
printf 'vetting_trust_format: gpg\n' > "$T/uc-gpg.yaml"
printf 'vetting_trust_format: gpg\nvetting_trust_root: %s/home-b\n' "$T" > "$T/uc-gpg-home.yaml"
mkdir -p "$T/ov/b" "$T/ov/same"
cp "$T/signers-b" "$T/ov/b/signers-b-rel"; printf 'vetting_trust_root: signers-b-rel\n' > "$T/ov/b/config.yaml"
printf 'vetting_trust_root: %s/home-a/.sandbox/vetting/allowed_signers\n' "$T" > "$T/ov/same/config.yaml"

D0=1700000000
n=0
mkcommit() {  # message
  n=$((n + 1)); local d=$((D0 + n * 3600))
  echo "$1 $n" >> file.txt; git add -A; GIT_AUTHOR_DATE="@$d +0000" GIT_COMMITTER_DATE="@$d +0000" git commit -q -m "$1"
}
tagdate=0
signtag() {  # tag key [rev]
  tagdate=$((tagdate + 1)); local d=$((D0 + 100000 + tagdate * 60))
  GIT_COMMITTER_DATE="@$d +0000" git -c gpg.format=ssh -c user.signingkey="$T/keys/$2" tag -s -m "attest $1" "$1" "${3:-HEAD}"
}
newrepo() { mkdir -p "$T/$1"; cd "$T/$1"; git init -q -b main .; git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false; n=0; }
commits() { for i in $(seq 1 "$1"); do mkcommit c; done; }
P=agent-vetted

newrepo r-notag; commits 3
newrepo r-empty
cd "$T"; git clone -q --depth 1 "file://$T/r-notag" r-shallow 2>/dev/null
newrepo r-at-head; commits 3; signtag $P/at-head a
newrepo r-behind1; commits 3; signtag $P/b1 a HEAD~1
newrepo r-behind3; commits 5; signtag $P/b3 a HEAD~3
newrepo r-multi; commits 6; signtag $P/v1 a HEAD~3; signtag $P/v2 a HEAD~1; signtag $P/v3 evil HEAD
newrepo r-ties; commits 2; for t in z a-b a.b aB A a_b Zed; do signtag $P/$t a; done
newrepo r-ties-mixed; commits 2; signtag $P/m1 evil; signtag $P/m2 b; signtag $P/m3 a
newrepo r-divergent; commits 2; git checkout -q -b side; mkcommit side; signtag $P/side a; git checkout -q main; mkcommit main
newrepo r-untrusted; commits 3; signtag $P/u evil
newrepo r-signed-b; commits 3; signtag $P/sb b
newrepo r-unsigned; commits 3; GIT_COMMITTER_DATE="@$((D0+999)) +0000" git tag -a -m unsigned $P/un
newrepo r-lightweight; commits 3; git tag $P/light
newrepo r-wrongprefix; commits 3; signtag other/x a; signtag vetted/x a
newrepo r-oddnames; commits 3; for t in 'a;b' '$x' 'é' '-x' 'a%b' "a'b" 'a"b' 'a&b'; do signtag "$P/$t" a; done
newrepo r-branch-shadow; commits 3; signtag $P/s a; git branch $P/s HEAD~2 2>/dev/null || true
newrepo r-dirty-untracked; commits 3; signtag $P/d a; echo x > untracked.txt
newrepo r-dirty-modified; commits 3; signtag $P/d a; echo more >> file.txt
newrepo r-dirty-staged; commits 3; signtag $P/d a; echo more >> file.txt; git add file.txt
newrepo r-clean; commits 3; signtag $P/d a
cd "$T"; ln -s r-at-head r-link; mkdir not-a-repo

# a hostile workspace: signed by an attacker key that only the workspace's own config trusts, with
# every program hook the config can name pointing at a script that leaves a marker
newrepo r-evil; commits 2
printf '*.txt filter=x\n*.dat filter=a=b\n*.bin filter=y\n*.e filter=\n*.dot filter=dot.ted\n' > .gitattributes
: > f.dat; : > f.bin; : > f.e; : > f.dot; git add -A; GIT_AUTHOR_DATE="@$((D0+900)) +0000" GIT_COMMITTER_DATE="@$((D0+900)) +0000" git commit -q -m attrs
signtag $P/evil evil
# tags whose signature armor names X.509 and OpenPGP: git would run the repo's configured program
head="$(git rev-parse HEAD)"
for kind in x509:"SIGNED MESSAGE" pgp:"PGP SIGNATURE"; do
  nm="${kind%%:*}"; armor="${kind#*:}"
  obj="$(printf 'object %s\ntype commit\ntag %s/%s\ntagger t <t@example.invalid> %s +0000\n\nattest\n-----BEGIN %s-----\nQUFB\n-----END %s-----\n' "$head" "$P" "$nm" $((D0+500)) "$armor" "$armor" | git hash-object -w -t tag --stdin)"
  git update-ref "refs/tags/$P/$nm" "$obj"
done
cat > .git/inc <<INC
[filter "y"]
	clean = $T/scripts/filter-inc.sh
	smudge = $T/scripts/filter-inc.sh
	process = $T/scripts/filter-inc.sh
INC
git config include.path "$T/../x-ignored" 2>/dev/null || true
git config --add include.path "$PWD/.git/inc"
git config gpg.ssh.program "$T/scripts/ssh.sh"
git config gpg.program "$T/scripts/gpg.sh"
git config gpg.x509.program "$T/scripts/x509.sh"
git config gpg.ssh.allowedSignersFile "$T/signers-evil"
git config core.fsmonitor "$T/scripts/fsmon.sh"
git config core.hooksPath "$T/hooks"
git config filter.x.clean "$T/scripts/clean.sh"; git config filter.x.smudge "$T/scripts/smudge.sh"; git config filter.x.required true
git config 'filter.a=b.clean' "$T/scripts/filter-eq.sh"
git config 'filter..clean' "$T/scripts/filter-empty.sh"
git config 'filter.dot.ted.clean' "$T/scripts/filter-dot.sh"
git config user.signingkey "$T/keys/evil"
sleep 1; for f in file.txt f.dat f.bin f.e f.dot; do touch "$f"; done   # force a re-hash through the filters
