#!/usr/bin/env bash
# cases.tsv: kind <TAB> id <TAB> repo <TAB> user-config <TAB> accept_unvetted <TAB> honor
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
{
i=0
for r in ra-vetted ra-drift ra-drift3 ra-drift-dirty ra-unvetted ra-gitleaks ra-both ra-ign-dir ra-none ra-uncommitted-ign ra-ignored-ign ra-empty-ign ra-crlf-ign ra-evil ra-link ra-notgit ra-nocommit missing-dir; do
  for uc in uc-none uc-fc uc-rh uc-both; do for acc in false true EMPTY; do for honor in true false yes EMPTY; do
    printf 'exc\te%04d\t%s\t%s\t%s\t%s\n' $i $r $uc $acc $honor; i=$((i+1))
  done; done; done
done
i=0
for r in sk-unset sk-empty sk-ssh sk-sk sk-ecdsa sk-keycolon sk-file sk-missing sk-tilde-ok sk-tilde-missing sk-gpg sk-dir sk-prefix-lookalike sk-space ra-notgit missing-dir; do
  for v in none ok literal bad missing tilde; do for fmt in ssh gpg; do
    printf 'key\tk%04d\t%s\tuc-vsk-%s-%s\t-\t-\n' $i $r $v $fmt; i=$((i+1))
  done; done
done
} > "$here/cases.tsv"
wc -l < "$here/cases.tsv"
