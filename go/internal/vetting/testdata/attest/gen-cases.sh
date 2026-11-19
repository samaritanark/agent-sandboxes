#!/usr/bin/env bash
# cases.tsv: id func repo uc yes msg home tty scen pathmode
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
i=0
row() { printf 'a%04d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' $i "$@"; i=$((i+1)); }
{
for r in at-clean at-nokey at-gpgid at-evilkey at-dirty at-tagged at-exc at-exc-legacy at-evil-config not-a-repo missing; do
  for uc in base vsk-a vsk-evil vsk-bad clean gpg vsk-a-clean; do for y in false true; do
    row attest $r $uc $y - ed - acc-one stub
  done; done
done
row attest at-clean vsk-a false "custom message" ed - none stub
row attest at-clean vsk-a false "it's got 'quotes' and \$vars" ed - none stub
row attest at-clean vsk-a true "" ed - none stub
row attest at-clean vsk-a false NONE ed - none stub
row attest at-exc vsk-a false NONE ed y acc-one stub
for y in yes TRUE ""; do row attest at-exc vsk-a "$y" - ed - acc-one stub; row ack at-exc base "$y" - ed - acc-one stub; done
row attest at-evil-defaultkey base false - ed - acc-one stub
row attest at-evil-defaultkey vsk-a false - ed - acc-one stub
for h in empty blank; do for tty in y n; do row assist at-clean base false - $h $tty none stub; row assist at-nokey base false - $h $tty none stub; done; done
for tty in - y n; do row ack at-exc base true - ed $tty mixed stub; row attest at-exc vsk-a true - ed $tty mixed stub; done
for r in at-exc at-exc-legacy; do for rep in y n EOF "y|y" " y" x; do
  row attest $r vsk-a false - ed "$rep" acc-one stub
  row attest $r vsk-a false - ed "$rep" acc-two stub
done; done
for r in at-exc at-exc-legacy at-clean; do for y in false true; do for scn in acc-one acc-two none notlisted; do for tty in - y n EOF; do for pm in stub nostub; do
  row ack $r base $y - ed "$tty" $scn $pm
done; done; done; done; done
for r in at-clean at-nokey at-gpgid at-evilkey at-exc at-tagged at-dirty; do for uc in base vsk-a vsk-evil clean; do for tty in y n EOF "y|y" "y|n" x; do
  row inline $r $uc false - ed "$tty" acc-one stub
done; done; done
for r in at-clean at-nokey at-gpgid at-exc not-a-repo missing; do for uc in base vsk-a vsk-bad gpg existing has-vsk-line; do for h in ed none rsa; do for tty in - y n EOF; do
  row assist $r $uc false - $h "$tty" none stub
done; done; done; done
} > "$here/cases.tsv"
wc -l < "$here/cases.tsv"
