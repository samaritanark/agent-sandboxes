#!/usr/bin/env bash
# poststate.sh <repo>: tags and the headers of their objects (signature body removed)
r="$1"; export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git -C "$r" for-each-ref --format='%(refname:short)' refs/tags 2>/dev/null | while IFS= read -r t; do
  echo "tag $t"; git -C "$r" cat-file -p "refs/tags/$t" 2>/dev/null | sed '/^-----BEGIN/,$d'
done
