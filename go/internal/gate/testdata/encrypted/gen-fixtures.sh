#!/usr/bin/env bash
# Regenerates fixtures/ from the fixture_* functions in the bash test (the oracle's own test data),
# extracted by name so they follow the source. Run from the repo root: go/internal/gate/testdata/encrypted/gen-fixtures.sh
set -euo pipefail
src=tests/test-secret-gate.sh
out="$(dirname "$0")/fixtures"
eval "$(grep -E '^(SEALED_TOK|PLAIN_TOK)=' "$src")"
fns=(fixture_sealedsecret fixture_sealed_template_leak fixture_sealed_nested_spec fixture_sealed_extraobjects
     fixture_extraobjects_mixed fixture_sealed_multidoc fixture_sops fixture_sops_unencrypted_leak
     fixture_sops_sameline_comment fixture_sops_nonyaml)
for fn in "${fns[@]}"; do
  eval "$(awk -v f="$fn" '$0 ~ "^" f "\\(\\) \\{" {p=1} p {print} p && /^}/ {exit}' "$src")"
done
fixture_sealedsecret            "$out/sealed.yaml"
fixture_sealed_template_leak    "$out/tmpl.yaml"
fixture_sealed_nested_spec      "$out/nested.yaml"
fixture_sealed_extraobjects     "$out/extra.yaml"
fixture_extraobjects_mixed      "$out/mixed-extra.yaml"
fixture_sealed_multidoc         "$out/multi.yaml"
fixture_sops                    "$out/sops.yaml"
fixture_sops_unencrypted_leak   "$out/sopsleak.yaml"
fixture_sops_sameline_comment   "$out/sameline.yaml"
fixture_sops_nonyaml            "$out/config.py"
