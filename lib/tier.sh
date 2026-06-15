#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/tier.sh — Tier definitions and domain lists
set -euo pipefail

# validate_tier — die if tier is not 1, 2, or 3
validate_tier() {
  local tier="$1"
  case "${tier}" in
    1|2|3) return 0 ;;
    *)
      echo "ERROR: Invalid tier '${tier}'. Valid tiers: 1, 2, 3." >&2
      echo " " >&2
      exit 1
      ;;
  esac
}

# get_tier_domains — print newline-separated list of extra domains for tier
get_tier_domains() {
  local tier="$1"
  case "${tier}" in
    1)
      # Tier 1: agent domains only, no extra domains
      ;;
    2|3)
      # Tier 2/3: project + package registry domains. Operators who use an
      # internal Git host (Gitea, GitLab Self-Managed, etc.) can add it per
      # invocation with --allow-domain <host>.
      #
      # codeload.github.com / objects.githubusercontent.com /
      # release-assets.githubusercontent.com are siblings of github.com used
      # whenever something downloads a GitHub source archive, an LFS object,
      # or a release asset — Go modules, pip-from-git, npm-from-git, and
      # terraform-from-git all hit them. go.dev + dl.google.com +
      # proxy.golang.org + sum.golang.org are the standard set Go needs for
      # `go install` / `go mod download` to work.
      cat <<'EOF'
github.com
api.github.com
codeload.github.com
objects.githubusercontent.com
release-assets.githubusercontent.com
pypi.org
files.pythonhosted.org
registry.npmjs.org
registry.terraform.io
go.dev
dl.google.com
proxy.golang.org
sum.golang.org
EOF
      ;;
  esac
}

# get_tier_retention_days — returns log retention days for tier
get_tier_retention_days() {
  local tier="$1"
  case "${tier}" in
    1|2) echo "90" ;;
    3)   echo "180" ;;
    *)   echo "90" ;;
  esac
}

# get_tier_description — human-readable tier name
get_tier_description() {
  local tier="$1"
  case "${tier}" in
    1) echo "Ephemeral" ;;
    2) echo "Project" ;;
    3) echo "Infra" ;;
    *) echo "Unknown" ;;
  esac
}
