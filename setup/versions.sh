#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# setup/versions.sh — Single source of truth for infrastructure component pins.
#
# These are the versions of the isolation stack (k3s, Cilium, gVisor) and its
# helper tools that setup installs and `sandbox upgrade` moves you between.
# Historically every one of these floated to "latest" at provision time, so two
# machines set up a week apart could run different kernels of the sandbox. Pinning
# them here makes a checkout reproducible and gives `sandbox status` / `upgrade`
# a concrete target to compare the live cluster against.
#
# Renovate keeps these current (see renovate.json): a bump lands as a PR you
# review, rather than silently on the next setup run.
#
# Empty string == "unpinned": the installer falls back to its original
# latest-resolving behavior. Blank a pin to opt a single component back out of
# pinning (e.g. to chase a hotfix upstream hasn't tagged into a release yet)
# without touching the wiring in common.sh / linux.sh / the Lima template.
#
# Each var honors a pre-set environment value, so `SANDBOX_K3S_VERSION=... ./setup.sh`
# still works for one-off overrides.

# k3s — passed as INSTALL_K3S_VERSION to the get.k3s.io installer. Format is the
# upstream release tag including the +k3sN build suffix (URL-encoded by the
# installer). k3s tracks upstream Kubernetes' support window, so this is the pin
# that matters most for EOL.
# renovate: datasource=github-releases depName=k3s-io/k3s versioning=semver-coerced
SANDBOX_K3S_VERSION="${SANDBOX_K3S_VERSION:-v1.35.5+k3s1}"

# Cilium — Helm chart version, passed as `--version` to `helm upgrade --install`.
# renovate: datasource=helm depName=cilium registryUrl=https://helm.cilium.io versioning=semver
SANDBOX_CILIUM_VERSION="${SANDBOX_CILIUM_VERSION:-1.19.4}"

# gVisor — release "point" identifier (YYYYMMDD.N) that selects the
# storage.googleapis.com/gvisor/releases/release/<id>/ directory. gVisor has no
# semver and no clean Renovate datasource; the fallback is a github-tags regex on
# google/gvisor (tags look like release-YYYYMMDD.0) plus `sandbox status`
# surfacing staleness. "latest" is the historical unpinned value and still works.
# renovate: datasource=github-tags depName=google/gvisor extractVersion=^release-(?<version>.+)$ versioning=loose
SANDBOX_GVISOR_RELEASE="${SANDBOX_GVISOR_RELEASE:-20260601.0}"

# helm — only used when setup has to install helm itself (get-helm-3). Passed as
# DESIRED_VERSION. Constrained to <4 in renovate.json: setup uses the get-helm-3
# installer and the Cilium chart is validated against helm 3.
# renovate: datasource=github-releases depName=helm/helm versioning=semver
SANDBOX_HELM_VERSION="${SANDBOX_HELM_VERSION:-v3.21.1}"

# nerdctl — macOS-only in-VM image builder (nerdctl-full release asset).
# renovate: datasource=github-releases depName=containerd/nerdctl versioning=semver
SANDBOX_NERDCTL_VERSION="${SANDBOX_NERDCTL_VERSION:-2.3.4}"
