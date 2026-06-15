#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# setup/linux.sh — Linux-specific sandbox setup
set -euo pipefail

SANDBOX_ROOT="${SANDBOX_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

setup_linux() {
  echo "==> Setting up sandbox on Linux..."

  check_linux_prerequisites
  install_k3s_linux
  # Cilium must be installed (as the CNI) before gVisor configuration triggers
  # a k3s restart — without a CNI, system pods cannot start after that restart.
  install_cilium_helm
  install_masquerade_service
  configure_containerd_gvisor
}

check_linux_prerequisites() {
  echo "  Checking prerequisites..."

  # Must be able to run sudo
  if ! sudo -n true 2>/dev/null; then
    echo "WARN: sudo access required for some install steps." >&2
  fi

  # Required tools
  local tools=("curl" "git" "jq")
  local missing=0
  for tool in "${tools[@]}"; do
    if ! command -v "${tool}" &>/dev/null; then
      echo "  MISSING: ${tool}"
      (( missing++ )) || true
    fi
  done

  if [[ "${missing}" -gt 0 ]]; then
    echo "  Installing missing prerequisites..."
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends curl git jq ca-certificates
  fi

  echo "  Prerequisites satisfied."
}

# write_k3s_apiserver_config — pin the k3s API server listen port via the k3s
# config file. k3s reads /etc/rancher/k3s/config.yaml on startup and merges it
# with the CLI flags baked into the systemd unit. The port lives here, rather
# than in INSTALL_K3S_EXEC alongside the CIDRs, precisely so it can be changed
# in place — rewrite this file and restart k3s, with no installer re-run.
write_k3s_apiserver_config() {
  sudo mkdir -p /etc/rancher/k3s
  sudo tee /etc/rancher/k3s/config.yaml > /dev/null <<EOF
# Managed by ai-agent-sandboxes setup.sh — do not edit by hand.
# Change the API server port with: ./setup.sh --apiserver-port <PORT>
https-listen-port: ${SANDBOX_APISERVER_PORT}
EOF
}

# detect_k3s_apiserver_port — print the port the running cluster's API server
# is currently on, read from the sandbox kubeconfig. Falls back to 6443 (the
# k3s default) when the kubeconfig is absent or unparseable.
detect_k3s_apiserver_port() {
  local kc="${HOME}/.sandbox/kubeconfig"
  local port=""
  if [[ -f "${kc}" ]]; then
    local server
    server="$(grep -m1 -E '^[[:space:]]*server:' "${kc}" | sed -E 's/.*server:[[:space:]]*//')"
    port="${server##*:}"
    port="${port%%/*}"
  fi
  [[ "${port}" =~ ^[0-9]+$ ]] || port="6443"
  echo "${port}"
}

# copy_k3s_kubeconfig — copy k3s' generated kubeconfig to the sandbox-dedicated
# path (~/.sandbox/kubeconfig). We do NOT touch ~/.kube/config — the user may
# have other clusters there. All kubectl/helm calls in setup/common.sh and
# uninstall.sh use --kubeconfig explicitly rather than relying on env.
copy_k3s_kubeconfig() {
  mkdir -p "${HOME}/.sandbox"
  sudo cp /etc/rancher/k3s/k3s.yaml "${HOME}/.sandbox/kubeconfig"
  sudo chown "$(id -u):$(id -g)" "${HOME}/.sandbox/kubeconfig"
  chmod 600 "${HOME}/.sandbox/kubeconfig"
}

# wait_for_k3s — block until the k3s API server answers, or fail loudly.
# Use 'k3s kubectl' rather than bare 'kubectl': k3s may have skipped creating
# the /usr/local/bin/kubectl symlink (if another kubectl exists), so bare
# 'sudo kubectl' won't find the k3s kubeconfig at /etc/rancher/k3s/k3s.yaml.
wait_for_k3s() {
  local retries="${1:-30}"
  local i=0
  until sudo k3s kubectl get nodes &>/dev/null 2>&1; do
    (( i++ )) || true
    if [[ "${i}" -ge "${retries}" ]]; then
      echo "ERROR: k3s did not become ready within ${retries} attempts." >&2
      sudo journalctl -u k3s --no-pager -n 30 >&2
      exit 1
    fi
    sleep 5
    echo "  Waiting... (${i}/${retries})"
  done
}

install_k3s_linux() {
  if command -v k3s &>/dev/null; then
    echo "  k3s already installed: $(k3s --version | head -1)"
    if ! systemctl is-active --quiet k3s; then
      echo "  Starting k3s..."
      sudo systemctl start k3s
    fi
    mkdir -p "${HOME}/.sandbox"
    if [[ ! -f "${HOME}/.sandbox/kubeconfig" ]]; then
      copy_k3s_kubeconfig
    fi

    # Reconfigure the API server port in place if it differs from the request.
    # This makes 'setup.sh --apiserver-port' idempotent: re-running it with a
    # new value rewrites the k3s config file, restarts k3s, and refreshes the
    # kubeconfig. Existing pods survive the restart (containerd keeps them);
    # Cilium picks up the new port via the helm upgrade in install_cilium_helm.
    local current_port
    current_port="$(detect_k3s_apiserver_port)"
    if [[ "${current_port}" != "${SANDBOX_APISERVER_PORT}" ]]; then
      echo "  Reconfiguring k3s API server port: ${current_port} -> ${SANDBOX_APISERVER_PORT}..."
      write_k3s_apiserver_config
      sudo systemctl restart k3s
      echo "  Waiting for k3s to restart on port ${SANDBOX_APISERVER_PORT}..."
      wait_for_k3s 30
      # k3s regenerates k3s.yaml with the new port on restart.
      copy_k3s_kubeconfig
      echo "  k3s API server now on port ${SANDBOX_APISERVER_PORT}."
    fi
    return 0
  fi

  echo "  Installing k3s..."
  echo "  (Flannel disabled — Cilium will handle networking)"
  # API server listen port — written before the installer runs so k3s honours
  # it on first start. See write_k3s_apiserver_config.
  write_k3s_apiserver_config
  # --resolv-conf: on Ubuntu, /etc/resolv.conf symlinks to systemd-resolved's
  # stub at 127.0.0.53, which is unreachable from inside pod network namespaces.
  # Pointing k3s at the upstream resolv.conf causes CoreDNS to forward to real
  # DNS servers rather than the loopback stub, preventing SERVFAIL for all pods.
  local resolv_conf="/etc/resolv.conf"
  if [[ -f /run/systemd/resolve/resolv.conf ]]; then
    resolv_conf="/run/systemd/resolve/resolv.conf"
  fi

  # WSL2 special case: the host resolv.conf points at a DNS-tunnel sentinel
  # (10.255.255.254) that WSL only answers in the host network namespace.
  # CoreDNS runs in a pod netns, so every forward to it times out and all
  # in-pod resolution fails (agents see "could not resolve host" / socket
  # errors reaching their APIs). There is no auto-discoverable pod-reachable
  # resolver — the corporate one behind the tunnel is unreachable too — so the
  # operator must name one via --dns / SANDBOX_DNS. Required on WSL2; optional
  # everywhere else.
  if [[ -z "${SANDBOX_DNS}" ]] && grep -qi microsoft /proc/version 2>/dev/null; then
    echo "ERROR: WSL2 detected. Its host DNS resolver is unreachable from pod" >&2
    echo "       network namespaces, so CoreDNS cannot resolve any names and" >&2
    echo "       agents will fail to reach their APIs." >&2
    echo "" >&2
    echo "       Set a pod-reachable DNS resolver and re-run setup:" >&2
    echo "         PowerShell:  .\\setup.ps1 -Dns 1.1.1.1,8.8.8.8" >&2
    echo "         WSL/bash:    ./setup.sh --dns 1.1.1.1,8.8.8.8" >&2
    echo "" >&2
    echo "       Use a public resolver, or your organization's internal DNS" >&2
    echo "       IP if pods need to resolve internal names." >&2
    exit 1
  fi

  # An explicit resolver overrides the auto-detected host resolv.conf on any
  # Linux host (opt-in — e.g. a bare-Linux operator behind their own split-DNS
  # who wants to pin CoreDNS's upstream); on WSL2 it is the only workable
  # option. Rendered into a dedicated file k3s owns, so we neither fight WSL's
  # resolv.conf regeneration nor clobber the host's.
  if [[ -n "${SANDBOX_DNS}" ]]; then
    resolv_conf="/etc/rancher/k3s/sandbox-resolv.conf"
    sudo mkdir -p /etc/rancher/k3s
    printf '%s\n' "${SANDBOX_DNS//,/ }" | tr ' ' '\n' | grep -v '^$' \
      | sed 's/^/nameserver /' | sudo tee "${resolv_conf}" > /dev/null
    echo "  CoreDNS will forward to ${SANDBOX_DNS} (--resolv-conf ${resolv_conf})"
  fi
  # --cluster-cidr: align k3s' built-in controller-manager with Cilium's IPAM
  # pool so the Node's .spec.podCIDR matches the range pods are actually
  # allocated from. Cilium ignores .spec.podCIDR (k8s-require-ipv4-pod-cidr=
  # false) but operators still see the value and have wasted triage time on
  # the resulting phantom mismatch.
  # --service-cidr: passed explicitly so the value is visible/overridable in
  # one place rather than relying on k3s' default.
  curl -sfL https://get.k3s.io | \
    INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable=servicelb --disable=traefik --disable=metrics-server --resolv-conf=${resolv_conf} --cluster-cidr=${SANDBOX_POD_CIDR} --service-cidr=${SANDBOX_SERVICE_CIDR}" \
    sh -

  echo "  Waiting for k3s API server to start..."
  wait_for_k3s 30

  copy_k3s_kubeconfig

  echo "  k3s installed and running on API server port ${SANDBOX_APISERVER_PORT}."
}

# install_masquerade_service — install a systemd oneshot service that
# re-applies the pod egress SNAT rule on every boot.
#
# Pod IPs are in 10.0.0.0/8 (Cilium IPAM). Without MASQUERADE, return
# packets from external hosts have nowhere to go and pod-to-internet
# traffic silently fails after a reboot. The rule is idempotent (-C check
# before -A add) so running it multiple times is safe.
install_masquerade_service() {
  echo "==> Installing sandbox-masquerade systemd service..."

  sudo tee /etc/systemd/system/sandbox-masquerade.service > /dev/null << EOF
[Unit]
Description=Sandbox pod egress MASQUERADE rule
# Run after the network stack and k3s are up so iptables rules persist
# after Cilium BPF programs are loaded.
After=network.target k3s.service
Wants=k3s.service

[Service]
Type=oneshot
# Check before add — idempotent across repeated runs and reboots.
# CIDR is scoped to the pod network (${SANDBOX_POD_CIDR}) so that traffic
# from pods to hosts on the host's own network is masqueraded correctly.
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s ${SANDBOX_POD_CIDR} ! -d ${SANDBOX_POD_CIDR} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${SANDBOX_POD_CIDR} ! -d ${SANDBOX_POD_CIDR} -j MASQUERADE'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable sandbox-masquerade.service
  # Apply the rule immediately (in case we just rebooted or this is a fresh install)
  sudo systemctl start sandbox-masquerade.service

  echo "  sandbox-masquerade.service installed and enabled."
}

configure_containerd_gvisor() {
  echo "  Configuring containerd for gVisor..."

  # Install gVisor binaries
  install_gvisor_linux

  # k3s with containerd v2 generates a version=3 base config and imports any
  # *.toml files from config-v3.toml.d/ — so we drop in only the runsc stanza.
  # Do NOT overwrite config.toml.tmpl: that would replace k3s's entire
  # containerd config with our static file, breaking the version=3 setup.
  local dropin_dir="/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d"
  sudo mkdir -p "${dropin_dir}"
  sudo cp "${SANDBOX_ROOT}/config/containerd-config.toml.tmpl" \
    "${dropin_dir}/gvisor.toml"

  # Remove the old misplaced template file if setup was previously run
  # with the wrong path, to avoid k3s picking up conflicting configs.
  sudo rm -f "/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl"

  # runsc options file (gVisor runtime configuration)
  # Use gVisor's default "sandbox" network mode (its own userspace netstack).
  # "host" mode routes traffic through the host machine's network namespace,
  # bypassing the pod's veth and Cilium's per-pod BPF programs entirely.
  # With the sandbox network mode and no Cilium TPROXY/dns: proxy rules, DNS
  # packets from gVisor's netstack flow through the pod's veth normally and
  # Cilium's port/entity-based egress policy governs them correctly.
  sudo mkdir -p /etc/containerd
  sudo tee /etc/containerd/runsc.toml > /dev/null << 'EOF'
[runsc_config]
  debug = "false"
  debug-log = "/tmp/runsc-%ID%.log"
  strace = "false"
  net-raw = "false"
EOF

  echo "  Restarting k3s to apply containerd config..."
  sudo systemctl restart k3s

  echo "  Waiting for k3s restart..."
  sleep 10
  local retries=20
  local i=0
  until sudo k3s kubectl get nodes &>/dev/null 2>&1; do
    (( i++ )) || true
    [[ "${i}" -ge "${retries}" ]] && { echo "ERROR: k3s did not restart." >&2; exit 1; }
    sleep 5
  done

  echo "  containerd configured for gVisor."
}
