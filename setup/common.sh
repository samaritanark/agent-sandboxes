#!/usr/bin/env bash
# setup/common.sh — Common setup tasks for all platforms
set -euo pipefail

SANDBOX_ROOT="${SANDBOX_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Canonical kubeconfig path — must match lib/platform.sh and uninstall.sh.
# All kubectl and helm calls below use this explicitly so the user's default
# ~/.kube/config (which may point to other clusters) is never consulted.
SANDBOX_KUBECONFIG="${SANDBOX_KUBECONFIG:-${HOME}/.sandbox/kubeconfig}"

# Network interface detection + Cilium-for-VPN device wiring.
# shellcheck source=../lib/network.sh
source "${SANDBOX_ROOT}/lib/network.sh"

# Per-pod resource constants + dynamic ResourceQuota sizing.
# shellcheck source=../lib/resources.sh
source "${SANDBOX_ROOT}/lib/resources.sh"

# Pod CIDR for Cilium IPAM and iptables masquerade rules.
# Must not overlap with the host network. 100.64.0.0/10 (CGNAT range) is used
# instead of 10.0.0.0/8 to avoid conflicts with corporate/private networks that
# use RFC 1918 10.x.x.x space. Override via --pod-cidr in setup.sh if needed.
# Also passed to k3s as --cluster-cidr so the Node's .spec.podCIDR matches
# Cilium's IPAM pool — otherwise operators see two different ranges and waste
# triage time chasing a phantom mismatch.
SANDBOX_POD_CIDR="100.64.0.0/10"  # may be overridden by --pod-cidr in setup.sh

# Service CIDR for k3s (kube-apiserver/controller-manager). Cilium reads this
# from the apiserver in kube-proxy-replacement mode; no Cilium flag needed.
# Default matches k3s' own default. Override via --service-cidr if your host
# network overlaps with 10.43.0.0/16.
SANDBOX_SERVICE_CIDR="10.43.0.0/16"  # may be overridden by --service-cidr in setup.sh

# Kubernetes API server (kube-apiserver) listen port. 6443 is the k3s and
# upstream-Kubernetes default. Override via --apiserver-port in setup.sh when
# the host already runs another local Kubernetes endpoint on 6443 — e.g.
# Ansible/kubectl tooling pointed at a cluster on OpenStack — which would
# otherwise collide with the sandbox cluster. On Linux this is the k3s
# --https-listen-port (set via /etc/rancher/k3s/config.yaml); re-running
# setup.sh with a different value reconfigures it in place.
SANDBOX_APISERVER_PORT="${SANDBOX_APISERVER_PORT:-6443}"

# Upstream DNS resolver(s) for CoreDNS to forward to, as a comma- or
# space-separated list of IPs. Empty by default: bare Linux and macOS/Lima
# derive a pod-reachable resolver from the host's resolv.conf automatically.
# Required only on WSL2, whose host resolv.conf points at a DNS-tunnel
# sentinel (e.g. 10.255.255.254) that is unreachable from a pod network
# namespace — see install_k3s_linux in setup/linux.sh.
SANDBOX_DNS="${SANDBOX_DNS:-}"

# setup_common — apply Kubernetes manifests and verify cluster state
setup_common() {
  echo "==> Applying Kubernetes manifests..."

  if ! command -v kubectl &>/dev/null; then
    echo "WARN: kubectl not found; skipping manifest apply." >&2
    return 0
  fi

  if ! kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" cluster-info &>/dev/null 2>&1; then
    echo "WARN: Cluster not reachable; skipping manifest apply." >&2
    echo "      Re-run 'sandbox setup' after cluster is running." >&2
    return 0
  fi

  echo "  Applying namespace..."
  kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" apply -f "${SANDBOX_ROOT}/manifests/namespace.yaml"

  echo "  Sizing and applying ResourceQuota and LimitRange..."
  apply_resourcequota "${SANDBOX_KUBECONFIG}"

  echo "  Applying ServiceAccount..."
  kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" apply -f "${SANDBOX_ROOT}/manifests/serviceaccount.yaml"

  echo "  Applying RuntimeClass..."
  kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" apply -f "${SANDBOX_ROOT}/manifests/runtimeclass.yaml"

  echo "  Applying kube-system network policy..."
  kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" apply -f "${SANDBOX_ROOT}/manifests/policy-kube-system.yaml"

  echo "  Verifying Cilium policy enforcement mode..."
  # Check the ConfigMap first; fall back to the Helm release values.
  # Cilium 1.16+ may not write this key to the ConfigMap when set via Helm,
  # but the agent still honours the value compiled into the release.
  local enforcement_mode
  enforcement_mode="$(kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
    get configmap -n kube-system cilium-config \
    -o jsonpath='{.data.policy-enforcement-mode}' 2>/dev/null || true)"

  if [[ -z "${enforcement_mode}" ]]; then
    # Newer Cilium stores the value in the Helm release rather than ConfigMap
    enforcement_mode="$(helm --kubeconfig "${SANDBOX_KUBECONFIG}" \
      get values cilium -n kube-system 2>/dev/null \
      | grep -E '^policyEnforcementMode:' \
      | awk '{print $2}' || true)"
  fi

  if [[ "${enforcement_mode}" == "always" ]]; then
    echo "  Cilium enforcement: always (correct)"
  elif [[ -z "${enforcement_mode}" ]]; then
    echo "WARN: Could not determine Cilium policy enforcement mode." >&2
    echo "      Verify manually: helm get values cilium -n kube-system" >&2
  else
    echo "WARN: Cilium policy enforcement mode is '${enforcement_mode}' (expected 'always')." >&2
    echo "      Re-run setup or: helm upgrade cilium cilium/cilium --reuse-values --set policyEnforcementMode=always" >&2
  fi

  echo "  Setting up log directory..."
  local log_dir="${HOME}/.sandbox/logs"
  mkdir -p "${log_dir}"
  chmod 700 "${HOME}/.sandbox"
  echo "  Log directory: ${log_dir}"

  echo "  Adding bin/sandbox to PATH hint..."
  local sandbox_bin="${SANDBOX_ROOT}/bin/sandbox"
  chmod +x "${sandbox_bin}"

  if ! echo "${PATH}" | grep -q "${SANDBOX_ROOT}/bin"; then
    echo ""
    echo "NOTE: Add the following to your shell profile to use 'sandbox' directly:"
    echo "  export PATH=\"${SANDBOX_ROOT}/bin:\${PATH}\""
    echo ""
    echo "  # Bash completions:"
    echo "  source ${SANDBOX_ROOT}/bin/completions/sandbox.bash"
    echo ""
    echo "  # Zsh completions:"
    echo "  source ${SANDBOX_ROOT}/bin/completions/sandbox.zsh"
  fi
}

# install_gvisor_linux — install gVisor runsc and configure containerd
install_gvisor_linux() {
  echo "==> Installing gVisor..."

  local arch
  arch="$(uname -m)"

  local runsc_url="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}/runsc"
  local shim_url="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}/containerd-shim-runsc-v1"

  # Download both binaries into a temp dir so sha512sum -c can find them by
  # their bare filename (the checksum file contains e.g. "<hash>  runsc", and
  # sha512sum looks for that name relative to the working directory).
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  curl -fsSL "${runsc_url}"        -o "${tmp_dir}/runsc"
  curl -fsSL "${runsc_url}.sha512" -o "${tmp_dir}/runsc.sha512"
  (cd "${tmp_dir}" && sha512sum -c runsc.sha512)
  sudo install -m 755 "${tmp_dir}/runsc" /usr/local/bin/runsc

  curl -fsSL "${shim_url}"        -o "${tmp_dir}/containerd-shim-runsc-v1"
  curl -fsSL "${shim_url}.sha512" -o "${tmp_dir}/containerd-shim-runsc-v1.sha512"
  (cd "${tmp_dir}" && sha512sum -c containerd-shim-runsc-v1.sha512)
  sudo install -m 755 "${tmp_dir}/containerd-shim-runsc-v1" /usr/local/bin/containerd-shim-runsc-v1

  rm -rf "${tmp_dir}"
  echo "  gVisor installed: $(runsc --version)"
}

# install_cilium_helm — install Cilium via Helm
install_cilium_helm() {
  echo "==> Installing Cilium via Helm..."

  if ! command -v helm &>/dev/null; then
    echo "  Installing helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  fi

  helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
  helm repo update

  # If a VPN interface is up at install time, pin Cilium's device list in the
  # INITIAL install so the cluster comes up correct on first boot. Otherwise
  # configure_cilium_for_vpn (called below) has to apply the device list with
  # `helm upgrade` + `rollout restart ds/cilium` AFTER k3s has already started
  # CoreDNS — and restarting the agent mid-bringup leaves stale BPF service
  # maps that break pod->ClusterIP, which kills cluster DNS and strands setup.
  # See the configure_cilium_for_vpn header in lib/network.sh. These settings
  # match what configure_cilium_for_vpn would apply, so the call below sees no
  # change and skips the restart entirely.
  local -a cilium_device_args=()
  local primary_iface vpn_iface_count
  primary_iface="$(detect_primary_iface)"
  vpn_iface_count="$(detect_vpn_ifaces | grep -c . || true)"
  if [[ -n "${primary_iface}" ]] && [[ "${vpn_iface_count}" -gt 0 ]]; then
    local devices_csv
    devices_csv="${primary_iface},$(detect_vpn_ifaces | sort | paste -sd, -)"
    echo "  VPN interface detected — pinning Cilium devices at install: ${devices_csv}"
    cilium_device_args=(
      --set "devices={${devices_csv}}"
      --set-string "extraConfig.direct-routing-device=${primary_iface}"
      --set-string "extraConfig.egress-masquerade-interfaces="
    )
  fi

  # socketLB.hostNamespaceOnly=true: required for gVisor pods.
  # Cilium's default socket-LB rewrites ClusterIPs at the host kernel's
  # cgroup connect() hook. gVisor pods never reach that hook because their
  # connect() syscall is handled by gVisor's userspace netstack, not the
  # host kernel — so ClusterIP→PodIP translation never happens, packets
  # leave the pod with the ClusterIP intact, hit the host's default route
  # (often a VPN), and disappear. Restricting socket-LB to the host netns
  # forces Cilium to install TC-based LB on pod veths, which DNATs the
  # packet in transit (after gVisor builds it, before host routing). Both
  # paths produce identical results for runc pods; gVisor pods only work
  # via the TC path.
  helm --kubeconfig "${SANDBOX_KUBECONFIG}" upgrade --install cilium cilium/cilium \
    --namespace kube-system \
    --set operator.replicas=1 \
    --set hubble.relay.enabled=true \
    --set hubble.enabled=true \
    --set hubble.metrics.enableOpenMetrics=false \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="127.0.0.1" \
    --set k8sServicePort="${SANDBOX_APISERVER_PORT}" \
    --set policyEnforcementMode="always" \
    --set bpf.masquerade=true \
    --set socketLB.hostNamespaceOnly=true \
    --set ipam.operator.clusterPoolIPv4PodCIDRList="${SANDBOX_POD_CIDR}" \
    "${cilium_device_args[@]+"${cilium_device_args[@]}"}"

  echo "  Waiting for Cilium to be ready..."
  kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
    -n kube-system rollout status ds/cilium --timeout=120s

  # Cilium BPF masquerade (bpf.masquerade=true) may not activate without an
  # explicit native device configured.  Ensure pod-to-internet traffic is
  # SNAT'd to the node IP via an iptables fallback rule.  Cilium pod IPs
  # (allocated from ${SANDBOX_POD_CIDR} by Cilium IPAM) must be masqueraded
  # before leaving the node or external routers cannot return packets to them.
  # Source and destination use the pod CIDR (not a broader RFC 1918 range) so
  # that traffic from pods to hosts on the host's own network (e.g. corporate
  # 10.x.x.x) is still masqueraded correctly.
  if ! sudo iptables -t nat -C POSTROUTING \
       -s "${SANDBOX_POD_CIDR}" '!' -d "${SANDBOX_POD_CIDR}" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING \
      -s "${SANDBOX_POD_CIDR}" '!' -d "${SANDBOX_POD_CIDR}" -j MASQUERADE
    echo "  Added iptables MASQUERADE rule for pod egress."
  fi

  # Verify/reconcile Cilium's device wiring. When a VPN was up at install
  # time the devices were already baked into the helm install above, so this
  # is a no-op — no DaemonSet restart. It still covers the no-VPN case and
  # any interface drift. Operators reconnecting a VPN after setup run
  # 'sandbox configure-network' to re-apply.
  echo "==> Verifying Cilium network configuration..."
  configure_cilium_for_vpn "${SANDBOX_KUBECONFIG}"

  # Seed the baseline primary-IPv4 annotation on the Node. reconcile_node_ipv4
  # compares this on every subsequent `sandbox run` to detect a host IP change
  # that didn't rename the interface — the WSL2-on-Windows-reboot case in
  # particular. Without this seed the first post-install run would treat the
  # current IP as "new" and trigger a needless restart sequence.
  reconcile_node_ipv4 "${SANDBOX_KUBECONFIG}"

  echo "  Cilium installed."
}

# tls_intercept_check — probe a known-public HTTPS endpoint that the image
# build will hit, and abort with a clear message if the host's egress
# appears to be MITM'd by a TLS-intercepting proxy (Zscaler/Netskope/etc.)
# that the sandbox image doesn't yet trust.
#
# Called by build_images BEFORE the first `docker build`, since the build
# step's curl failure ("SSL certificate problem: unable to get local issuer
# certificate") is what stranded users without a working sandbox CLI — and
# without the CLI, the obvious "run sandbox setup-proxy-cert" hint doesn't
# land. We surface that hint here against ./bin/sandbox, which works from
# the repo root before anything is on PATH.
#
# Skipped when:
#   - config/extra-ca-certs/ already has *.crt files (the user has either
#     hand-staged a cert or run setup-proxy-cert; trust them);
#   - curl is unavailable (we can't probe; let the build try);
#   - the probe succeeds (no interception, or the corporate root happens
#     to chain to a public CA — either way the build will work).
#
# The probe target is deb.nodesource.com because Dockerfile.base hits it
# unconditionally; if THAT fails inside the image, the build dies. Using
# the same host on the probe minimises the chance of a false positive
# from a host-specific block.
tls_intercept_check() {
  command -v curl >/dev/null 2>&1 || return 0

  # Already have something staged — don't pester the user.
  local user_dir="${SANDBOX_ROOT}/config/extra-ca-certs"
  if [[ -d "${user_dir}" ]]; then
    local existing
    existing="$(find "${user_dir}" -maxdepth 1 -name '*.crt' -print -quit 2>/dev/null)"
    [[ -n "${existing}" ]] && return 0
  fi

  if curl -fsSL --max-time 8 https://deb.nodesource.com -o /dev/null 2>/dev/null; then
    return 0
  fi
  # Re-run to capture the exit code separately from the silenced stderr.
  curl -fsSL --max-time 8 https://deb.nodesource.com -o /dev/null 2>/dev/null
  local rc=$?

  # curl exit 60 == "peer certificate cannot be authenticated with given CA
  # certs". Exit 35 (SSL connect error) also commonly indicates interception.
  # Anything else (DNS fail, timeout) is more likely a plain network problem
  # and we shouldn't claim it's TLS interception.
  if [[ "${rc}" -ne 60 ]] && [[ "${rc}" -ne 35 ]]; then
    return 0
  fi

  echo "" >&2
  echo "ERROR: TLS interception detected on the host network." >&2
  echo "" >&2
  echo "  A TLS-intercepting proxy (Zscaler, Netskope, Forcepoint, etc.) is" >&2
  echo "  re-signing TLS connections from this host. The sandbox image build" >&2
  echo "  will fail when it tries to fetch packages over HTTPS." >&2
  echo "" >&2
  echo "  To fix this BEFORE the image build runs, extract your org's proxy" >&2
  echo "  root CA and stage it for the build:" >&2
  echo "" >&2
  echo "    ./bin/sandbox setup-proxy-cert" >&2
  echo "" >&2
  echo "  Then re-run setup:" >&2
  echo "" >&2
  echo "    ./setup.sh" >&2
  echo "" >&2
  echo "  setup-proxy-cert auto-detects most common proxies on Linux, macOS," >&2
  echo "  and WSL2 (falling back to the Windows trust store via PowerShell)." >&2
  echo "  If your proxy's CA subject doesn't match the built-in vendor list," >&2
  echo "  pass --vendor <substring>, or use --from-wire deb.nodesource.com to" >&2
  echo "  pull the chain directly off the wire. See:" >&2
  echo "" >&2
  echo "    ./bin/sandbox setup-proxy-cert --help" >&2
  echo "" >&2
  echo "  Full details: README §'Corporate TLS-intercept proxies'." >&2
  echo "" >&2
  exit 1
}

# stage_extra_ca_certs — copy any user-provided extra root CAs from the
# canonical config dir into the Docker build context immediately before
# `docker build` runs.
#
# Why two directories: config/extra-ca-certs/ is the discoverable, user-facing
# location (sits alongside blocked-destinations.yaml, defaults.yaml, etc.).
# docker/extra-ca-certs/ is the build-context staging area that Dockerfile.base
# COPYs from. Keeping them separate avoids exposing `docker/` as a user-facing
# directory and keeps the staging area churnable without polluting `config/`.
#
# Both directories are tracked via .gitkeep so they always exist; the *.crt
# files themselves are gitignored. Staging is a clean overwrite: anything
# stale in docker/extra-ca-certs/ from a previous build (or hand-editing) is
# wiped first.
stage_extra_ca_certs() {
  local user_dir="${SANDBOX_ROOT}/config/extra-ca-certs"
  local build_dir="${SANDBOX_ROOT}/docker/extra-ca-certs"

  mkdir -p "${build_dir}"
  # Wipe stale *.crt files; preserve .gitkeep so the dir survives in git.
  find "${build_dir}" -maxdepth 1 -name '*.crt' -delete 2>/dev/null || true

  if [[ ! -d "${user_dir}" ]]; then
    return 0
  fi

  local count=0
  local f
  for f in "${user_dir}"/*.crt; do
    [[ -e "${f}" ]] || continue
    cp "${f}" "${build_dir}/"
    (( count++ )) || true
  done

  if [[ "${count}" -gt 0 ]]; then
    echo "  Staging ${count} extra CA cert(s) into the build context."
  fi
}

# run_with_retries <max_attempts> <delay_seconds> <label> -- <command...>
#
# Run a command up to <max_attempts> times, pausing <delay_seconds> between
# attempts, returning the final exit code. Used to absorb transient corporate-
# proxy hiccups during `docker build` (the dominant failure mode we've seen is
# Zscaler-mediated TLS to deb.nodesource.com timing out exactly once, then
# succeeding on retry — exit 100 from apt-get update, identical command works
# the next time).
#
# Output behavior: the command's own stdout/stderr is NOT suppressed — we want
# the real error visible when it ultimately fails. Between attempts we print a
# short "retrying" line; we do NOT print anything when attempt 1 succeeds.
#
# `--` separates our args from the wrapped command so the command can contain
# arbitrary flags (e.g. --build-arg) without ambiguity.
run_with_retries() {
  local max_attempts="$1"
  local delay="$2"
  local label="$3"
  shift 3
  [[ "${1:-}" == "--" ]] && shift

  local attempt=0 rc=0
  while true; do
    (( attempt++ )) || true
    if "$@"; then
      return 0
    fi
    rc=$?
    if [[ "${attempt}" -ge "${max_attempts}" ]]; then
      echo "  ERROR: ${label} failed after ${attempt} attempts (exit ${rc})." >&2
      return "${rc}"
    fi
    echo "  ${label} failed (attempt ${attempt}/${max_attempts}, exit ${rc}); retrying in ${delay}s..." >&2
    sleep "${delay}"
  done
}

# build_images — build all sandbox container images so pods can start with
# imagePullPolicy: Never. On Linux the images are built with the host's Docker
# (or Podman) and imported into k3s's containerd. On macOS the cluster lives in
# a Lima VM, so the build runs inside the VM — see build_images_macos.
build_images() {
  local platform
  platform="$(uname -s)"

  echo "==> Building sandbox container images..."

  if [[ "${platform}" == "Darwin" ]]; then
    build_images_macos
    return
  fi

  # Prefer docker; fall back to podman (CLI-compatible for build/save)
  local container_cli=""
  if command -v docker &>/dev/null; then
    container_cli="docker"
  elif command -v podman &>/dev/null; then
    container_cli="podman"
  else
    echo "  WARN: neither docker nor podman found — skipping image build." >&2
    echo "        Install Docker or Podman and re-run 'sandbox setup' or './setup.sh'." >&2
    return 0
  fi
  echo "  Using: ${container_cli}"

  local docker_dir="${SANDBOX_ROOT}/docker"

  tls_intercept_check
  stage_extra_ca_certs

  # Build in dependency order: base must come first; agent images depend on
  # base; infra variants depend on their respective agent images.
  local -a image_tags=()

  _build_image() {
    local tag="$1"
    local dockerfile="$2"
    shift 2  # remaining args are extra build flags (e.g. --build-arg)

    if [[ ! -f "${docker_dir}/${dockerfile}" ]]; then
      echo "  Skipping ${tag} (${dockerfile} not found)"
      return 0
    fi

    echo "  Building ${tag}..."
    # --quiet dropped intentionally: BuildKit's default progress output
    # surfaces the real apt-get/curl error when a step fails, which is the
    # information we need to act on. 3 attempts with a 5s pause absorbs
    # the common transient-corp-proxy case without masking real failures.
    run_with_retries 3 5 "build of ${tag}" -- \
      "${container_cli}" build \
        -t "${tag}" -f "${docker_dir}/${dockerfile}" "$@" "${docker_dir}"
    echo "  Built ${tag}"
    image_tags+=("${tag}")
  }

  _build_image "docker.io/library/sandbox:base"     "Dockerfile.base"
  _build_image "docker.io/library/sandbox:claude"   "Dockerfile.claude"
  _build_image "docker.io/library/sandbox:codex"    "Dockerfile.codex"
  _build_image "docker.io/library/sandbox:opencode" "Dockerfile.opencode"
  _build_image "docker.io/library/sandbox:shell"    "Dockerfile.shell"

  # Tier 3 infra variants — one per agent
  _build_image "docker.io/library/sandbox:claude-infra"   "Dockerfile.infra" --build-arg "BASE_IMAGE=sandbox:claude"
  _build_image "docker.io/library/sandbox:codex-infra"    "Dockerfile.infra" --build-arg "BASE_IMAGE=sandbox:codex"
  _build_image "docker.io/library/sandbox:opencode-infra" "Dockerfile.infra" --build-arg "BASE_IMAGE=sandbox:opencode"

  # k3s uses its own containerd instance; Docker-built images are not visible
  # to it until explicitly imported.
  if ! command -v k3s &>/dev/null; then
    echo "  WARN: k3s not found — skipping containerd import." >&2
    echo "        Images are in Docker; re-run after k3s is installed." >&2
    return 0
  fi

  echo "  Importing images into k3s containerd..."
  for tag in "${image_tags[@]}"; do
    echo "  Importing ${tag}..."
    "${container_cli}" save "${tag}" | sudo k3s ctr images import -
    echo "  Imported ${tag}"
  done
  echo "  All images imported into k3s containerd."

  echo "  Image build complete."
}

# build_images_macos — build the agent images inside the Lima VM.
#
# The macOS host may have no Docker at all, and the cluster's containerd lives
# inside the VM regardless — so the build runs in the VM via nerdctl + buildkit
# (installed by the Lima provision script). buildkit is wired to k3s's own
# containerd and the k8s.io namespace, so each build lands directly where k3s
# reads images, and an infra image can `FROM` a just-built agent image.
#
# The repo is bind-mounted into the VM at the SAME path it has on the host
# (Lima maps the host home to /Users/<user>), so SANDBOX_ROOT resolves
# identically inside the VM — provided the repo lives under the home directory.
build_images_macos() {
  if [[ "${SANDBOX_ROOT}" != "${HOME}/"* ]]; then
    echo "ERROR: on macOS the repo must live under your home directory so the" >&2
    echo "       Lima VM can see it for the image build." >&2
    echo "       Home: ${HOME}" >&2
    echo "       Repo: ${SANDBOX_ROOT}" >&2
    exit 1
  fi

  local docker_dir="${SANDBOX_ROOT}/docker"
  local -a nerdctl=(
    limactl shell "${LIMA_VM_NAME:-sandbox-vm}" --
    sudo nerdctl --address /run/k3s/containerd/containerd.sock --namespace k8s.io
  )

  # Probe the macOS host's egress for TLS interception before the VM build
  # starts. The Lima VM egresses through the host's network, so a host-level
  # MITM (Zscaler etc.) hits the in-VM image build the same way it would on
  # Linux. Running the probe here saves the user a 5-minute Lima build before
  # the first failing curl inside the Dockerfile.
  tls_intercept_check

  # Stage extra CA certs from the host (config/) into the docker/ build
  # context. The Lima VM bind-mounts ~ at the same path, so the VM sees the
  # staged files identically.
  stage_extra_ca_certs

  _vm_build_image() {
    local tag="$1"
    local dockerfile="$2"
    shift 2  # remaining args are extra build flags (e.g. --build-arg)

    if [[ ! -f "${docker_dir}/${dockerfile}" ]]; then
      echo "  Skipping ${tag} (${dockerfile} not found)"
      return 0
    fi

    echo "  Building ${tag} (inside the Lima VM)..."
    # See run_with_retries header for why we retry; same transient-proxy
    # rationale as the Linux build path.
    run_with_retries 3 5 "build of ${tag}" -- \
      "${nerdctl[@]}" build \
        -t "${tag}" -f "${docker_dir}/${dockerfile}" "$@" "${docker_dir}"
    echo "  Built ${tag}"
  }

  _vm_build_image "docker.io/library/sandbox:base"     "Dockerfile.base"
  _vm_build_image "docker.io/library/sandbox:claude"   "Dockerfile.claude"
  _vm_build_image "docker.io/library/sandbox:codex"    "Dockerfile.codex"
  _vm_build_image "docker.io/library/sandbox:opencode" "Dockerfile.opencode"
  _vm_build_image "docker.io/library/sandbox:shell"    "Dockerfile.shell"

  # Tier 3 infra variants — one per agent
  _vm_build_image "docker.io/library/sandbox:claude-infra"   "Dockerfile.infra" --build-arg "BASE_IMAGE=sandbox:claude"
  _vm_build_image "docker.io/library/sandbox:codex-infra"    "Dockerfile.infra" --build-arg "BASE_IMAGE=sandbox:codex"
  _vm_build_image "docker.io/library/sandbox:opencode-infra" "Dockerfile.infra" --build-arg "BASE_IMAGE=sandbox:opencode"

  echo "  Image build complete (images are in the VM's k3s containerd)."
}
