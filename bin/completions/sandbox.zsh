#compdef sandbox
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# bin/completions/sandbox.zsh — Zsh completion for sandbox CLI
#
# Source in your .zshrc:
#   source /path/to/ai-agent-sandboxes/bin/completions/sandbox.zsh
# Or copy to a directory in $fpath.

_sandbox() {
  local state line
  typeset -A opt_args

  _arguments -C \
    '1:command:->command' \
    '*::args:->args'

  case "${state}" in
    command)
      local commands=(
        'run:Launch a sandboxed agent session'
        'resume:Reconnect to a running session'
        'allow:Add domains to a running session''s egress allowlist (no restart)'
        'list:List active and recent sessions'
        'logs:Show audit log for a session'
        'flows:Show Hubble network flows for a session'
        'stop:Stop a running session'
        'cleanup:Remove old session logs'
        'check:Pre-flight workspace check'
        'status:Show cluster and sandbox status'
        'install:Install/configure sandbox prerequisites (cluster, CNI, gVisor)'
        'uninstall:Tear down the sandbox cluster and host artifacts'
        'upgrade:Move pinned infra components (k3s/Cilium/gVisor) forward'
        'setup:Alias of install (retained for compatibility)'
        'onboard:Stage host-side agent OAuth state for first-run convenience'
        'secret:Manage host-side secret store (injected per-session by profile)'
        'mask:Manage per-repo file masking (add/list masked_paths)'
        'vet:Attest a repo as cleared for agent use (signed tag; see run gate)'
        'profile:Create and manage launch profiles (save/list/show/delete)'
        'link:Link a git-backed team overlay and keep it pinned (status/sync/unlink)'
        'configure-network:Re-detect host interfaces and re-apply to Cilium (run after VPN reconnects)'
        'rebuild:Rebuild sandbox container image(s)'
        'version:Print version'
      )
      _describe 'sandbox command' commands
      ;;
    args)
      case "${line[1]}" in
        run)    _sandbox_run ;;
        resume) _sandbox_resume ;;
        allow)  _sandbox_allow ;;
        logs)   _sandbox_session_id ;;
        flows)  _sandbox_session_id ;;
        stop)   _sandbox_session_id ;;
        cleanup) _sandbox_cleanup ;;
        check)  _files -/ ;;
        rebuild) _sandbox_rebuild ;;
        install|setup) _sandbox_setup ;;
        uninstall) _sandbox_uninstall ;;
        upgrade) _sandbox_upgrade ;;
        onboard) _sandbox_onboard ;;
        secret) _sandbox_secret ;;
        mask)   _sandbox_mask ;;
        vet)    _sandbox_vet ;;
        profile) _sandbox_profile ;;
        link)   _sandbox_link ;;
      esac
      ;;
  esac
}

_sandbox_allow() {
  local log_dir="${SANDBOX_LOGS_DIR:-${HOME}/.sandbox/logs}"
  local sessions=()
  if [[ -d "${log_dir}" ]]; then
    for d in "${log_dir}"/ses-*/; do
      [[ -d "${d}" ]] && sessions+=("$(basename "${d}")")
    done
  fi
  _arguments \
    '*--add-domain[Domain to add to the running session allowlist]:domain:' \
    '--help[Show help]' \
    "1:session id:(${sessions[*]})"
}

_sandbox_secret() {
  local secrets_dir="${SANDBOX_SECRETS_DIR:-${HOME}/.sandbox/secrets}"
  local stored=()
  if [[ -d "${secrets_dir}" ]]; then
    stored=(${(f)"$(cd "${secrets_dir}" && ls -1 2>/dev/null)"})
  fi

  if (( CURRENT == 2 )); then
    _values 'subcommand' \
      'set[Store a secret value (reads stdin or --from-file)]' \
      'list[List stored secret names with sizes/mtimes (values not shown)]' \
      'delete[Remove a secret from the store]'
    return
  fi

  case "${words[2]}" in
    set)
      _arguments \
        '--from-file[Read value from a file instead of stdin]:file:_files' \
        '--help[Show help]' \
        ':secret name:'
      ;;
    delete|rm|remove)
      _values 'secret name' "${stored[@]}"
      ;;
  esac
}

_sandbox_mask() {
  if (( CURRENT == 2 )); then
    _values 'subcommand' \
      'add[Add path(s) to a repo''s masked_paths]' \
      'list[Show built-in + configured masked paths for a repo]'
    return
  fi

  case "${words[2]}" in
    add)
      _arguments \
        '--repo[Repository whose .sandbox/config.yaml to update]:directory:_files -/' \
        '--help[Show help]' \
        '*:relative path:_files'
      ;;
    list)
      _arguments \
        '--repo[Repository to inspect]:directory:_files -/' \
        '--help[Show help]'
      ;;
  esac
}

_sandbox_profile() {
  local pdir="${HOME}/.sandbox/profiles"
  local pnames=()
  if [[ -d "${pdir}" ]]; then
    pnames=(${(f)"$(cd "${pdir}" && ls -1 *.yaml(N) 2>/dev/null | sed 's/\.yaml$//')"})
  fi

  if (( CURRENT == 2 )); then
    _values 'subcommand' \
      'save[Generate ~/.sandbox/profiles/<name>.yaml from run-style flags]' \
      'list[List user and overlay profiles]' \
      'show[Print a profile YAML]' \
      'delete[Remove one of your profiles]'
    return
  fi

  case "${words[2]}" in
    save)
      _arguments \
        '--tier[Isolation tier (required)]:tier:(1 2 3)' \
        '--agent[Agent to pin (optional)]:agent:(claude codex opencode copilot)' \
        '--repo[Default workspace repository]:directory:_files -/' \
        '*--allow-domain[Extra allowed egress domain]:domain:' \
        '--name[Profile name (default: derived from repo + agent)]:name:' \
        '--force[Overwrite an existing profile]' \
        '--dry-run[Print the YAML instead of writing it]' \
        '--help[Show help]'
      ;;
    show|cat)
      _values 'profile name' "${pnames[@]}"
      ;;
    delete|rm|remove)
      _arguments \
        '--yes[Skip the confirmation prompt]' \
        "*:profile name:(${pnames[*]})"
      ;;
  esac
}

_sandbox_link() {
  if (( CURRENT == 2 )); then
    _values 'subcommand or git URL' \
      'status[Show the active link and whether it is behind its ref]' \
      'sync[Advance the pinned commit to the ref tip (or a new --ref)]' \
      'unlink[Clear the link pointer, optionally deleting the clone]'
    return
  fi

  case "${words[2]}" in
    sync)
      _arguments \
        '--ref[Change the pinned tag/branch/commit before advancing]:ref:' \
        '--help[Show help]'
      ;;
    unlink)
      _arguments \
        '--keep-clone[Leave the cloned directory on disk]' \
        '--yes[Skip the confirmation prompt]' \
        '--help[Show help]'
      ;;
    status) ;;
    *)
      _arguments \
        '--name[Directory name under ~/.sandbox/overlays/]:name:' \
        '--ref[Tag, branch, or commit to pin]:ref:' \
        '--help[Show help]'
      ;;
  esac
}

_sandbox_onboard() {
  _arguments \
    '--agent[Limit to one agent (default: all)]:agent:(claude codex opencode copilot all)' \
    '--skip-config[Do not write ~/.sandbox/config.yaml]' \
    '--dry-run[Report what would be done; copy nothing]' \
    '--force[Overwrite already-staged files]' \
    '--help[Show help]'
}

_sandbox_setup() {
  _arguments \
    '--pod-cidr[Pod network CIDR for Cilium IPAM]:cidr:' \
    '--service-cidr[Kubernetes Service CIDR]:cidr:' \
    '--apiserver-port[Kubernetes API server port (default 6443)]:port:' \
    '--dns[In-cluster DNS upstream IP(s), comma-separated (Linux only)]:ips:'
}

_sandbox_uninstall() {
  _arguments \
    '(--yes -y)'{--yes,-y}'[Skip all confirmation prompts]' \
    '--keep-logs[Preserve ~/.sandbox/logs (session audit records)]' \
    '--keep-images[Skip sandbox container image removal]' \
    '--keep-lima[macOS: delete the Lima VM but leave Lima itself installed]' \
    '--keep-kubetools[Leave Helm (and kubectl on Linux) on PATH]' \
    '--help[Show help]'
}

_sandbox_upgrade() {
  _arguments \
    '--k3s[Upgrade k3s]' \
    '--cilium[Upgrade Cilium]' \
    '--gvisor[Upgrade gVisor (runsc)]' \
    '--all[Upgrade all components (default when none given)]' \
    '--to-k3s[Override the k3s target version]:version:' \
    '--to-cilium[Override the Cilium chart target]:version:' \
    '--to-gvisor[Override the gVisor release id (YYYYMMDD.N)]:release:' \
    '--dry-run[Show the plan (pinned vs installed) and exit]' \
    '--force[Proceed even if sessions are running]' \
    '(--yes -y)'{--yes,-y}'[Skip the confirmation prompt]' \
    '--help[Show help]'
}

_sandbox_rebuild() {
  _arguments \
    '--agent[Image to rebuild]:image:(claude codex opencode copilot shell base all)' \
    '--tier3[Also rebuild matching *-infra image(s)]' \
    '--no-cache[Pass --no-cache to container builder]' \
    '--codex-version[Pin @openai/codex npm version]:version:' \
    '--opencode-version[Pin OpenCode release version]:version:' \
    '--copilot-version[Pin @github/copilot npm version]:version:' \
    '--help[Show help]'
}

_sandbox_run() {
  local pdir="${HOME}/.sandbox/profiles"
  local pnames=(1 2 3)
  if [[ -d "${pdir}" ]]; then
    pnames+=(${(f)"$(cd "${pdir}" && ls -1 *.yaml(N) 2>/dev/null | sed 's/\.yaml$//')"})
  fi
  _arguments \
    '--agent[Agent to run]:agent:(claude codex opencode copilot)' \
    '--tier[Isolation tier]:tier:(1 2 3)' \
    "--profile[Numeric (1|2|3) aliases --tier; named resolves a profile YAML]:profile:(${pnames[*]})" \
    '--repo[Workspace git repository]:directory:_files -/' \
    '--allow-domain[Extra allowed egress domain]:domain:' \
    '--base-url[opencode: OpenAI-compatible endpoint URL; overrides OPENCODE_BASE_URL]:url:' \
    '--infra-token[Path to infra token file]:file:_files' \
    '--infra-kubeconfig[Path to kubeconfig (tier 3); minified and mounted as Secret]:file:_files' \
    '--infra-kube-context[Context within --infra-kubeconfig to use]:context:' \
    '--allow-exec-plugin[Skip prompt when --infra-kubeconfig uses an exec credential plugin]' \
    '--infra-endpoint[Extra infra endpoint URL]:url:' \
    '--dry-run[Print manifests without applying]' \
    '--name[Human-readable session name]:name:' \
    '--keep-alive[Leave the pod running after disconnect (default: tear down)]' \
    '--i-accept-unmasked-secrets[Launch despite unmasked secrets (agent will see them)]' \
    '--i-accept-unvetted-repo[Launch despite an unvetted repo when vetting is required]' \
    '--help[Show help]'
}

_sandbox_vet() {
  _arguments \
    '--repo[Repository to attest (or inspect with --status)]:directory:_files -/' \
    '--status[Print the repo''s vetting state instead of signing]' \
    '--message[Tag message]:message:' \
    '--help[Show help]'
}

_sandbox_resume() {
  local log_dir="${SANDBOX_LOGS_DIR:-${HOME}/.sandbox/logs}"
  local sessions=()

  if [[ -d "${log_dir}" ]]; then
    for d in "${log_dir}"/ses-*/; do
      [[ -d "${d}" ]] && sessions+=("$(basename "${d}")")
    done
  fi

  _arguments \
    '--keep-alive[Leave the pod running after disconnect (default: tear down)]' \
    '--help[Show help]' \
    "1:session id:(${sessions[*]})"
}

_sandbox_session_id() {
  local log_dir="${SANDBOX_LOGS_DIR:-${HOME}/.sandbox/logs}"
  local sessions=()

  if [[ -d "${log_dir}" ]]; then
    for d in "${log_dir}"/ses-*/; do
      [[ -d "${d}" ]] && sessions+=("$(basename "${d}")")
    done
  fi

  _arguments "1:session id:(${sessions[*]})"
}

_sandbox_cleanup() {
  _arguments \
    '--older-than[Remove sessions older than N days]:days:(7 14 30 60 90 180)'
}

_sandbox "$@"
