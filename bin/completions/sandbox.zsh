#compdef sandbox
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
        'setup:Install/configure sandbox prerequisites'
        'onboard:Stage host-side agent OAuth state for first-run convenience'
        'secret:Manage host-side secret store (injected per-session by profile)'
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
        setup)  _sandbox_setup ;;
        onboard) _sandbox_onboard ;;
        secret) _sandbox_secret ;;
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

_sandbox_onboard() {
  _arguments \
    '--agent[Limit to one agent (default: all)]:agent:(claude codex opencode all)' \
    '--skip-config[Do not write ~/.sandbox/config.yaml]' \
    '--dry-run[Report what would be done; copy nothing]' \
    '--force[Overwrite already-staged files]' \
    '--help[Show help]'
}

_sandbox_setup() {
  _arguments \
    '--pod-cidr[Pod network CIDR for Cilium IPAM]:cidr:' \
    '--service-cidr[Kubernetes Service CIDR]:cidr:' \
    '--apiserver-port[Kubernetes API server port (default 6443)]:port:'
}

_sandbox_rebuild() {
  _arguments \
    '--agent[Image to rebuild]:image:(claude codex opencode shell base all)' \
    '--tier3[Also rebuild matching *-infra image(s)]' \
    '--no-cache[Pass --no-cache to container builder]' \
    '--codex-version[Pin @openai/codex npm version]:version:' \
    '--opencode-version[Pin OpenCode release version]:version:' \
    '--help[Show help]'
}

_sandbox_run() {
  _arguments \
    '--agent[Agent to run]:agent:(claude codex opencode)' \
    '--tier[Isolation tier]:tier:(1 2 3)' \
    '--profile[Numeric (1|2|3) aliases --tier; named resolves a profile YAML]:profile:' \
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
