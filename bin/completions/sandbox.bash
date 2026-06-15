#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# bin/completions/sandbox.bash — Bash completion for sandbox CLI
#
# Source in your .bashrc:
#   source /path/to/ai-agent-sandboxes/bin/completions/sandbox.bash

_sandbox_complete() {
  local cur prev words cword
  _init_completion || return

  local commands="run resume allow list logs flows stop cleanup check status setup onboard secret profile configure-network rebuild version"
  local run_opts="--agent --tier --profile --repo --allow-domain --base-url --infra-token --infra-kubeconfig --infra-kube-context --allow-exec-plugin --infra-endpoint --dry-run --name --keep-alive --help"
  local rebuild_opts="--agent --tier3 --no-cache --codex-version --opencode-version --help"
  local setup_opts="--pod-cidr --service-cidr --apiserver-port"
  local onboard_opts="--agent --skip-config --dry-run --force --help"
  local secret_subs="set list delete"
  local secret_set_opts="--from-file --help"
  local profile_subs="save list show delete"
  local profile_save_opts="--tier --agent --repo --allow-domain --name --force --dry-run --help"
  local agents="claude codex opencode"
  local onboard_agents="claude codex opencode all"
  local rebuild_agents="claude codex opencode shell base all"
  local tiers="1 2 3"

  if [[ "${cword}" -eq 1 ]]; then
    # Complete subcommand
    # shellcheck disable=SC2207
    COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
    return
  fi

  local command="${words[1]}"

  case "${command}" in
    run)
      case "${prev}" in
        --agent)
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "${agents}" -- "${cur}"))
          return ;;
        --tier)
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "${tiers}" -- "${cur}"))
          return ;;
        --profile)
          # Numeric tier aliases + saved profile names from the user dir.
          local _pdir="${HOME}/.sandbox/profiles" _pnames=""
          [[ -d "${_pdir}" ]] && _pnames="$(cd "${_pdir}" && ls -1 ./*.yaml 2>/dev/null | sed 's#.*/##;s/\.yaml$//' || true)"
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "1 2 3 ${_pnames}" -- "${cur}"))
          return ;;
        --repo|--infra-token|--infra-kubeconfig)
          # File/directory completion
          _filedir
          return ;;
        --allow-domain|--base-url|--infra-endpoint|--infra-kube-context|--name)
          # No completion for free-form values
          return ;;
      esac
      # Complete run options
      if [[ "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${run_opts}" -- "${cur}"))
      fi
      ;;
    logs|flows|stop|resume)
      # Complete session IDs from log directory; resume also accepts --keep-alive
      if [[ "${command}" == "resume" && "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "--keep-alive --help" -- "${cur}"))
        return
      fi
      local log_dir="${SANDBOX_LOGS_DIR:-${HOME}/.sandbox/logs}"
      if [[ -d "${log_dir}" ]]; then
        local sessions=()
        for d in "${log_dir}"/ses-*/; do
          [[ -d "${d}" ]] && sessions+=("$(basename "${d}")")
        done
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${sessions[*]}" -- "${cur}"))
      fi
      ;;
    cleanup)
      if [[ "${prev}" == --older-than ]]; then
        # Suggest common values
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "7 14 30 60 90 180" -- "${cur}"))
      elif [[ "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "--older-than" -- "${cur}"))
      fi
      ;;
    check)
      # File/directory completion for workspace path
      _filedir -d
      ;;
    setup)
      if [[ "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${setup_opts}" -- "${cur}"))
      fi
      ;;
    onboard)
      case "${prev}" in
        --agent)
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "${onboard_agents}" -- "${cur}"))
          return ;;
      esac
      if [[ "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${onboard_opts}" -- "${cur}"))
      fi
      ;;
    allow)
      # First positional is the session id; complete from ~/.sandbox/logs/.
      if [[ "${cword}" -eq 2 ]]; then
        local log_dir="${SANDBOX_LOGS_DIR:-${HOME}/.sandbox/logs}"
        local sessions=""
        if [[ -d "${log_dir}" ]]; then
          sessions="$(cd "${log_dir}" && ls -1d ses-* 2>/dev/null || true)"
        fi
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${sessions}" -- "${cur}"))
        return
      fi
      if [[ "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "--add-domain --help" -- "${cur}"))
      fi
      ;;
    secret)
      # First positional after 'secret' is the sub-subcommand.
      if [[ "${cword}" -eq 2 ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${secret_subs}" -- "${cur}"))
        return
      fi
      local secret_sub="${words[2]}"
      case "${secret_sub}" in
        set)
          if [[ "${prev}" == "--from-file" ]]; then
            _filedir
            return
          fi
          if [[ "${cur}" == --* ]]; then
            # shellcheck disable=SC2207
            COMPREPLY=($(compgen -W "${secret_set_opts}" -- "${cur}"))
          fi
          ;;
        delete|rm|remove|list)
          # Complete with names from the host-side store.
          local secrets_dir="${SANDBOX_SECRETS_DIR:-${HOME}/.sandbox/secrets}"
          local stored=""
          if [[ -d "${secrets_dir}" ]]; then
            stored="$(cd "${secrets_dir}" && ls -1 2>/dev/null || true)"
          fi
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "${stored}" -- "${cur}"))
          ;;
      esac
      ;;
    profile)
      # First positional after 'profile' is the sub-subcommand.
      if [[ "${cword}" -eq 2 ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${profile_subs}" -- "${cur}"))
        return
      fi
      local profile_sub="${words[2]}"
      case "${profile_sub}" in
        save)
          case "${prev}" in
            --agent) COMPREPLY=($(compgen -W "${agents}" -- "${cur}")); return ;;
            --tier)  COMPREPLY=($(compgen -W "${tiers}" -- "${cur}")); return ;;
            --repo)  _filedir -d; return ;;
            --allow-domain|--name) return ;;
          esac
          if [[ "${cur}" == --* ]]; then
            # shellcheck disable=SC2207
            COMPREPLY=($(compgen -W "${profile_save_opts}" -- "${cur}"))
          fi
          ;;
        show|cat|delete|rm|remove)
          # Complete with saved profile names from the user dir.
          local pdir="${HOME}/.sandbox/profiles" pnames=""
          [[ -d "${pdir}" ]] && pnames="$(cd "${pdir}" && ls -1 ./*.yaml 2>/dev/null | sed 's#.*/##;s/\.yaml$//' || true)"
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "${pnames} --yes" -- "${cur}"))
          ;;
      esac
      ;;
    rebuild)
      case "${prev}" in
        --agent)
          # shellcheck disable=SC2207
          COMPREPLY=($(compgen -W "${rebuild_agents}" -- "${cur}"))
          return ;;
        --codex-version|--opencode-version)
          return ;;
      esac
      if [[ "${cur}" == --* ]]; then
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${rebuild_opts}" -- "${cur}"))
      fi
      ;;
  esac
}

complete -F _sandbox_complete sandbox
