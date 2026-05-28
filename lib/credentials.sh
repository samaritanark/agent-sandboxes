#!/usr/bin/env bash
# lib/credentials.sh — Credential handling and secret creation
set -euo pipefail

# HOST_ENV_BLOCKLIST — host env vars that must NEVER be passed to pods
HOST_ENV_BLOCKLIST=(
  "KUBECONFIG"
  "SSH_AUTH_SOCK"
  "DOCKER_HOST"
  "KUBERNETES_SERVICE_HOST"
  "KUBERNETES_SERVICE_PORT"
)

# HOST_ENV_BLOCKLIST_PATTERNS — prefix patterns (all vars matching blocked)
HOST_ENV_BLOCKLIST_PATTERNS=(
  "OS_"
  "AWS_"
  "GOOGLE_"
  "AZURE_"
  "TELEPORT_"
  "TSH_"
  "ANTHROPIC_"
  "OPENAI_"
)

# check_host_env_not_leaked — verify dangerous host vars are not set in current shell
# that could bleed through. This is advisory; actual enforcement is pod spec (no envFrom host).
check_host_env_not_leaked() {
  local agent="$1"
  local warnings=0

  for var in "${HOST_ENV_BLOCKLIST[@]}"; do
    if [[ -n "${!var:-}" ]]; then
      echo "  WARN: Host env var '${var}' is set. It will NOT be passed to the sandbox." >&2
      (( warnings++ )) || true
    fi
  done

  for prefix in "${HOST_ENV_BLOCKLIST_PATTERNS[@]}"; do
    while IFS= read -r line; do
      local var_name="${line%%=*}"
      # Skip OPENCODE_API_KEY which is intentional for opencode agent
      if [[ "${var_name}" == "OPENCODE_API_KEY" ]] && [[ "${agent}" == "opencode" ]]; then
        continue
      fi
      echo "  WARN: Host env var '${var_name}' is set. It will NOT be passed to the sandbox." >&2
      (( warnings++ )) || true
    done < <(env | grep "^${prefix}" || true)
  done

  if [[ "${warnings}" -gt 0 ]]; then
    echo "  ${warnings} host env var(s) detected that will be blocked."
  fi
}

# create_opencode_apikey_secret — create K8s Secret for opencode API key +
# OPENCODE_CONFIG_CONTENT.  Queries the configured OpenAI-compatible endpoint
# for its model list so the config only exposes the operator's models inside
# the sandbox.
create_opencode_apikey_secret() {
  local session_id="$1"
  local api_key="${OPENCODE_API_KEY:-}"
  local base_url="${OPENCODE_BASE_URL:-}"

  if [[ -z "${api_key}" ]]; then
    echo "ERROR: OPENCODE_API_KEY not set in host environment. Cannot create secret." >&2
    echo " " >&2
    exit 1
  fi

  if [[ -z "${base_url}" ]]; then
    echo "ERROR: OPENCODE_BASE_URL not set in host environment." >&2
    echo "  Set it to the URL of any OpenAI-compatible endpoint, e.g." >&2
    echo "    export OPENCODE_BASE_URL=https://api.openai.com/v1" >&2
    echo "    export OPENCODE_BASE_URL=https://vllm.example.com/v1" >&2
    exit 1
  fi

  echo "  Fetching model list from ${base_url}..."
  local models_json
  if ! models_json="$(curl -fsSL --max-time 10 \
    -H "Authorization: Bearer ${api_key}" \
    "${base_url}/models" 2>&1)"; then
    echo "ERROR: Could not fetch model list from ${base_url}/models:" >&2
    echo "  ${models_json}" >&2
    echo "  Verify the URL has scheme + path (typically https://host/v1) and" >&2
    echo "  that OPENCODE_API_KEY is valid for the endpoint." >&2
    exit 1
  fi

  # Parse the OpenAI /models response into the { "<id>": { ... }, ... } shape
  # that OpenCode's openai-compatible provider config expects. _MODELS_JSON is
  # passed via env to avoid shell-quoting the JSON payload.
  local models_obj
  models_obj="$(_MODELS_JSON="${models_json}" python3 - <<'PYEOF'
import json, os
raw = os.environ.get("_MODELS_JSON", "{}")
try:
    d = json.loads(raw)
    models = {}
    for m in d.get("data", []):
        mid = m.get("id", "")
        if mid:
            models[mid] = {"name": mid, "limit": {"context": 131072, "output": 8192}}
    print(json.dumps(models))
except Exception:
    print("{}")
PYEOF
)"

  local model_count
  model_count="$(echo "${models_obj}" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)"
  if [[ "${model_count}" -eq 0 ]]; then
    echo "ERROR: ${base_url}/models returned no usable models." >&2
    echo "  The endpoint responded but its model list is empty or malformed." >&2
    echo "  Verify the URL is the OpenAI-compatible base (typically ends in /v1)" >&2
    echo "  and that OPENCODE_API_KEY has permission to list models." >&2
    exit 1
  fi
  echo "  Found ${model_count} model(s) on endpoint."

  # Build OPENCODE_CONFIG_CONTENT — restricts the TUI to only the configured
  # endpoint's models (whatever OPENCODE_BASE_URL points at).
  local config_content
  config_content="$(_MODELS="${models_obj}" _BASE_URL="${base_url}" python3 - <<'PYEOF'
import json, os
config = {
    "enabled_providers": ["openai-compat"],
    "provider": {
        "openai-compat": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "OpenAI-compatible endpoint",
            "options": {
                "baseURL": os.environ["_BASE_URL"],
                "apiKey": "{env:OPENAI_API_KEY}"
            },
            "models": json.loads(os.environ.get("_MODELS", "{}"))
        }
    }
}
print(json.dumps(config))
PYEOF
)"

  local secret_name="opencode-apikey-${session_id}"

  kubectl create secret generic "${secret_name}" \
    --namespace "${SANDBOX_NAMESPACE}" \
    --from-literal="OPENAI_API_KEY=${api_key}" \
    --from-literal="OPENCODE_CONFIG_CONTENT=${config_content}" \
    --dry-run=client -o yaml | kubectl apply -f - 2>&1

  echo "  Created API key secret: ${secret_name}"
  # Unset from shell so it doesn't linger
  unset OPENCODE_API_KEY || true
}

# delete_opencode_apikey_secret — remove API key secret after session
delete_opencode_apikey_secret() {
  local session_id="$1"
  local secret_name="opencode-apikey-${session_id}"

  kubectl delete secret -n "${SANDBOX_NAMESPACE}" \
    "${secret_name}" --ignore-not-found=true 2>&1 || true
}
