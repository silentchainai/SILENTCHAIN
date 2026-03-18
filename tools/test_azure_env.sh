#!/usr/bin/env bash

set -u

ENV_FILE="${1:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "STATUS: ERROR"
  echo "DETAIL: Missing env file at $ENV_FILE"
  exit 1
fi

echo "INFO: Using env file: $ENV_FILE"

# Export values from env file for this process only.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

overall_ok=true

require_var() {
  local key="$1"
  local value="${!key:-}"
  if [[ -z "${value// }" ]]; then
    echo "VAR:$key=missing"
    overall_ok=false
  else
    echo "VAR:$key=present"
  fi
}

require_var "AZURE_OPENAI_ENDPOINT"
require_var "AZURE_OPENAI_API_KEY"
require_var "AZURE_OPENAI_DEPLOYMENT"

api_version="${OPENAI_API_VERSION:-${AZURE_OPENAI_API_VERSION:-2024-06-01}}"
echo "VAR:API_VERSION=$api_version"

endpoint="${AZURE_OPENAI_ENDPOINT:-}"
if [[ -n "$endpoint" ]]; then
  endpoint="${endpoint%%\?*}"
  endpoint="${endpoint%/}"

  if [[ "$endpoint" =~ ^https:// ]]; then
    echo "CHECK:endpoint_scheme=ok"
  else
    echo "CHECK:endpoint_scheme=invalid"
    overall_ok=false
  fi

  if [[ "$endpoint" == *".openai.azure.com"* ]]; then
    echo "CHECK:endpoint_domain=ok"
  else
    echo "CHECK:endpoint_domain=unexpected"
  fi
fi

if [[ -n "${AZURE_OPENAI_ENDPOINT:-}" && -n "${AZURE_OPENAI_API_KEY:-}" ]]; then
  endpoint_no_query="${AZURE_OPENAI_ENDPOINT%%\?*}"
  endpoint_no_query="${endpoint_no_query%/}"

  resource_root="$endpoint_no_query"
  if [[ "$resource_root" == *"/openai/deployments/"* ]]; then
    resource_root="${resource_root%%/openai/deployments/*}"
  elif [[ "$resource_root" == *"/openai/v1"* ]]; then
    resource_root="${resource_root%%/openai/v1*}"
  fi

  deployments_url="${resource_root}/openai/deployments?api-version=${api_version}"
  tmp_body="$(mktemp)"

  http_code="$(curl -sS -o "$tmp_body" -w "%{http_code}" \
    -H "api-key: ${AZURE_OPENAI_API_KEY}" \
    -H "Content-Type: application/json" \
    "$deployments_url" || true)"

  echo "CHECK:probe_http_code=$http_code"

  deployments_ok=false
  deployments_failed=false

  case "$http_code" in
    200)
      if grep -q '"data"' "$tmp_body"; then
        echo "CHECK:probe_result=ok"
        deployments_ok=true
      else
        echo "CHECK:probe_result=ok_but_unexpected_payload"
        deployments_ok=true
      fi
      ;;
    401|403)
      echo "CHECK:probe_result=auth_failed"
      deployments_failed=true
      ;;
    404)
      echo "CHECK:probe_result=endpoint_or_api_version_invalid"
      deployments_failed=true
      ;;
    000)
      echo "CHECK:probe_result=network_or_dns_failed"
      deployments_failed=true
      ;;
    *)
      echo "CHECK:probe_result=unexpected_status"
      deployments_failed=true
      ;;
  esac

  # Also validate the deployment chat endpoint used by the extension.
  deployment_chat_url="${resource_root}/openai/deployments/${AZURE_OPENAI_DEPLOYMENT}/chat/completions?api-version=${api_version}"
  chat_code="$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "api-key: ${AZURE_OPENAI_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"ping"}],"max_tokens":1,"temperature":0.0}' \
    "$deployment_chat_url" || true)"

  echo "CHECK:chat_probe_http_code=$chat_code"
  chat_ok=false
  case "$chat_code" in
    200)
      echo "CHECK:chat_probe_result=ok"
      chat_ok=true
      ;;
    401|403)
      echo "CHECK:chat_probe_result=auth_failed"
      overall_ok=false
      ;;
    404)
      echo "CHECK:chat_probe_result=deployment_or_endpoint_invalid"
      overall_ok=false
      ;;
    429)
      echo "CHECK:chat_probe_result=rate_limited_but_reachable"
      ;;
    *)
      echo "CHECK:chat_probe_result=unexpected_status"
      overall_ok=false
      ;;
  esac

  # Chat endpoint is authoritative for real extension behavior.
  if [[ "$chat_ok" == true ]]; then
    if [[ "$deployments_failed" == true ]]; then
      echo "INFO: Deployments-list probe failed, but chat endpoint works; treating config as valid"
    fi
  elif [[ "$deployments_ok" == false ]]; then
    overall_ok=false
  fi

  rm -f "$tmp_body"
fi

if [[ "$overall_ok" == true ]]; then
  echo "STATUS: VALID"
  exit 0
else
  echo "STATUS: INVALID"
  exit 2
fi
