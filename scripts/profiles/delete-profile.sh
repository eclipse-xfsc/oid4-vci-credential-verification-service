#!/usr/bin/env bash
set -euo pipefail
: "${BASE_URL:?}" "${TENANT_ID:?}" "${GROUP_ID:?}" "${PROFILE_TYPE:?}" "${INTERACTION_TYPE:?}"
args=(-fsS -X DELETE -H "x-groupid: ${GROUP_ID}")
if [[ -n "${JWT:-}" ]]; then args+=(-H "Authorization: Bearer ${JWT}"); fi
curl "${args[@]}" -o /dev/null -w 'HTTP %{http_code}\n' "${BASE_URL%/}/v1/tenants/${TENANT_ID}/internal/presentation-profiles/${PROFILE_TYPE}/${INTERACTION_TYPE}"
