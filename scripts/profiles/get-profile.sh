#!/usr/bin/env bash
set -euo pipefail
: "${BASE_URL:?}" "${TENANT_ID:?}" "${GROUP_ID:?}" "${PROFILE_TYPE:?}" "${INTERACTION_TYPE:?}"
args=(-fsS -H "x-groupid: ${GROUP_ID}")
if [[ -n "${JWT:-}" ]]; then args+=(-H "Authorization: Bearer ${JWT}"); fi
curl "${args[@]}" "${BASE_URL%/}/v1/tenants/${TENANT_ID}/internal/presentation-profiles/${PROFILE_TYPE}/${INTERACTION_TYPE}"
printf '\n'
