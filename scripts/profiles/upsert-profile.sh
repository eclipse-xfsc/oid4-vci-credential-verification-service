#!/usr/bin/env bash
set -euo pipefail
# Usage: BASE_URL=https://... TENANT_ID=x GROUP_ID=y PROFILE_TYPE=verifier INTERACTION_TYPE=human PROFILE_FILE=profile.json [JWT=...] ./scripts/profiles/upsert-profile.sh
: "${BASE_URL:?}" "${TENANT_ID:?}" "${GROUP_ID:?}" "${PROFILE_TYPE:?}" "${INTERACTION_TYPE:?}" "${PROFILE_FILE:?}"
args=(-sS -X PUT -H 'Content-Type: application/json' -H "x-groupid: ${GROUP_ID}" --data-binary "@${PROFILE_FILE}")
if [[ -n "${JWT:-}" ]]; then args+=(-H "Authorization: Bearer ${JWT}"); fi
curl "${args[@]}" "${BASE_URL%/}/v1/tenants/${TENANT_ID}/internal/presentation-profiles/${PROFILE_TYPE}/${INTERACTION_TYPE}"
printf '\n'
