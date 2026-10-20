#!/usr/bin/env bash
set -euo pipefail
TENANT_ID="${TENANT_ID:-demo_tenant}"; GROUP_ID="${GROUP_ID:?Set GROUP_ID}"; STATE="${1:?Usage: verifier-nats-get.sh presentation_id [output.json]}"
OUT="${2:-verified-presentation.json}"
EVENT="$(jq -n --arg tenant "$TENANT_ID" --arg group "$GROUP_ID" --arg id "$STATE" \
 '{specversion:"1.0",id:"verifier-result-get",source:"verifier-test",type:"verifier.presentation.result.get",datacontenttype:"application/json",data:{tenant_id:$tenant,group_id:$group,presentation_id:$id}}')"
nats req --server "${NATS_URL:-nats://127.0.0.1:4222}" --timeout "${NATS_TIMEOUT:-30s}" --raw "${NATS_SUBJECT:-request}" "$EVENT" | tee "$OUT" | jq .
if jq -e '.data.error // empty' "$OUT" >/dev/null; then exit 1; fi
