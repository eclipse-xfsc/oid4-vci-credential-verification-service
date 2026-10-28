#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "Usage: $0 PERMISSION_SET" >&2
  echo "Example: $0 mitgliedschaft" >&2
  exit 2
fi
PERMISSION_SET="$1"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_SUBJECT="${NATS_SUBJECT:-presentation.request}"
TENANT_ID="${TENANT_ID:-demo_tenant}"
GROUP_ID="${GROUP_ID:-test}"
REQUEST_ID="${REQUEST_ID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"
TTL="${TTL:-3600}"

EVENT="$(jq -n --arg policy "$PERMISSION_SET" --arg tenant "$TENANT_ID" --arg group "$GROUP_ID" \
  --arg rid "$REQUEST_ID" --argjson ttl "$TTL" \
  '{specversion:"1.0",id:$rid,source:"verifier-test",type:"verifier.presentation.authorization",datacontenttype:"application/json",data:{tenant_id:$tenant,group_id:$group,request_id:$rid,permission_set:$policy,ttl:$ttl}}')"

echo "$EVENT" | jq . >&2
REPLY="$(nats req --server "$NATS_URL" --timeout "${NATS_TIMEOUT:-30s}" --raw "$NATS_SUBJECT" "$EVENT")"
echo "$REPLY" | jq .
if echo "$REPLY" | jq -e '.data.BaseReply.Error // .data.baseReply.error // .data.error' >/dev/null; then
  exit 1
fi
