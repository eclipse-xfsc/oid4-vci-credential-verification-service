#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
  echo "Usage: $0 PRESENTATION_POLICY_ID PUBLIC_ORIGIN" >&2
  echo "Example: $0 my-policy https://tenant.example.org" >&2
  exit 2
fi
POLICY_ID="$1"
PUBLIC_ORIGIN="$2"
if [[ ! "$PUBLIC_ORIGIN" =~ ^https://[^/?#]+/?$ ]]; then
  echo "PUBLIC_ORIGIN must be an HTTPS origin without path, query or fragment" >&2
  exit 2
fi
PUBLIC_ORIGIN="${PUBLIC_ORIGIN%/}"

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_SUBJECT="${NATS_SUBJECT:-presentation.request}"
TENANT_ID="${TENANT_ID:-demo_tenant}"
GROUP_ID="${GROUP_ID:-test}"
CLIENT_ID="${CLIENT_ID:?Set CLIENT_ID}"
REQUEST_ID="${REQUEST_ID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"
TTL="${TTL:-3600}"

# Existing requestor.buildUri() expects scheme-less host + path for these fields.
PUBLIC_HOST="${PUBLIC_ORIGIN#https://}"
TARGET_URI="${PUBLIC_HOST}/api/verifier/presentation"
REQUESTOBJECT_URI="${PUBLIC_HOST}/api/verifier/presentation/proof"

EVENT="$(jq -n --arg policy "$POLICY_ID" --arg tenant "$TENANT_ID" --arg group "$GROUP_ID" \
  --arg rid "$REQUEST_ID" --arg client "$CLIENT_ID" --arg target "$TARGET_URI" \
  --arg requestobj "$REQUESTOBJECT_URI" --argjson ttl "$TTL" \
  '{specversion:"1.0",id:$rid,source:"verifier-test",type:"verifier.presentation.authorization",datacontenttype:"application/json",data:{tenant_id:$tenant,group_id:$group,request_id:$rid,presentation_policy_id:$policy,client_id:$client,target_uri:$target,requestobject_uri:$requestobj,ttl:$ttl}}')"

echo "$EVENT" | jq . >&2
REPLY="$(nats req --server "$NATS_URL" --timeout "${NATS_TIMEOUT:-30s}" --raw "$NATS_SUBJECT" "$EVENT")"
echo "$REPLY" | jq .
if echo "$REPLY" | jq -e '.data.BaseReply.Error // .data.baseReply.error // .data.error' >/dev/null; then
  exit 1
fi
