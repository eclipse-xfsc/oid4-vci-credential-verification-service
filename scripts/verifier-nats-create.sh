#!/usr/bin/env bash
set -euo pipefail
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"; NATS_SUBJECT="${NATS_SUBJECT:-presentation.request}"
TENANT_ID="${TENANT_ID:-demo_tenant}"; GROUP_ID="${GROUP_ID:-test}"
CLIENT_ID="${CLIENT_ID:?Set CLIENT_ID}"; TARGET_URI="${TARGET_URI:?Set TARGET_URI (hostname of verifier authorization endpoint)}"
REQUESTOBJECT_URI="${REQUESTOBJECT_URI:?Set REQUESTOBJECT_URI (hostname and base path of verifier proof endpoint)}"
REQUEST_ID="${REQUEST_ID:-$(python3 -c 'import uuid;print(uuid.uuid4())')}"; TTL="${TTL:-3600}"
POLICY_ID="${1:?Usage: verifier-nats-create.sh PRESENTATION_POLICY_ID}"
EVENT="$(jq -n --arg policy "$POLICY_ID" --arg tenant "$TENANT_ID" --arg group "$GROUP_ID" \
 --arg rid "$REQUEST_ID" --arg client "$CLIENT_ID" --arg target "$TARGET_URI" \
 --arg requestobj "$REQUESTOBJECT_URI" --argjson ttl "$TTL" \
 '{specversion:"1.0",id:$rid,source:"verifier-test",type:"verifier.presentation.authorization",datacontenttype:"application/json",data:{tenant_id:$tenant,group_id:$group,request_id:$rid,presentation_policy_id:$policy,client_id:$client,target_uri:$target,requestobject_uri:$requestobj,ttl:$ttl}}')"
echo "$EVENT" | jq . >&2
REPLY="$(nats req --server "$NATS_URL" --timeout "${NATS_TIMEOUT:-30s}" --raw "$NATS_SUBJECT" "$EVENT")"
echo "$REPLY" | jq .
if echo "$REPLY" | jq -e '.data.BaseReply.Error // .data.baseReply.error // .data.error' >/dev/null; then exit 1; fi
