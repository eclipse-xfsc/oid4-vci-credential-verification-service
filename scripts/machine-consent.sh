#!/usr/bin/env bash
set -euo pipefail

# Machine-to-Machine: NATS Intake mit consentMode=auto.
# Der Service fragt anschließend selbst den Policy Client ab.
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_SUBJECT="${NATS_SUBJECT:-presentation.authorisation}"
NATS_REPLY_SUBJECT="${NATS_REPLY_SUBJECT:-}"
TENANT_ID="${TENANT_ID:-demo-tenant}"
GROUP_ID="${GROUP_ID:-demo-group}"
NAMESPACE="${NAMESPACE:-$TENANT_ID}"
KEY_GROUP="${KEY_GROUP:-$GROUP_ID}"
DID="${DID:-}"
KEY="${KEY:-}"
TTL="${TTL:-3600}"
REQUEST_ID="${REQUEST_ID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"
OID4VP_URL="${1:-${OID4VP_URL:-}}"

for cmd in nats jq python3; do command -v "$cmd" >/dev/null || { echo "ERROR: $cmd fehlt" >&2; exit 1; }; done
[[ -n "$OID4VP_URL" ]] || { echo "Usage: $0 'openid4vp://?...'" >&2; exit 1; }
python3 - "$OID4VP_URL" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qs
u = urlsplit(sys.argv[1])
if u.scheme != 'openid4vp': sys.exit('ERROR: openid4vp:// erwartet')
p = parse_qs(u.query, keep_blank_values=True)
for k in ('client_id', 'request_uri'):
    if len(p.get(k, [])) != 1 or not p[k][0]: sys.exit(f'ERROR: {k} fehlt/mehrfach')
r = urlsplit(p['request_uri'][0])
if r.scheme != 'https' or not r.netloc: sys.exit('ERROR: request_uri muss HTTPS sein')
print('OID4VP-Link formal gültig')
PY

EVENT="$(jq -n \
 --arg id "$REQUEST_ID" --arg tenant "$TENANT_ID" --arg group "$GROUP_ID" \
 --arg url "$OID4VP_URL" --arg did "$DID" --arg key "$KEY" \
 --arg namespace "$NAMESPACE" --arg keyGroup "$KEY_GROUP" --argjson ttl "$TTL" \
 '{specversion:"1.0",id:$id,source:"xfsc-machine-agent",type:"verifier.presentation.authorization.remote",datacontenttype:"application/json",data:{tenant_id:$tenant,group_id:$group,request_id:$id,url:$url,consentMode:"auto",ttl:$ttl,did:$did,key:$key,namespace:$namespace,group:$keyGroup}}')"
echo '== NATS Authorization (auto) =='
echo "$EVENT" | jq .
nats pub --server "$NATS_URL" "$NATS_SUBJECT" "$EVENT"
echo 'CloudEvent veröffentlicht; Policy-Entscheidung und Fulfillment erfolgen asynchron.'
if [[ -n "$NATS_REPLY_SUBJECT" ]]; then
  echo "Antworten beobachten: nats sub --server '$NATS_URL' '$NATS_REPLY_SUBJECT'"
fi
