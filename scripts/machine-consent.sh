#!/usr/bin/env bash
set -euo pipefail

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_SUBJECT="${NATS_SUBJECT:-presentation.authorisation}"
NATS_TIMEOUT="${NATS_TIMEOUT:-130s}"
TENANT_ID="${TENANT_ID:-demo-tenant}"
GROUP_ID="${GROUP_ID:-demo-group}"
NAMESPACE="${NAMESPACE:-$TENANT_ID}"
KEY_GROUP="${KEY_GROUP:-$GROUP_ID}"
DID="${DID:-}"
KEY="${KEY:-}"
TTL="${TTL:-3600}"
REQUEST_ID="${REQUEST_ID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"
OID4VP_URL="${1:-${OID4VP_URL:-}}"

for cmd in nats jq python3; do
  command -v "$cmd" >/dev/null || { echo "ERROR: $cmd fehlt" >&2; exit 1; }
done
[[ -n "$OID4VP_URL" ]] || { echo "Usage: $0 'openid4vp://?...'" >&2; exit 1; }
[[ "$TTL" =~ ^[0-9]+$ ]] && (( TTL >= 1 && TTL <= 86400 )) || { echo 'ERROR: TTL muss 1..86400 sein' >&2; exit 1; }

python3 - "$OID4VP_URL" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qs
u = urlsplit(sys.argv[1])
if u.scheme != 'openid4vp' or u.netloc or u.fragment:
    sys.exit('ERROR: openid4vp://? erwartet')
p = parse_qs(u.query, keep_blank_values=True)
for k in ('client_id', 'request_uri'):
    if len(p.get(k, [])) != 1 or not p[k][0]:
        sys.exit(f'ERROR: {k} fehlt/mehrfach')
r = urlsplit(p['request_uri'][0])
if r.scheme != 'https' or not r.netloc:
    sys.exit('ERROR: request_uri muss HTTPS sein')
print('OID4VP-Link formal gültig')
PY

EVENT="$(jq -n \
  --arg id "$REQUEST_ID" --arg tenant "$TENANT_ID" --arg group "$GROUP_ID" \
  --arg url "$OID4VP_URL" --arg did "$DID" --arg key "$KEY" \
  --arg namespace "$NAMESPACE" --arg keyGroup "$KEY_GROUP" --argjson ttl "$TTL" \
  '{specversion:"1.0",id:$id,source:"xfsc-machine-agent",type:"verifier.presentation.authorization.remote",datacontenttype:"application/json",data:{tenant_id:$tenant,group_id:$group,request_id:$id,url:$url,consentMode:"auto",ttl:$ttl,did:$did,key:$key,namespace:$namespace,group:$keyGroup}}')"

echo '== NATS Authorization Request (auto) =='
echo "$EVENT" | jq .

if ! REPLY="$(nats req --server "$NATS_URL" --timeout "$NATS_TIMEOUT" --raw "$NATS_SUBJECT" "$EVENT")"; then
  echo 'ERROR: NATS Request fehlgeschlagen oder Timeout erreicht' >&2
  exit 1
fi

if ! echo "$REPLY" | jq -e '.data | type == "object"' >/dev/null 2>&1; then
  echo 'ERROR: Ungültige CloudEvent-Antwort:' >&2
  printf '%s\n' "$REPLY" >&2
  exit 1
fi

echo '== NATS Authorization Reply =='
echo "$REPLY" | jq .

REPLY_REQUEST_ID="$(echo "$REPLY" | jq -r '.data.requestId // .data.request_id // ""')"
if [[ "$REPLY_REQUEST_ID" != "$REQUEST_ID" ]]; then
  echo "ERROR: Request-ID stimmt nicht überein (erwartet: $REQUEST_ID, erhalten: $REPLY_REQUEST_ID)" >&2
  exit 1
fi

STATUS="$(echo "$REPLY" | jq -r '.data.status // "unknown"')"
case "$STATUS" in
  completed)
    echo "AutoConsent erfolgreich abgeschlossen (Presentation: $(echo "$REPLY" | jq -r '.data.presentationId // ""'))"
    ;;
  pending)
    echo 'Authorization Request gespeichert; Consent steht noch aus'
    ;;
  failed)
    echo "ERROR: $(echo "$REPLY" | jq -r '.data.error // "Unbekannter Fehler"')" >&2
    exit 1
    ;;
  *)
    echo "ERROR: Unbekannter Status: $STATUS" >&2
    exit 1
    ;;
esac
