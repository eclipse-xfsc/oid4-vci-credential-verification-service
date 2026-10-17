#!/usr/bin/env bash
set -euo pipefail

# Web-Wallet / manueller Consent: HTTP Intake, anschließend Inbox/Approve über HTTP.
API_BASE="${API_BASE:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-demo-tenant}"
GROUP_ID="${GROUP_ID:-demo-group}"
NAMESPACE="${NAMESPACE:-demo-tenant}"
KEY_GROUP="${KEY_GROUP:-demo-group}"
HOST="${HOST:-}"
TTL="${TTL:-3600}"
OID4VP_URL="${1:-${OID4VP_URL:-}}"

for cmd in curl jq python3; do command -v "$cmd" >/dev/null || { echo "ERROR: $cmd fehlt" >&2; exit 1; }; done
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

BASE="${API_BASE%/}/v1/${TENANT_ID}/api/presentation/presentations"
HEADERS=(-H 'Content-Type: application/json' -H "x-tenantid: $TENANT_ID" -H "x-groupid: $GROUP_ID" -H "x-namespace: $NAMESPACE" -H "x-group: $KEY_GROUP")
[[ -z "$HOST" ]] || HEADERS+=(-H "x-host: $HOST")
BODY="$(jq -n --arg url "$OID4VP_URL" --argjson ttl "$TTL" '{url:$url,consentMode:"manual",ttl:$ttl}')"
echo '== HTTP Intake (manual) =='
curl --fail-with-body -sS -X POST "${HEADERS[@]}" -d "$BODY" "$BASE" | jq .
echo
echo '== Offene Anfragen (Inbox) =='
curl --fail-with-body -sS "${HEADERS[@]}" "$BASE" | jq .
echo
echo "Details: GET $BASE/{presentationId}"
echo "Kandidaten: GET $BASE/{presentationId}/candidates"
echo "Bestätigung: POST $BASE/{presentationId}/approve"
echo "Ablehnung: POST $BASE/{presentationId}/reject"
