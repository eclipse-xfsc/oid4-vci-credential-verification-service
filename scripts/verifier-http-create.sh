#!/usr/bin/env bash
set -euo pipefail
API_BASE="${API_BASE:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-demo_tenant}"; GROUP_ID="${GROUP_ID:-test}"
CLIENT_ID="${CLIENT_ID:?Set CLIENT_ID}"
POLICY_ID="${1:?Usage: verifier-http-create.sh PRESENTATION_POLICY_ID}"
TTL="${TTL:-3600}"; OUT="${OUTPUT_DIR:-./verifier-output}"
mkdir -p "$OUT"
body="$(jq -n --arg id "$POLICY_ID" --arg client "$CLIENT_ID" --argjson ttl "$TTL" '{presentationPolicyId:$id,clientId:$client,ttl:$ttl}')"
curl --fail-with-body -sS -X POST "${API_BASE%/}/v1/tenants/$TENANT_ID/internal/presentations/authorization" -H 'Content-Type: application/json' -H "x-groupid: $GROUP_ID" -d "$body" | tee "$OUT/authorization.json" | jq .
jq -r '.authorizationUrl' "$OUT/authorization.json" > "$OUT/oid4vp-link.txt"
jq -r '.presentationId' "$OUT/authorization.json" > "$OUT/presentation_id.txt"
