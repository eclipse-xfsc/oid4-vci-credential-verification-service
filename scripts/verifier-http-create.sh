#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "Usage: $0 PERMISSION_SET" >&2
  echo "Example: $0 mitgliedschaft" >&2
  exit 2
fi
PERMISSION_SET="$1"
API_BASE="${API_BASE:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-demo_tenant}"
GROUP_ID="${GROUP_ID:-test}"
TTL="${TTL:-3600}"
OUT="${OUTPUT_DIR:-./verifier-output}"
mkdir -p "$OUT"

body="$(jq -n --arg id "$PERMISSION_SET" --argjson ttl "$TTL" \
  '{permissionSet:$id,ttl:$ttl}')"

curl --fail-with-body -sS -X POST \
  "${API_BASE%/}/v1/tenants/$TENANT_ID/internal/presentations/authorization" \
  -H 'Content-Type: application/json' \
  -H "x-groupid: $GROUP_ID" \
  -d "$body" | tee "$OUT/authorization.json" | jq .

jq -er '.authorizationUrl' "$OUT/authorization.json" > "$OUT/oid4vp-link.txt"
jq -er '.presentationId' "$OUT/authorization.json" > "$OUT/presentation_id.txt"
