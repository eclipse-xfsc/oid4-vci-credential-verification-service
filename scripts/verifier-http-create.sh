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

API_BASE="${API_BASE:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-demo_tenant}"
GROUP_ID="${GROUP_ID:-test}"
DID="${DID:?Set DID (e.g. did:web:tenant.example.org)}"
if [[ ! "$DID" =~ ^did:[a-z0-9]+:.+ ]] || [[ "$DID" =~ [[:space:]\?\#] ]] || [[ "$DID" == *: ]]; then
  echo "DID must be a valid DID" >&2
  exit 2
fi
CLIENT_ID="decentralized_identifier:${DID}"
TTL="${TTL:-3600}"
OUT="${OUTPUT_DIR:-./verifier-output}"
mkdir -p "$OUT"

body="$(jq -n --arg id "$POLICY_ID" --argjson ttl "$TTL" \
  '{presentationPolicyId:$id,ttl:$ttl}')"

curl --fail-with-body -sS -X POST \
  "${API_BASE%/}/v1/tenants/$TENANT_ID/internal/presentations/authorization" \
  -H 'Content-Type: application/json' \
  -H "x-groupid: $GROUP_ID" \
  -H "x-origin: $PUBLIC_ORIGIN" \
  -H "x-did: $DID" \
  -d "$body" | tee "$OUT/authorization.json" | jq .

jq -er '.authorizationUrl' "$OUT/authorization.json" > "$OUT/oid4vp-link.txt"
jq -er '.presentationId' "$OUT/authorization.json" > "$OUT/presentation_id.txt"
