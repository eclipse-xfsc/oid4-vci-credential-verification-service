#!/usr/bin/env bash
set -euo pipefail
API_BASE="${API_BASE:-http://127.0.0.1:8080}"; TENANT_ID="${TENANT_ID:-demo_tenant}"; GROUP_ID="${GROUP_ID:?Set GROUP_ID for internal retrieval}"
STATE="${1:?Usage: verifier-http-get.sh presentation_id [output.json]}"; OUT="${2:-verified-presentation.json}"
STATUS="$(curl -sS -o "$OUT" -w '%{http_code}' -H "x-tenantid: $TENANT_ID" -H "x-groupid: $GROUP_ID" \
  "${API_BASE%/}/v1/tenants/$TENANT_ID/internal/presentations/$STATE")"
if [[ "$STATUS" != 200 ]]; then echo "HTTP $STATUS: $(cat "$OUT")" >&2; exit 1; fi
jq . "$OUT"
