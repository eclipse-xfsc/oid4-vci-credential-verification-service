#!/usr/bin/env bash
set -euo pipefail
API_BASE="${API_BASE:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-demo_tenant}"
GROUP_ID="${GROUP_ID:?Set GROUP_ID for internal listing}"
curl --fail-with-body -sS -H "x-tenantid: $TENANT_ID" -H "x-groupid: $GROUP_ID" \
  "${API_BASE%/}/v1/tenants/$TENANT_ID/internal/presentations" | jq .
