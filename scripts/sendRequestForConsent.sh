#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# Configuration
# ============================================================

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_SUBJECT="${NATS_SUBJECT:-presentation.authorisation}"
NATS_REPLY_SUBJECT="${NATS_REPLY_SUBJECT:-}"

EVENT_TYPE="verifier.presentation.authorization.remote"

TENANT_ID="${TENANT_ID:-demo-tenant}"
GROUP_ID="${GROUP_ID:-demo-group}"
REQUEST_ID="${REQUEST_ID:-$(uuidgen | tr '[:upper:]' '[:lower:]')}"

# Vollständiger OID4VP-Link
OID4VP_URL="${OID4VP_URL:-$1}"

# ============================================================
# Dependencies
# ============================================================

for cmd in nats jq python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: $cmd is not installed"
    exit 1
  fi
done

# ============================================================
# Validate OID4VP URL
# ============================================================

echo "Validating OID4VP URL..."

python3 - "$OID4VP_URL" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qs

url = sys.argv[1]
parsed = urlsplit(url)

if parsed.scheme != "openid4vp":
    sys.exit("ERROR: Expected openid4vp:// URL")

params = parse_qs(parsed.query, keep_blank_values=True)

for name in ("client_id", "request_uri"):
    values = params.get(name, [])
    if len(values) != 1 or not values[0]:
        sys.exit(f"ERROR: Expected exactly one non-empty {name}")

request_uri = urlsplit(params["request_uri"][0])
if request_uri.scheme != "https" or not request_uri.netloc:
    sys.exit("ERROR: request_uri must be an absolute HTTPS URL")

print("OID4VP URL valid")
print("Client ID:", params["client_id"][0])
print("Request URI:", params["request_uri"][0])
PY

# ============================================================
# Build CloudEvent
# ============================================================

EVENT="$(jq -n \
  --arg id "$REQUEST_ID" \
  --arg type "$EVENT_TYPE" \
  --arg tenantId "$TENANT_ID" \
  --arg groupId "$GROUP_ID" \
  --arg requestId "$REQUEST_ID" \
  --arg url "$OID4VP_URL" \
  '{
    specversion: "1.0",
    id: $id,
    source: "xfsc-debug",
    type: $type,
    datacontenttype: "application/json",
    data: {
      tenant_id: $tenantId,
      group_id: $groupId,
      request_id: $requestId,
      url: $url
    }
  }'
)"

# ============================================================
# Publish
# ============================================================

echo
echo "=========================================="
echo " XFSC OID4VP Authorization Request"
echo "=========================================="
echo
echo "NATS:       $NATS_URL"
echo "Subject:    $NATS_SUBJECT"
echo "Event Type: $EVENT_TYPE"
echo "Tenant:     $TENANT_ID"
echo "Group:      $GROUP_ID"
echo "Request ID: $REQUEST_ID"
echo
echo "CloudEvent:"
echo "$EVENT" | jq .
echo

nats pub \
  --server "$NATS_URL" \
  "$NATS_SUBJECT" \
  "$EVENT"

echo
echo "CloudEvent published successfully."

if [[ -n "$NATS_REPLY_SUBJECT" ]]; then
  echo
  echo "Configured reply subject: $NATS_REPLY_SUBJECT"
  echo "To receive asynchronous replies, run:"
  echo
  echo "  nats sub --server '$NATS_URL' '$NATS_REPLY_SUBJECT'"
fi