#!/usr/bin/env bash
set -euo pipefail
STATE="${1:?Usage: verifier-http-wait.sh presentation_id [output.json]}"
OUT="${2:-verified-presentation.json}"; INTERVAL="${INTERVAL:-2}"; ATTEMPTS="${ATTEMPTS:-60}"
for ((i=1;i<=ATTEMPTS;i++)); do
  if "$(dirname "$0")/verifier-http-get.sh" "$STATE" "$OUT"; then exit 0; fi
  sleep "$INTERVAL"
done
echo 'Timeout waiting for verified presentation' >&2; exit 1
