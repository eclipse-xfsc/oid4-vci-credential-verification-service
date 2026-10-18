#!/usr/bin/env bash
set -euo pipefail

# Test-/Demo-Client: approves automatically with the first credential of the first nonempty DCQL group.
# Usage: ./manual-consent.sh '<openid4vp://...>' '<holderDid>' '<signKey>' '[disclosure1,disclosure2]'
API_BASE="${API_BASE:-http://127.0.0.1:8080}"
TENANT_ID="${TENANT_ID:-demo_tenant}"
GROUP_ID="${GROUP_ID:-test}"
NAMESPACE="${NAMESPACE:-ocm-wstack}"
KEY_GROUP="${KEY_GROUP:-demo-tenant}"
HOST="${HOST:-}"
TTL="${TTL:-3600}"
# Use the actual deployed route prefix; defaults to /v1/tenants/<tenantId>.
BASE="${PRESENTATIONS_BASE:-${API_BASE%/}/v1/tenants/${TENANT_ID}/api/presentation/presentations}"
OID4VP_URL="${1:-${OID4VP_URL:-}}"
HOLDER_DID="${2:-${HOLDER_DID:-}}"
SIGN_KEY="${3:-${SIGN_KEY:-}}"
DISCLOSURES_CSV="${4:-${DISCLOSURES:-}}"

for cmd in curl jq python3; do
  command -v "$cmd" >/dev/null || { echo "ERROR: $cmd fehlt" >&2; exit 1; }
done
if [[ -z "$OID4VP_URL" || -z "$HOLDER_DID" || -z "$SIGN_KEY" ]]; then
  echo "Usage: $0 '<openid4vp://...>' '<holderDid>' '<signKey>' '[disclosure1,disclosure2]'" >&2
  exit 1
fi
if ! [[ "$TTL" =~ ^[0-9]+$ ]] || [[ "$TTL" == 0 ]]; then
  echo "ERROR: TTL muss eine positive Ganzzahl sein" >&2; exit 1
fi
python3 - "$OID4VP_URL" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qs
u = urlsplit(sys.argv[1]); p = parse_qs(u.query, keep_blank_values=True)
if u.scheme != 'openid4vp': sys.exit('ERROR: openid4vp:// erwartet')
for k in ('client_id', 'request_uri'):
    if len(p.get(k, [])) != 1 or not p[k][0]: sys.exit(f'ERROR: {k} fehlt/mehrfach')
r = urlsplit(p['request_uri'][0])
if r.scheme != 'https' or not r.netloc: sys.exit('ERROR: request_uri muss HTTPS sein')
PY

HEADERS=(-H 'Content-Type: application/json' -H "x-tenantid: $TENANT_ID" -H "x-groupid: $GROUP_ID" -H "x-namespace: $NAMESPACE" -H "x-group: $KEY_GROUP")
[[ -z "$HOST" ]] || HEADERS+=(-H "x-host: $HOST")

api_call() {
  local method="$1" url="$2" data="${3:-}" tmp status
  tmp="$(mktemp)"
  if [[ "$method" == POST ]]; then
    if ! status="$(curl -sS --connect-timeout 10 --max-time 90 -o "$tmp" -w '%{http_code}' -X POST "${HEADERS[@]}" -d "$data" "$url")"; then
      cat "$tmp" >&2; rm -f "$tmp"; return 1
    fi
  else
    if ! status="$(curl -sS --connect-timeout 10 --max-time 90 -o "$tmp" -w '%{http_code}' "${HEADERS[@]}" "$url")"; then
      cat "$tmp" >&2; rm -f "$tmp"; return 1
    fi
  fi
  echo "HTTP $status ($method $url)" >&2
  if [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
    cat "$tmp" >&2; echo >&2; rm -f "$tmp"; return 1
  fi
  if ! jq -e . "$tmp" >/dev/null 2>&1; then
    echo 'ERROR: API returned invalid JSON:' >&2
    cat "$tmp" >&2; echo >&2; rm -f "$tmp"; return 1
  fi
  cat "$tmp"
  rm -f "$tmp"
}

BODY="$(jq -n --arg url "$OID4VP_URL" --argjson ttl "$TTL" '{url:$url,consentMode:"manual",ttl:$ttl}')"
echo '== 1. HTTP Intake (manual) =='
INTAKE="$(api_call POST "$BASE" "$BODY")"
echo "$INTAKE" | jq .
PRESENTATION_ID="$(jq -r '.presentationId // empty' <<< "$INTAKE")"
[[ -n "$PRESENTATION_ID" ]] || { echo 'ERROR: presentationId fehlt' >&2; exit 1; }

echo '== 2. Credential Candidates =='
CANDIDATES="$(api_call GET "$BASE/$PRESENTATION_ID/candidates")"
echo "$CANDIDATES" | jq .

# FilterResult is serialized by Go; depending on its JSON tags, the field may
# be "Id" (Go default), "id", or "queryId". Never send a null queryId.
# Validate the candidate's query ID against the original DCQL request.
SELECTED="$(jq -ce '
  (.dcqlQuery.credentials // []) as $queries
  | [
      .candidates[]?
      | select((.credentials | type) == "object" and (.credentials | length) > 0)
      | (.id // .Id // .ID // .queryId // .QueryId) as $candidateId
      | (if ($candidateId | type) == "string" and $candidateId != "" and $candidateId != "null"
         then $candidateId
         elif ($queries | length) == 1 then $queries[0].id
         else null end) as $queryId
      | select(($queryId | type) == "string" and $queryId != "" and $queryId != "null")
      | select(any($queries[]; .id == $queryId))
      | {queryId: $queryId, credentialId: (.credentials | keys | first)}
      | select((.credentialId | type) == "string" and .credentialId != "")
    ] | first // empty
' <<< "$CANDIDATES")"
if [[ -z "$SELECTED" ]]; then
  echo 'ERROR: Keine Credential-Auswahl mit gültiger DCQL-queryId möglich.' >&2
  echo 'DEBUG: DCQL-Queries und Candidate-Gruppen:' >&2
  jq '{queries: [.dcqlQuery.credentials[]? | {id, format}], candidates: [.candidates[]? | {id, Id, queryId, QueryId, credentialIds: ((.credentials // {}) | keys)}]}' <<< "$CANDIDATES" >&2
  exit 1
fi
QUERY_ID="$(jq -er '.queryId | select(type == "string" and length > 0 and . != "null")' <<< "$SELECTED")"
CREDENTIAL_ID="$(jq -er '.credentialId | select(type == "string" and length > 0)' <<< "$SELECTED")"

# DCQL format belongs to credentials[] (query id); for SD-JWT require explicit disclosures
# or infer simple top-level claim paths. Complex claims require explicit manual input.
FORMAT="$(jq -r --arg id "$QUERY_ID" '.dcqlQuery.credentials[]? | select(.id==$id) | .format // empty' <<< "$CANDIDATES" | head -n 1)"
DISCLOSURES='[]'
if [[ -n "$DISCLOSURES_CSV" ]]; then
  DISCLOSURES="$(jq -cn --arg csv "$DISCLOSURES_CSV" '$csv | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length>0))')"
elif [[ "$FORMAT" == 'dc+sd-jwt' ]]; then
  # For simple DCQL claims such as {"path":["test"]}, use ["test"].
  # Refuse to silently approve nested/complex requirements.
  if ! DISCLOSURES="$(jq -cer --arg id "$QUERY_ID" '
    [.dcqlQuery.credentials[]? | select(.id==$id) | .claims[]? | .path] as $paths
    | if all($paths[]; type=="array" and length==1 and (.[0] | type)=="string")
      then [$paths[][]] | unique else error("complex DCQL paths: specify disclosures explicitly") end
  ' <<< "$CANDIDATES")"; then
    echo 'ERROR: Disclosures nicht automatisch ableitbar. Als viertes Argument angeben.' >&2
    exit 1
  fi
fi

APPROVE_BODY="$(jq -n \
  --arg holderDid "$HOLDER_DID" --arg signKey "$SIGN_KEY" \
  --arg queryId "$QUERY_ID" --arg credentialId "$CREDENTIAL_ID" \
  --argjson disclosures "$DISCLOSURES" \
  '{holderDid:$holderDid,signKey:$signKey,selections:[{queryId:$queryId,credentialId:$credentialId,disclosures:$disclosures}]}')"

echo "== 3. Approve first credential ($FORMAT, query=$QUERY_ID, credential=$CREDENTIAL_ID) =="
echo "$APPROVE_BODY" | jq .
APPROVED="$(api_call POST "$BASE/$PRESENTATION_ID/approve" "$APPROVE_BODY")"
echo "$APPROVED" | jq .
echo "== Fertig: $PRESENTATION_ID =="
