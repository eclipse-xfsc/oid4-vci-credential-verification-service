# XFSC Credential Selection Policy test server

Start with `docker compose -f compose.yaml up -d --build`.

Endpoint: `POST http://localhost:8085/policy` (also `/` and `/evaluate`).

Example:

```bash
curl -sS http://localhost:8085/policy -H 'Content-Type: application/json' -d '{"tenantId":"demo-tenant","groupId":"demo-group","clientId":"example","dcqlQuery":{},"credentials":[{"queryId":"identity","credentialId":"credential-123"}]}' | jq .
```

Response:

```json
{"approved":true,"selections":[{"queryId":"identity","credentialId":"credential-123"}]}
```

The server returns all supplied credential IDs as selections and does not implement any real authorization. Use for local tests only. The exact `PresentationSelection` JSON field names should be verified against the Go model.
