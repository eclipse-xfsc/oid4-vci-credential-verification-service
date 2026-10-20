# Demo Presentation Policy Service

Lokaler Fixture-Service für den XFSC OID4VP Verifier. **Nicht produktiv einsetzen**: Die Query-Parameter `tenantId` und `groupId` werden auf Vorhandensein geprüft, aber nicht autorisiert. Die JSON-Dateien unter `policies/` definieren die zurückgegebene `dcqlQuery`.

## Standalone starten

```bash
cd deployment/docker/demo-presentation-policy-service
docker compose up -d --build
curl -fsS 'http://127.0.0.1:8099/health'
curl -fsS 'http://127.0.0.1:8099/v1/presentation-policies/paradym-test?tenantId=demo_tenant&groupId=test' | jq .
```

Verfügbare IDs: `paradym-test`, `employee-sdjwt`, `employee-ldp`. Weitere Policies als `<id>.json` im Ordner `policies/` hinzufügen und Image neu bauen.

## Im globalen Compose

```bash
cd deployment/docker
docker compose up -d --build presentation-policy verification
```

Der Verifier verwendet innerhalb des Compose-Netzwerks `http://presentation-policy:8080` (`CREDENTIALVERIFICATION_PRESENTATIONPOLICY_URL`). Auf dem Host ist der Test-Service unter `127.0.0.1:8099` erreichbar.

```bash
curl -fsS 'http://127.0.0.1:8099/v1/presentation-policies/employee-sdjwt?tenantId=demo_tenant&groupId=test' | jq .
```

Die Antwort ist ein JSON-Objekt mit `id`, `version` und `dcqlQuery`. Diese DCQL wird im Verifier serverseitig in den OID4VP Authorization Request übernommen. Der Wallet wird keine `presentationPolicyId` als proprietärer OID4VP-Parameter übermittelt.
