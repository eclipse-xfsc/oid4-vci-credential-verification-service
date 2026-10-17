# Holder — OID4VP 1.0

## Implementierungsstand (geprüft am bereitgestellten ZIP)

Die Holder-Implementierung liegt im Go-Package `internal/services/holder`. Ein Kompatibilitäts-Facade im Package `services` hält bestehende Aufrufer unverändert.

## Ablauf

1. **Eingang:** CloudEvent vom Typ `verifier.presentation.authorization.remote` auf dem konfigurierten NATS-Subject, mit `tenantId`, `groupId`, `requestId`, `url`. Das Subject ist konfigurierbar, nicht durch den Event-Typ festgelegt.
2. **Request:** `AuthorizationHandler.receive` parst `openid4vp://?...`, ruft die `request_uri` ab, prüft das signierte Request Object und speichert die Transaktion einschließlich DCQL. Die NATS-Antwort auf `authorizationReply` enthält jetzt `presentation_id` (lokaler State). Die Antwort ist asynchron; `nats request` ist kein unterstütztes synchrones RPC.
3. **Consent:** Ein UI-/Wallet-Client muss den Request und die mögliche Offenlegung darstellen und die ausdrückliche Zustimmung einholen. **Ein eigener NATS-Consent-Handler ist im gelieferten Stand nicht implementiert.** Auch ein nackter `presentation_id` ist kein Consent-Beweis.
4. **Fulfillment (vorhanden):** `POST /v1/tenants/{tenantId}/internal/proofs/proof/{id}/fulfill` mit `holderDid`, `signKey`, optional `signNamespace`, `signGroup`. Die Route steht unter `VerifyState`-Middleware; zusätzlich müssen Benutzer-/Mandantenrechte und Consent vor Aufruf geprüft werden.
5. **Credential-Auswahl:** `resolveCredentials` sendet die persistierte DCQL-Abfrage an `POST {storageServiceURL}/v1/tenants/{tenantId}/storage/{region}/{country}/{groupId}/credentials`. `applyCredentialSelectionPolicy` filtert die Gruppen; derzeit ist **keine explizite Benutzer-Credential-Auswahl im Fulfillment-Payload** vorhanden.
6. **Signieren:** `signerServiceSignPresentations` erzeugt VP-Token via Signer; `VPToken.ValidateAgainst` prüft DCQL.
7. **Senden:** `postResponse` übermittelt `direct_post` als Formdaten oder `direct_post.jwt` als verschlüsselte `response` an die signierte `response_uri`. Status wird in der Datenbank aktualisiert.

## Wichtige Dateien

- `authorization.go`: NATS- und HTTP-Eingang, Request-Speicherung
- `request_fetch.go`, `request_verify.go`: HTTP-Abruf und JWS-Prüfung
- `storage.go`: DCQL-basierte Credential-Suche
- `policy.go`: Auswahl-Policy
- `presentation.go`: HTTP-Fulfillment, Signieren, Übermitteln
- `response_encryption.go`: `direct_post.jwt`-Verschlüsselung

## Offene Punkte

- Consent-UI/Approval-Bindung und authentifizierte Credential-/Claim-Auswahl implementieren.
- Falls gewünscht, NATS-Fulfillment-Command als **neuen** Event-Typ mit eigener Subscription und Antwort ergänzen; aktuell existiert nur HTTP-Fulfillment.
- Der Verifier muss `response_uri`, DCQL und Kryptografie gemäß OID4VP validieren; vorhandene Prüfungen sind kein Ersatz für End-to-End-Konformitätstests.
