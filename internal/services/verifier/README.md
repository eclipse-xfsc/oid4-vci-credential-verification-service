# Verifier — OID4VP 1.0

## Implementierung

Die Verifier-Funktionen befinden sich derzeit in `internal/services/verifier/*.go` (Go-Package `services`). Dieses Verzeichnis beschreibt die fachliche Grenze; die Go-Packages sind noch nicht physisch getrennt.

## Ablauf

1. `PresentationRequestor` empfängt eine NATS-Anfrage vom Typ `verifier.presentation.authorization` mit DCQL, Client-ID, Tenant und Request-ID.
2. Die DCQL-Abfrage wird validiert und persistiert; der Verifier erzeugt einen `presentation_id`/State und eine `request_uri`.
3. `GetRequestObjectAndSetObjectFetched` stellt das Request Object über den HTTP-Endpunkt `/:id/request-object/request.jwt` bereit.
4. Der Holder übermittelt die VP an den Direct-Post-Endpunkt `/:id`; `HandleProof` und `CheckPresentations` prüfen State, Token und DCQL-Matches.
5. `forwardPresentation` publiziert die verifizierte Präsentation auf dem konfigurierten Storage-NATS-Subject. Status-Events werden durch `publishStatus` versendet.

## Wichtige Dateien

- `../verifier/requestor.go`: Request-Erstellung, Signierung, NATS-Verarbeitung, Request-Object-Ausgabe
- `../verifier/response.go`: HTTP-Response-Eingang, VP-Verifikation und Storage-Event
- `../common/`: gemeinsame Persistenz und State-Operationen

## Hinweise

Der Verifier erzeugt Anfragen; er benötigt keinen Holder-Consent-Endpunkt. Der Consent liegt ausschließlich auf der Holder-Seite. `direct_post.jwt`-Unterstützung des eingehenden Verifier-Endpunkts muss anhand der tatsächlich implementierten Decoder geprüft werden.
