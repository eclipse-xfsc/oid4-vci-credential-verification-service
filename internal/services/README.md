# Service-Aufteilung

- [Holder](holder/README.md): externe OID4VP-Anfragen empfangen, Credentials aus Storage auswählen, Präsentation erstellen und versenden. Implementierung: `holder/*.go`.
- [Verifier](verifier/README.md): DCQL-Requests erzeugen, VP-Responses entgegennehmen und verifizieren. Implementierung: `verifier/*.go`.
- `common/*.go` und `common/`: gemeinsamer HTTP-Schutz, Fehlerbehandlung, Datenbank und State.

**Technische Einschränkung:** Die Rolle ist nach Dateinamen und Dokumentation getrennt, nicht in zwei eigenständige Go-Packages. Ein physischer Move in Unterverzeichnisse ohne API-Entkopplung würde aufgrund gemeinsamer unexportierter Funktionen, Methoden auf `PresentationRequestor` und HTTP-Handler-Referenzen zu Buildfehlern führen.

