# Send Request for Consent

An received OID4VP Link (oid4vp://...) can be sent via nats to the service, to resolve the link and store the request in the db. Script Call: 

```
./scripts/sendRequestForConsent.sh $LINK
```