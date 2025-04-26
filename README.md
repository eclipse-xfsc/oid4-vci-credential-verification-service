# Introduction

The credential verfication service fullfills two task: 

1. Receiveing Presentations and verifying it's credential content (credential verification execution)
2. Preparing Presentation Requests for fullfillment (credential verification preperation)

This processes are based on the [OID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) especially the [Cross Device Flow](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-3.2) which allows an interaction between different devices (in this case cloud services)

For this purpose the service is able to generate/process dynamically and cryptographically protected request.jwt objects which are prepared for each client, when a link is requested.

The service it self can be triggered over different ways: 

1. VP Authorization Requests can be triggered via Redirect or Nats
2. VP Authorization Links can be generated over Nats

The service itself stores each Request in a Cassandra DB, either for fullment a request or delivering the data to a link which was generated. 


# Flows

## Authorization Link Creation and Usage

A [nats message](https://gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/credential-verification-service/-/blob/main/pkg/messaging/types.go?ref_type=heads#L14) is sent to the service together with a TTL and a presentation definition, which the service stores along with a request.jwt object. If the link is later on used, the request.jwt is delivered. When the TTL is exceeded, the record is deleted and the link then not more usable. 

```mermaid
sequenceDiagram
title Authorization Link Creation

Internal System->> Internal System: Build Presentation Definition
Internal System->> Credential Verification Service: Send Nats Message with Presentation Definition/TTL etc
Credential Verification Service->>Credential Verification Service: Build request.jwt Object with Presentation Definition
Credential Verification Service->>Credential Verification Service: Create Auth Link with request.jwt
Credential Verification Service->>Credential Verification Service: Stores Request with TTL
Credential Verification Service->> Internal System: Replies with Auth Link and Presentation ID
Internal System -->> External System: Submits Link or redirect to any other System (see Authorization Link Processing)
```

Note: Building a Presentation Definition is custom business and needs to be done by business specific controllers. 
Note: The credential selection is currently an functionality of storage service, but it can be selected from any other system which understands the way of doing it. 


## Authorization Link Processing

The processing of a link can be either done by redirect (if enabled) or by internal nats message. Both have in the end the same effect. 

```mermaid
sequenceDiagram
title Authorization Link Processing
alt
External System->> Credential Verification Service: Redirect via Authorization Link
end
alt
Internal System ->> Credential Verification Service: Receive Nats message with Link
end 
Credential Verification Service->> Credential Verification Service: Extract Request Object Url
Credential Verification Service->> Credential Verification Service: Download Request Object
Credential Verification Service->> Credential Verification Service: Verifies Request Object
Credential Verification Service->> Credential Verification Service: Extract Presentation Definition
Credential Verification Service->> Credential Verification Service: Store Request in DB
alt
Credential Verification Service-->> Internal System: Redirect to Internal System
end 
alt 
Credential Verification Service-->> Internal System: Publish Message about new Record
end
Internal System->> Credential Verification Service: Pick up of Presentation Definition (See Presentation Definition Processing)
```

## Presentation Definition Processing

After picking up a presentation definition the definition must be fullfilled by selecting the right credentials. 

```mermaid
sequenceDiagram
title Presentation Definition Processing
Internal System ->> Internal System: Checks Presentation Definition
Internal System ->> Internal System: Selects Credential according to Definition
Internal System ->> Internal System: Creates Submission Data
Internal System ->> Internal System: Creates and Signs VP
Internal System ->> Credential Verification Service: Uses POST Endpoint for transferring the VP
Credential Verification Service->>TSA Signer Service: Checks VP
Credential Verification Service->> Credential Verification Service: Store VP
Credential Verification Service->> Internal System: Notification of Presentation ID 
Internal System->> Credential Verification Service: Claim Presentation ID by account assigning

```

Note: The Credential Verification Service can be either in the role of a holder or of a verifier. 


# Bootstrap


# Developer Information

## Retrieve data from database

### Retrieve Presentation Definitions

```bash
cqlsh <cassandra host> <cassandra port> -u <cassandra user> -p <cassandra password> -e "SELECT * FROM tenant_space.presentations;"

```