# Registry Notary scenario patterns

## Registry-backed evaluation

```mermaid
sequenceDiagram
  participant App as Service application
  participant Notary as Registry Notary
  participant Relay as Registry Relay
  participant Source as Registry source

  App->>Notary: Evaluate claims for purpose
  Notary->>Notary: Authenticate and authorize
  Notary->>Relay: Execute pinned consultation
  Relay->>Source: Governed read
  Source-->>Relay: Bounded response
  Relay-->>Notary: Outcome, outputs, provenance
  Notary->>Notary: Claims, disclosure, issuance policy
  Notary-->>App: Minimized result or credential
```

One consultation can support several direct and CEL claims. Relay returns
typed outputs, while Notary owns claim meaning and disclosure.

## Self-attested Notary-only evaluation

```mermaid
sequenceDiagram
  participant Holder as Authenticated holder
  participant Notary as Registry Notary

  Holder->>Notary: Source-free evidence request
  Notary->>Notary: Validate token and subject binding
  Notary->>Notary: Evaluate self-attested CEL policy
  Notary-->>Holder: Allowed result or credential
```

This topology performs no Relay or registry-source call.

## Delegated evaluation

```mermaid
sequenceDiagram
  participant Caller as Delegated caller
  participant Notary as Registry Notary
  participant Relay as Registry Relay

  Caller->>Notary: Request for represented target
  Notary->>Notary: Validate exact authorization details
  Notary->>Relay: Optional pinned relationship-proof consultation
  Relay-->>Notary: Boolean proof outcome
  Notary->>Relay: Pinned evidence consultation
  Relay-->>Notary: Minimized evidence
  Notary-->>Caller: Policy-limited result
```

The proof consultation proves only the configured requester-target edge. It
does not add scopes or grant source authority. Binding or scope failure must
make zero Relay calls.

## Credential issuance

Credential issuance reuses an allowed evaluation. The credential profile owns
claim membership, format, holder binding, validity, and disclosure. A direct
output claim is not issued on `no_match`; ambiguity or failure never issues.

## Unsupported composition

A project does not join independent registry trust domains. Cross-registry
composition requires separately governed projects and explicit federation or
an external workflow. Notary does not execute source adapters or general
orchestration.
