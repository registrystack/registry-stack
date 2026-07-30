# Credential issuance trust-boundary migration

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** credential · **Audience:** operator, integrator

Registry Notary now issues credentials only from a stored evaluation whose
selected claims were produced by fresh, exact compiler-pinned Registry Relay
consultations. This applies to `POST /v1/credentials` and
`POST /oid4vci/credential`.

## Removal of caller-provided evidence

The `self_attested` evidence mode has been removed. It is not an
evaluation-only compatibility mode. Configuration containing
`evidence_mode.type: self_attested` is rejected.

To migrate:

1. Remove claims that have no authoritative evidence source.
2. For retained claims, declare exactly one compiler-pinned Relay
   consultation and derive the result only from its typed outputs.
3. Rename the authorization wire value `delegated_attestation` to
   `delegated_subject_access`.
4. Rename the access scope `evidence:self_attest` to
   `evidence:subject_access`.
5. Regenerate configuration and restart Notary.

OIDC identity, authorization details, subject binding, and representative
policy remain access controls. They must not be treated as claim provenance.

The OID4VCI surface also changes to issuer-initiated pre-authorized code only.
Remove integrations that call the former credential-offer or public nonce
routes, or that treat an identity-provider authorization code as a wallet
grant. The corresponding Rust `oid4vci_credential_offer` and `oid4vci_nonce`,
Node.js `oid4vciCredentialOffer` and `oid4vciNonce`, and Python
`oid4vci_credential_offer` and `oid4vci_nonce` client helpers are also removed.
Start the browser journey at `GET /oid4vci/offer/start`, import the offer
rendered after the callback, redeem its pre-authorized code at
`POST /oid4vci/token`, and use the proof nonce from that token response. The
issuer metadata no longer contains `nonce_endpoint`, and the credential
response no longer returns a next nonce.

## Configuration changes

Before upgrading, inspect every credential profile, every
`subject_access.allowed_claims` entry used by credential capability, and every
OID4VCI projection:

- Each selected claim must use `registry_backed` evidence.
- A profile and its claims must name each other consistently.
- OID4VCI claims and projections must resolve through those same
  registry-backed profile bindings.
- Remove claims without compiler-pinned Relay evidence.
- Remove legacy `credential_profiles` entries from delegated relationships.
  Representative OID4VCI issuance is configured on the credential
  configuration instead and requires the digitally authenticated
  representative ceremony, one named relationship, and live credential
  status.
- Keep other delegated claims evaluation-only. Direct issuance and OID4VCI
  configurations without the representative ceremony reject delegated
  evaluations.

Configuration load rejects a mixed or one-sided binding. The diagnostic names
the invalid credential claim binding and the required remediation.

## Stored evaluation compatibility

Existing stored evaluations remain readable and renderable. Records without
the private issuance provenance and per-claim execution binding introduced by
this release cannot be used to issue a credential. Re-evaluate the
registry-backed claim under the active configuration, then retry issuance with
the new evaluation id.

Notary retains this restricted provenance only when all selected roots share a
mutually validated credential profile. Registry-backed evaluation-only claims
remain evaluatable and renderable but store no private Relay consultation ids
or acquisition times.

For every claim in each selected root's executed registry-backed dependency
closure, the new evaluation stores one private compiler-pin record containing
the claim id and version, Relay profile id and contract hash, canonical purpose,
and executed consultation ULID. A separate normalized execution record stores
each unique consultation ULID and acquisition time once, including when one
coalesced Relay execution supports several claims. Each claim pin also carries
an unkeyed SHA-256 execution binding over the compiler pin, execution ULID and
acquisition time, evaluation and result time, and exact claim provenance. Each public root result's
`relay_consultation_count` must equal the number of unique executed ULIDs in
that root's closure. Missing, duplicate, extra, stale, or modified claim pins or
execution records are denied before signer access, signing, credential
identifiers, or status writes.
Direct issuance performs this check before holder-proof replay mutation. The
OID4VCI callback creates the registry-backed transaction and completes the
Relay evaluation before it renders an offer. The credential endpoint rejects
incomplete Relay provenance, consumes the transaction-bound proof nonce, reloads
the stored transaction and evaluation, and verifies exact provenance before
signer access.

The execution binding detects partial stored-record mutation, including a
changed acquisition time or consultation ids swapped between claims. It is not
a keyed authenticity proof and does not protect against an operator who can
rewrite every committed field and recompute the digest. Protect the evaluation
store with the deployment's database access controls, audit, and backup
controls.

This is an application-data compatibility change only. It introduces no
database migration, DDL change, or correctness-state schema fingerprint
change.

## Rollout

1. Regenerate the project configuration and correct any credential-binding
   validation errors.
2. Remove claims without Relay evidence. Retain delegated credential journeys
   only when they use the representative OID4VCI ceremony.
3. Deploy compatible Relay and Notary configuration from one project
   generation.
4. Re-evaluate claims used by in-progress credential journeys.
5. Replace wallet authorization-code, public nonce, and next-nonce assumptions
   with the pre-authorized transaction flow.
6. Exercise both direct and OID4VCI issuance and confirm the Relay receives the
   exact configured profile, purpose, and contract hash.

Do not copy provenance from an old evaluation or retry with an edited stored
record. Re-evaluation is the supported recovery path.
