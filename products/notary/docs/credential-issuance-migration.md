# Credential issuance trust-boundary migration

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** credential · **Audience:** operator, integrator

Registry Notary now issues credentials only from a stored evaluation whose
selected claims were produced by fresh, exact compiler-pinned Registry Relay
consultations. This applies to `POST /v1/credentials` and
`POST /oid4vci/credential`.

## Configuration changes

Before upgrading, inspect every credential profile, every
`subject_access.allowed_claims` entry used by credential capability, and every
OID4VCI projection:

- Each selected claim must use `registry_backed` evidence.
- A profile and its claims must name each other consistently.
- OID4VCI claims and projections must resolve through those same
  registry-backed profile bindings.
- Remove source-free `self_attested` claims from credential profiles,
  credential-capable subject-access allow-lists, and OID4VCI configurations.
- Keep a source-free service evaluation-only by disabling credential issuance
  and omitting credential profiles and OID4VCI credential configurations.
- Remove `credential_profiles` from every delegated relationship and from each
  delegated dependent claim. Delegated self-attestation remains available for
  evaluation and rendering, but neither direct nor OID4VCI credential issuance
  accepts a delegated evaluation in 1.0.
- If a dependent fact must become a credential, model a separate
  registry-backed, non-delegated claim and bind that claim through
  `subject_access.credential_profiles`.

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
OID4VCI path rejects a source-free credential configuration before nonce
consumption, then preserves its nonce-before-evaluation ordering and verifies
the newly stored evaluation before signer access.

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
2. Remove or replace source-free and delegated credential journeys. They may
   continue as evaluation and rendering journeys.
3. Deploy compatible Relay and Notary configuration from one project
   generation.
4. Re-evaluate claims used by in-progress credential journeys.
5. Exercise both direct and OID4VCI issuance and confirm the Relay receives the
   exact configured profile, purpose, and contract hash.

Do not copy provenance from an old evaluation or retry with an edited stored
record. Re-evaluation is the supported recovery path.
