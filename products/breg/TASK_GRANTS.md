# Task grants for governed writes

A Casework task grant gives an institutional agent bounded authority under its
own principal. It does not make the agent the human who approved the task.
BREG verifies the exchanged access token and selected access profile, then
checks current Casework status before each new governed mutation. Task agents
use change-request drafts and lifecycle operations; a task grant does not
authorize direct changes to the target records.

The authored access profile selects `actorKind: agent`, exact
`requesterClients`, `requiredPurposes`, and a `taskGrant` containing `authority`
and `sourceIssuer`. The token must match that profile, BREG's configured audience,
and the compiled collection and operation bounds. A task token cannot fall back
to a standing access profile. Ordinary profiles retain their own authority.

An authored `permissions` entry is the Registry's governed ceiling for a
profile. A delegated `taskGrant` is signed, short-lived authority for one task
inside that ceiling. It never adds an operation or field. BREG requires the
grant's complete BREG permission bounds to equal the profile's compiled
collections and operations. Wider, narrower, partial, and wrong-resource
bounds are refused.

Standing native citizen agents use the same `actorKind: agent` and
`requesterClients` binding without a `taskGrant`. Configure the exact native
actor identity for each such client under `authentication.authorityClaims`:

```yaml
authentication:
  authorityClaims:
    principal: sub
    purpose: registry_purpose
    trustedActors:
      citizen-self-service-agent: 00000000-0000-4000-8000-000000000001
```

The access token keeps the citizen in `sub`. Its `act.sub` must equal the
configured actor for the verified `azp` or `client_id`; BREG does not accept a
caller-supplied actor alias. Custom contextual claim names, when needed for an
existing issuer, are configured together in the closed `contextual` object.

## Configure current status

Configure BREG's runtime with one entry for each trusted authority and original
source issuer used by its task profiles:

```yaml
taskGrantStatus:
  - authority: https://casework.example.gov/tasks
    sourceIssuer: https://casework.example.gov
    baseUrl: https://casework.example.gov
    tokenEndpoint: https://identity.example.gov/oauth2/token
    clientId: breg-task-status
    privateKeyRef: secret:file/breg-task-status-private-jwk
    caseworkResource: urn:casework:case-management
```

Register this client for client credentials with the exact Casework resource and
`casework:grants:status` scope. Register the same client in Casework's status
client mapping for this BREG resource. BREG supplies its configured OIDC audience
as that resource; neither a caller nor the grant chooses an outbound endpoint.
The private JWK must include its registered key identifier. `caBundleRef` can
refer to a private CA PEM bundle for both outbound connections. Production
endpoints use HTTPS; loopback HTTP is available for local development.

Startup refuses a task profile without its configured authority/source-issuer
mapping. A failed status request refuses the mutation. No positive status result
is cached. BREG compares all retained authorization fields, including the
original principal, client, resource, purpose, bounds, subjects, and deadline.

## Approval, retries, and expiry

Submission freezes the original task authority alongside the proposal version
and its immutable effects. A later human reviewer remains a separate actor.
Approval and application check the original grant, including automatic
application. A database concurrency retry makes a fresh status check.

An exact completed retry recovers the existing receipt under current disclosure
authority. It does not perform a new mutation or require a new positive status
check. Reusing the idempotency key with a different grant conflicts. An expired
or revoked task requires an explicit new authorized submission; refreshing an
access token cannot extend the original grant deadline.

Status refusal returns a failed precondition; status service failure returns
unavailable. Human rejection and owner cancellation keep their existing
permissions. These actions do not require the old submitter grant to remain
active. Read cursors and representation ETags do not incorporate grant IDs.

The bounded status check runs while the proposal is locked. Casework revocation
can still occur between that check and the local commit. BREG and Casework do
not share a distributed transaction. Proposal-detail erasure also removes its
retained task subjects, under the existing operator retention boundary.
