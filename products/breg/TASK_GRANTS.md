# Task grants for governed writes

A Casework task grant gives an institutional agent bounded authority under its
own principal. It does not make the agent the human who approved the task.
BREG verifies the exchanged access token and selected access profile, then
checks current Casework status before each new governed mutation. Task agents
use change-request drafts and lifecycle operations; a task grant does not
authorize direct changes to the target records. A task-grant profile cannot
hold `apply_request`: the compiler refuses it with
`access_profile.task_grant.operation_forbidden`.

The authored access profile selects `actorKind: agent`, exact
`requesterClients`, `requiredPurposes`, and a `taskGrant` containing the exact
`sourceIssuer`. The token must match that profile, BREG's configured audience,
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
caller-supplied actor alias. `act` is exactly `{sub}` or exactly `{sub, iss}`,
and `iss`, when present, must be a string equal to the verified token issuer;
any other member, a different issuer, or a nested `act` refuses the token. A
token carrying a verified trusted actor is an agent token whatever its
`registry_actor_kind` claim says: a token exchange copies that claim from the
subject token, so it describes the citizen, not the caller. Such a token is
admitted only by an access profile, or an immediate-action permission, that
declares `actorKind: agent`; a profile that declares another kind or no
`actorKind` at all refuses it. A token without `act` is unaffected: a profile
without `actorKind` still accepts every kind of direct token. Custom contextual claim
names, when needed for an existing issuer, are configured together in the
closed `contextual` object.

A standing agent profile has a lower ceiling than a task-grant profile. A task
grant carries the approval of the human who assigned the task; a standing
agent carries none, so the human must confirm the change themselves by
submitting it. A standing agent profile may read and may create, read, and
patch change-request drafts. The compiler refuses it when it holds
`submit_request`, `revise_request`, `cancel_request`, or `apply_request`,
with `access_profile.standing_agent.operation_forbidden`, and when it holds
`create` or `patch` on an entity without a `changeRequest`, or `tombstone` or
`batch` on any entity, with
`access_profile.standing_agent.direct_mutation_forbidden`. Profiles
contributed by modules meet the same ceiling. Give the lifecycle operations to
a separate profile the citizen uses directly. This check does not cover action
permissions: an `invoke` grant on an immediate action is still accepted on a
standing agent profile.

## Configure current status

Configure BREG's runtime with one entry for each original source issuer used by
its task profiles:

```yaml
taskGrantStatus:
  - sourceIssuer: https://casework.example.gov
    baseUrl: https://casework.example.gov
    tokenEndpoint: https://identity.example.gov/oauth2/token
    clientAssertionAudience: https://identity.example.gov
    clientId: breg-task-status
    privateKeyRef: secret:file/breg-task-status-private-jwk
    caseworkResource: urn:casework:case-management
```

Register this client for client credentials with the exact Casework resource and
`casework:grants:status` scope. Register the same client in Casework's status
client mapping for this BREG resource. BREG supplies its configured OIDC audience
as that resource; neither a caller nor the grant chooses an outbound endpoint.
`clientAssertionAudience` is required and must exactly match the audience the
identity provider accepts for the signed client assertion. Stock ThunderID uses
its issuer URL. The private JWK must include its registered key identifier.
`caBundleRef` can refer to a private CA PEM bundle for both outbound connections.
Production endpoints use HTTPS; loopback HTTP is available for local development.

Startup refuses a task profile without its configured source-issuer mapping. A
failed status request refuses the mutation. No positive status result
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
## Audit

Terminal and refusal records for a request carrying a verified task grant include
an `authorization` object using the shared authorization audit fields. Grant,
principal, client and approver identifiers are keyed pseudonyms, scoped to the
package revision. The object also records the source issuer and grant deadline.
It contains no subjects, bounds values or purpose value. BREG continues
to record purpose presence separately. Later human review remains a separate
actor, and the retained original grant continues to govern status checks.

A request carrying a verified trusted actor records the same `authorization`
object on the same records, with `actorKind: agent` and an `actorPseudonym`:
the keyed pseudonym of `act.sub`, scoped to the package revision like the other
identifiers. `principalPseudonym` then names the person the agent acts for and
`clientPseudonym` the agent's client. A standing agent carries no grant, so its
object has no grant, approver, source issuer or deadline. The raw actor
identifier never reaches the journal. A task-grant token without `act` records
exactly what it did before.

Both kinds of token also carry the object on a read's terminal record: record
reads, lists and lookups, revision reads, and history and snapshot reads. An
immediate action's terminal record carries it whether the action committed,
replayed a stored receipt, or returned its target conditions. Action admission
refuses every task-grant token, so on an immediate action only a delegated
actor appears. A direct token records no `authorization` object anywhere.
Neither kind of token adds the object to a pre-I/O attempt record or to the
refusal record a read or revision read writes.
