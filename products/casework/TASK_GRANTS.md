# Approve bounded work for an institutional agent

A task grant records a current human holder's explicit approval for one
institutional agent to perform a bounded task under its own principal. Unified
review tasks use the review-task grant routes; retained source work items use
their existing routes during migration. In both cases the source remains
authoritative for proposal identity and disclosed subject facts.

## Declare templates

Add `taskTemplates` to the Casework project. Each template declares:

- A stable `id`, immutable `version`, and human-readable `label`.
- `eligibleTeams`, human Staff/Supervisor `eligibleProfiles`, and `source`.
- `reviewKinds` for unified review tasks, or `itemKinds` plus eligible
  `itemStates` for retained source work items. A template cannot mix the two.
- Exact `agent: {issuer, subject}`, OAuth `client`, one absolute `resource`,
  and `purpose`, plus explicit OAuth `scopes` for that resource.
- `bounds`, one of `{type: evidence, requirement: ...}`,
  `{type: breg, permissions: [{collection: ..., operations: [...]}]}`, or
  `{type: scheduling, permissions: [{service: ..., location: ...,
  actions: [...]}]}`.
- `subjects`, mapping token identity keys to governed source logical fields.
- `lifetimeSeconds`, an explicit approved duration. Omitted `authorizationMode`
  means `immediate`, with a 900-second ceiling. Opt in with
  `authorizationMode: deferred` for a duration of at most 604800 seconds
  (seven days). Seven days is an initial hard ceiling, not a default duration.
  The preview shows this mode and duration before approval.

Scopes are immutable approved authorization, not inferred from product operations.
The assertion includes those scopes, and stock token exchange only accepts a
requested subset. Use exact product operation names. Wildcards and duplicate bounds are refused.
A registry operation under `bounds.permissions[].operations` is a local
identifier: a lowercase letter, then at most 63 lowercase letters, digits,
underscores, or hyphens, so `apply-request` and `apply_request` are both
well formed and the registry decides which one it knows. Any other value is
refused as `casework.task-template.invalid-operation` at the operation's own
pointer.
Required source fields must be disclosed to the approving human and exposed to
the configured service reader for later checks. Callers cannot supply subject
values. Changing a template requires a new version. Retiring a version
invalidates its live grants; reactivation does not restore those grants.

Scheduling permissions use the same strict claim grammar its runtime verifies:
one to 64 unique `(service, location)` pairs, each with one to 32 unique action
names. Services and locations are exact, whitespace-free values with no
wildcard. Actions are lowercase operation names such as
`appointment.create`, `appointment.reschedule`, `appointment.cancel`,
`hold.create`, or `hold.release`. Casework copies these governed bounds into
the signed assertion; it does not import Scheduling or infer an offering.

## Configure the authority

Runtime `taskAuthority` declares assertion `issuer`, `exchangeAudience`,
`signingKeyRef`, and `statusClients`. Register its public JWKS, served at
`/.well-known/jwks.json`, with the token-exchange issuer. Keep the private ES256
or RS256 signing key in the configured secret provider, with its registered key
identifier.

The signed assertion identifies the grant and its immutable bounds. The token
exchange issuer derives `registry_grant_source_issuer` from the verified
assertion issuer instead of accepting an assertion-supplied source issuer.
Casework retains that issuer and returns it as `sourceIssuer` from the status
endpoint.

Include agent and resource status clients in OIDC `allowedClients`. Template
agent issuers must match that verifier. Register the agent's client-credentials
bootstrap for only the Casework resource and `casework:grants:assert`. Register
token exchange separately for its exact resource and access scopes. The agent
uses its own `private_key_jwt` credential for both requests.

Optionally add `assertionIssuers` alongside `allowedClients` to bind a client to
the assertion authorities its tokens may claim. When a client has an entry
there, a token presented to Casework that carries `registry_assertion_issuer`
is accepted only if that value is one of the client's listed authorities; a
token without the claim, such as the agent's client-credentials bootstrap, is
unaffected.

`statusClients` maps each resource server's service client to one exact resource
audience. These clients use `casework:grants:status`. Configure the matching
Base Registry Engine (BReg) [`taskGrantStatus`](../breg/TASK_GRANTS.md) entry for
governed writes.

## Preview and approve

1. The current eligible holder reads
   `GET /v1/review-tasks/{taskId}/task-templates` using Casework and source
   profiles. Retained source work items use
   `GET /v1/work-items/{itemId}/task-templates`. The response includes the
   current task or item revision and the exact disclosed authorization to
   review.
2. After explicit approval, call
   `POST /v1/review-tasks/{taskId}/task-grants`, or the retained
   `POST /v1/work-items/{itemId}/task-grants`, with only `templateId` and
   `templateVersion`, current `If-Match`, and `Idempotency-Key`. Casework
   rechecks the exact holder, eligibility, proposal identity, and subject facts.
3. The agent obtains its bootstrap token and calls
   `POST /v1/task-grants/{grantId}/assertion` with an empty body. This endpoint
   rejects human profile headers and verifies the exact agent tuple.
4. Exchange the assertion using RFC 8693. Assertions last at most 60 seconds;
   access tokens last at most 300 seconds. Neither extends the grant deadline.

The Casework clients expose `task_assertion_endpoint(grant_id)` (or
`taskAssertionEndpoint(grantId)` in Node) for the exact empty-POST route. Pass
that endpoint to a shared `exchange` authorization option with a
Casework-audience bootstrap scoped only to `casework:grants:assert`. The
provider checks the grant, client, resource, scopes and deadline in each fresh
assertion before exchanging it. Its cache ends by the grant deadline; renewal
asks Casework again, so an inactive grant cannot issue another access token.

The unified Node/Python Casework clients expose these operations. Credentials
stay on the server. Exact approval retries return the original grant without
extending its deadline. New authorization requires explicit new approval and a
new grant ID. Listings omit retained subject selectors.

## Revocation and status

Any officer with a profile and team membership eligible under the grant template
for the task's queue can call
`POST /v1/review-tasks/{taskId}/task-grants/{grantId}/revoke` with an empty
body. Retained work-item grants use the corresponding `/v1/work-items` route.
Revocation does not require holding the task or reading its source.
Resource servers call `GET /v1/task-grants/{grantId}/status`; inactive status
returns no grant detail. Machine callers cannot substitute resources or subjects.

Retained work-item grants use the existing transactional item and directory
triggers: definitive holder/state/proposal loss invalidates the grant and records
history even without a status observation. Benign revision changes do not.
Retired templates and observed definitive subject changes also invalidate grants.
Deferred review grants pin an assignment generation: release, reassignment, queue movement, absence-cover
change, decision, and completion change it in the same task transaction. A
release followed by reclaim cannot revive the approval even if no status check
observed the intervening release. Immediate review grants keep the exact
ordinary task revision; deferred review grants allow draft revision changes
while the assignment, subject, proposal, and disclosed facts stay unchanged.
Temporary source failure refuses the current request without permanent
invalidation. A mutable source revision alone does not change frozen proposal
identity.

Offline reads may continue until the earlier access-token or grant deadline.
BReg checks fresh status before new writes, later approval, and application.
Scheduling deployments using deferred work configure `taskGrantStatus` and
check fresh exact status before every capacity command and receipt replay.
With no status registry, Scheduling permits only authorization with at most
900 seconds remaining; the final fifteen minutes of a deferred grant can also
use this legacy offline path, with that bounded stale-authority window.
A configured registry never falls back when status is unavailable or inactive.
There is no distributed transaction between a status observation and a resource
commit. Scheduling also rechecks the earlier execution-token and grant expiry
under its capacity locks, so waiting for a lock cannot carry an expired execution
credential into a later commit.
Evidence wallet-delivery deferred offers carrying a task grant remain refused.

## Resume deferred work

Retain the grant ID, original deadline, and the owning product's logical
operation/idempotency key. After waiting or restarting, authenticate as the
same agent and construct a fresh exchange provider using the original grant
reference and deadline. An assertion refresh is neither a new authorization
nor a new operation. Expiry or cancellation requires an explicit new decision;
there is no fallback to standing service authority.

This mode retains the current holder's continuing authority. It does not
survive release, reassignment, or completion of the review task. Keep that task
active while the approved deferred work waits, then complete it when the
workflow no longer needs the authorization. An institutional decision that
survives task completion requires a separately designed policy.

The grant limits allowed operations, resources, principal, purpose, subject
facts, and deadline. It does not promise one business effect. Each resource
server owns its atomic business limits and duplicate rules; preserve the same
operation key across refresh and restart to recover the same effect. A new key
names a new logical operation, still inside the approved bounds.

Source proposal version, digest/integrity, binding generation, and exact
subject facts are material. Unrelated source revision churn is not. Temporary
source/status failure refuses the current attempt and can be retried; an
observed definitive change invalidates permanently. Review directory eligibility
is checked at observation, so removing and restoring a membership between
observations is not a historical revocation signal. Use explicit revocation
when authority must stay withdrawn.
