# Approve bounded work for an institutional agent

A task grant records a current human ReviewTask holder's explicit approval for
one institutional agent to perform bounded work under its own principal.
Casework grants only from ReviewTask. The trusted producer remains authoritative
for the subject and proposal; the resource server independently authorizes and
commits the agent's operation.

A grant subject binds a row only where the resource server's profile authors a
boundary on that key; for BReg, that is a row boundary on the identity key the
template's `subjects` names. Casework cannot check this, because it never sees
that profile.

## Declare templates

Add `taskTemplates` to the Casework project. Each template declares:

- A stable id as its key under `taskTemplates`, an immutable `version`, and a human-readable `label`.
- `eligibleTeams`, human Staff/Supervisor `eligibleProfiles`, `source`, and
  `reviewPolicies` naming the held ReviewTasks that may issue the grant.
- Exact `agent: {issuer, subject}`, OAuth `client`, one absolute `resource`,
  and `purpose`, plus explicit OAuth `scopes` for that resource.
- `bounds`, one of `{type: evidence, requirement: ...}`,
  `{type: breg, permissions: [{collection: ..., operations: [...]}]}`, or
  `{type: scheduling, permissions: [{service: ..., location: ...,
  actions: [...]}]}`.
- `subjects`, mapping token identity keys to governed source logical fields.
  The review policy's source must serve task-grant context. A BReg-backed
  policy needs the provider's distinct `task-grant-context` capability and a
  source profile granting `get-task-grant-context` for the exact fields. When
  that capability is absent, `caseworkctl check` and the runtime refuse the
  template as `casework.task-template.unserved-capability`.
- `lifetimeSeconds`, an explicit approved duration. Omitted `authorizationMode`
  means `immediate`, with a 900-second ceiling. Opt in with
  `authorizationMode: deferred` for a duration of at most 604800 seconds
  (seven days). Seven days is an initial hard ceiling, not a default duration.
  The preview shows this mode and duration before approval. A deferred grant
  cannot carry bounds of type `evidence`: Evidence checks the grant deadline
  and no grant status, so an Evidence grant keeps the 900-second immediate
  window, and `caseworkctl check` reports the combination as
  `casework.task-template.deferred-evidence`.

Scopes are immutable approved authorization, not inferred from product operations.
The assertion includes those scopes, and stock token exchange only accepts a
requested subset. Use exact product operation names. Wildcards and duplicate bounds are refused.
A registry operation under `bounds.permissions[].operations` is a local
identifier: a lowercase letter, then at most 63 lowercase letters, digits,
underscores, or hyphens, so `apply-request` and `apply_request` are both
well formed and the registry decides which one it knows. Any other value is
refused as `casework.task-template.invalid-operation` at the operation's own
pointer.
For BReg, bind a named Action or Proposal operation and its exact target
scope. A task grant does not authorize an arbitrary direct record write;
BReg checks its own governed operation and the current grant status before
commit.
Required current-source fields must be disclosed to the approving human and
available through the provider's separate `task-grant-context` capability for
later checks. For BReg, Casework uses the provider's separately authored
`taskGrantProfile`; there is no fallback to its human display or status
profiles. BReg verifies the frozen Proposal identity and contract, the exact
accepted review-policy binding, the current non-withdrawn source acceptance,
and current disclosure for every requested field. Submitted-context grants use
the admitted snapshot. Callers cannot supply subject values. Changing a
template requires a new version. Retiring a version invalidates its live
grants; reactivation does not restore those grants.

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
   `GET /v1/review-tasks/{taskId}/task-templates` using the Casework profile
   and, for current-source context, the human's source profile. The response
   includes the current task revision and exact disclosed authorization to
   review.
2. After explicit approval, call
   `POST /v1/review-tasks/{taskId}/task-grants` with only `templateId` and
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
body.
Revocation does not require holding the task or reading its source.
Resource servers call `GET /v1/task-grants/{grantId}/status`; inactive status
returns no grant detail. For the status check, machine callers cannot substitute
resources or subjects. That says nothing about which rows the resource server
binds; see the row-binding paragraph near the top of this page.

Retired templates and observed definitive subject changes invalidate grants.
Deferred grants pin an assignment generation: release, reassignment, queue movement, absence-cover
change, decision, and completion change it in the same task transaction. A
release followed by reclaim cannot revive the approval even if no status check
observed the intervening release. Immediate grants keep the exact
ordinary task revision; deferred grants allow draft revision changes
while the assignment, subject, proposal, and disclosed facts stay unchanged.
Temporary source failure refuses the current request without permanent
invalidation. A mutable source revision alone does not change frozen proposal
identity.

The approving officer's own source access is checked once, at approval, with
that officer's credential. Later observations read the source with the
configured service reader: they recheck the officer's Casework eligibility,
the proposal, and the disclosed facts, but not whether the source still lets
that officer read the record. A withdrawal of that source access alone leaves
the grant active until its deadline: at most 900 seconds for an immediate
grant, and up to the template's `lifetimeSeconds`, at most seven days, for a
deferred one. When an officer loses source access, also revoke their live
grants or remove their Casework eligibility, which ends each grant at its next
observation, and keep deferred lifetimes no longer than the work needs.

Offline reads may continue until the earlier access-token or grant deadline.
BReg checks fresh status before new writes, later approval, and application.
Scheduling deployments using deferred work configure `taskGrantStatus` and
check fresh exact status before every capacity command and receipt replay.
A Scheduling deployment that instead writes
`taskGrantStatus: unchecked-final-fifteen-minutes` permits only authorization
with at most 900 seconds remaining; the final fifteen minutes of a deferred
grant can also use this offline path, with that bounded stale-authority window.
A configured registry never falls back when status is unavailable or inactive.
There is no distributed transaction between a status observation and a resource
commit. Scheduling also rechecks the earlier execution-token and grant expiry
under its capacity locks, so waiting for a lock cannot carry an expired execution
credential into a later commit.
Evidence wallet-delivery deferred offers carrying a task grant remain refused.

## How long authority outlives a change

A change made at the task authority (a revocation, a decision, a release, a
retired template) reaches each resource server at a different speed. This table
gives the longest time each piece of authority can keep working after the
change, with the constant that sets it and what an operator can do to cut it
short. Casework owns the task-grant pages, and no single document owns
cross-product security guidance, so the map sits here.

| Piece of authority | Longest life | Set by | What cuts it short |
| --- | --- | --- | --- |
| Task assertion | 60 seconds, or the grant deadline if that is earlier | `TASK_ASSERTION_LIFETIME_SECONDS` in `crates/registry-casework-core/src/task_grant.rs:11`, applied at `crates/registry-casework/src/task_grants.rs:814` | Nothing after it is issued. Revoking the grant stops any new assertion, because each request rechecks the grant. |
| Access token from token exchange | At most 300 seconds, per this page's exchange step; the exchange issuer's configuration sets it. BReg refuses a token that carries a task grant and was issued for more than 900 seconds (`MAX_TASK_GRANT_TOKEN_LIFETIME_SECONDS` in `crates/registry-breg/src/auth.rs`). | The exchange issuer | Shorten the lifetime at the issuer. BReg mutations check fresh status and refuse the token once the grant is revoked. Scheduling checks fresh status when `taskGrantStatus` lists authorities; with `unchecked-final-fifteen-minutes` it does not, and a revoked grant keeps working for its last 900 seconds. BReg reads and Evidence do not check status, so a read keeps working until the token or the grant expires. |
| Immediate grant | 900 seconds | `TASK_GRANT_LIFETIME_SECONDS` in `crates/registry-casework-core/src/task_grant.rs:10` | Revoke the grant; release, reassign or decide the task; change the subject; retire the template. Casework applies each at the next assertion request or status check. |
| Deferred grant | 7 days (604800 seconds), the ceiling for `lifetimeSeconds` | `DEFERRED_TASK_GRANT_LIFETIME_SECONDS` in `crates/registry-casework-core/src/task_grant.rs:13` | The same actions as an immediate grant; the decision on the review task ends it. Write a shorter `lifetimeSeconds`. Withdrawing the officer's source access alone does not end it. |
| Offline read at Evidence | The grant deadline, checked at admission and again immediately before release (a late result is refused with 403); the access token expiry is checked once, at admission | the evaluation-deadline paragraph of `products/evidence/OPERATOR-CONTRACT.md` | Keep Evidence grants at the 900-second immediate window. Deferred grants cannot carry Evidence bounds. |
| Signing key set cached by a resource server | 600 seconds, plus 900 seconds served from the old key set while the issuer is unreachable, so up to 1500 seconds | `JwksFetcherConfig::defaults` in `crates/registry-platform-oidc/src/lib.rs:398,403`; the sum is `tolerated_age` at line 642. BReg reads both values from its runtime file, defaulting to the same numbers (`crates/registry-breg/src/runtime_config.rs:75,80`). | List the key in `authentication.oidc.revokedKeyIds` and restart every instance; the list is read at startup and is local to that service. Also revoke the key at the issuer and at every other relying party. |
| BReg status check of a task grant | One fresh check per mutation attempt; never cached. Each HTTP request times out after 5 seconds (3 seconds to connect), and the whole attempt, including getting the service credential, is cut off after 10 seconds. A failure or timeout refuses the mutation. | `crates/registry-platform-oidc/src/task_grant.rs:182,183,210` | Nothing to configure; revoking the grant takes effect at the next attempt. |

Revoking a grant at Casework does not recall a token already issued. A resource
server learns of the revocation only when it asks for status.

## Resume deferred work

Retain the grant ID, original deadline, and the owning product's logical
operation/idempotency key. After waiting or restarting, authenticate as the
same agent and construct a fresh exchange provider using the original grant
reference and deadline. An assertion refresh is neither a new authorization
nor a new operation. Expiry or cancellation requires an explicit new decision;
there is no fallback to standing service authority. Deferred work reaches BREG
or Scheduling only: deferred grants cannot carry Evidence bounds, because
Evidence accepts a grant until its deadline without checking its status.

This mode retains the current holder's continuing authority. It does not
survive release, reassignment, a decision on the review task, or completion of
the review task. A deferred grant ends when the review task is decided: the next
assertion request or status check finds the task no longer claimed and
invalidates the grant. Keep that task claimed and undecided while the approved
deferred work waits, then decide it when the workflow no longer needs the
authorization. An institutional decision that survives the review decision
requires a separately designed policy.

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
