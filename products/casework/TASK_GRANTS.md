# Approve bounded work for an institutional agent

A task grant records a current human holder's explicit approval for one
institutional agent to perform a bounded task under its own principal. This
surface applies to source-backed work items. The source remains authoritative
for proposal identity and disclosed subject facts. Hosted decisions retain
their separate workflow.

## Declare templates

Add `taskTemplates` to the Casework project. Each template declares:

- A stable `id`, immutable `version`, and human-readable `label`.
- `eligibleTeams`, human Staff/Supervisor `eligibleProfiles`, `source`,
  `itemKinds`, and eligible `itemStates`.
- Exact `agent: {issuer, subject}`, OAuth `client`, one absolute `resource`,
  and `purpose`.
- `bounds`, either `{type: evidence, requirement: ...}` or
  `{type: breg, permissions: [{collection: ..., operations: [...]}]}`.
- `subjects`, mapping token identity keys to governed source logical fields.
- `lifetimeSeconds`, no more than 900 seconds.

Use exact product operation names. Wildcards and duplicate bounds are refused.
Required source fields must be disclosed to the approving human and exposed to
the configured service reader for later checks. Callers cannot supply subject
values. Changing a template requires a new version. Retiring a version
invalidates its live grants; reactivation does not restore those grants.

## Configure the authority

Runtime `taskAuthority` declares `id`, assertion `issuer`, `exchangeAudience`,
`signingKeyRef`, and `statusClients`. Register its public JWKS, served at
`/.well-known/jwks.json`, with the token-exchange issuer. Keep the private ES256
or RS256 signing key in the configured secret provider, with its registered key
identifier.

Include agent and resource status clients in OIDC `allowedClients`. Template
agent issuers must match that verifier. Register the agent's client-credentials
bootstrap for only the Casework resource and `casework:grants:assert`. Register
token exchange separately for its exact resource and access scopes. The agent
uses its own `private_key_jwt` credential for both requests.

`statusClients` maps each resource server's service client to one exact resource
audience. These clients use `casework:grants:status`. Configure the matching
BREG [`taskGrantStatus`](../breg/TASK_GRANTS.md) entry for governed writes.

## Preview and approve

1. The current eligible holder reads
   `GET /v1/work-items/{itemId}/task-templates` using Casework and source
   profiles. The response includes current item revision and the exact
   disclosed authorization to review.
2. After explicit approval, call
   `POST /v1/work-items/{itemId}/task-grants` with only `templateId` and
   `templateVersion`, current `If-Match`, and `Idempotency-Key`. Casework
   rechecks eligibility, proposal identity, and subject facts.
3. The agent obtains its bootstrap token and calls
   `POST /v1/task-grants/{grantId}/assertion` with an empty body. This endpoint
   rejects human profile headers and verifies the exact agent tuple.
4. Exchange the assertion using RFC 8693. Assertions last at most 60 seconds;
   access tokens last at most 300 seconds. Neither extends the grant deadline.

The unified Node/Python Casework clients expose these operations. App Kit's
source-item view provides review, approval, retry, listing, and revocation.
Credentials stay on the server. Exact approval retries return the original
grant without extending its deadline. New authorization requires explicit new
approval and a new grant ID. Listings omit retained subject selectors.

## Revocation and status

An eligible current holder calls
`POST /v1/work-items/{itemId}/task-grants/{grantId}/revoke` with an empty body.
Resource servers call `GET /v1/task-grants/{grantId}/status`; inactive status
returns no grant detail. Machine callers cannot substitute resources or subjects.

Holder eligibility loss, retired templates, and definitive proposal or subject
changes permanently invalidate grants. Temporary source failure refuses the
current request without permanent invalidation. A mutable source revision alone
does not change frozen proposal identity.

Offline reads may continue until the earlier access-token or grant deadline.
BREG checks fresh status before new writes, later approval, and application.
There is no distributed transaction between that check and the resource commit.
Task-bound deferred wallet offers are refused.
