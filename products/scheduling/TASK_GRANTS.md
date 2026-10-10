# Task grants for scheduling commitments

A task grant gives an institutional agent bounded authority to commit
Scheduling capacity under its own principal. It does not make the agent the
human who approved the task, it carries no catalogue or availability read
authority, and it never decides eligibility: whether a party may hold a
service remains with the source system that owns the rule.

The three authority profiles are disjoint. A token carrying a product scope
does not thereby gain a commitment path, and a task grant does not by itself
grant a catalogue read. Scopes authorize reads and the separately configured
explain scope authorizes the diagnostic read; every commitment takes its
authority from the grant alone. One access token may carry both profiles, but
each operation still checks only its own authority.

## The claim set

A commitment requires no product scope. Its authority is the grant inside the
access token, whether or not that token also carries read scopes: the six
`registry_grant_*` members (`registry_grant_id`,
`registry_grant_source_issuer`, `registry_grant_client`,
`registry_grant_resource`, `registry_grant_exp`, `registry_grant_bounds`),
plus `registry_purpose` and `registry_approver`. A token carrying none of
them is an ordinary standing token; a token carrying some of them is refused
as a malformed credential rather than honored partially.

Before the caller reaches the service, the runtime binds the grant to two
facts it verified itself: the grant's client must equal the client the
deployment verified (`azp` or `client_id`), and the grant's resource must
equal this deployment's configured OIDC audience. A grant minted for another
product's resource is a profile refusal here, and the closed union of bounds
makes it one in every verifier: an unknown bounds tag is a malformed claim,
so a grant minted for one product can never be interpreted by another
product's runtime.

## The scheduling bounds

The bounds are `{"type": "scheduling", "permissions": [...]}`. One permission
names a service, a location, and the actions it allows there:

```json
{
  "type": "scheduling",
  "permissions": [
    {
      "service": "registry-update",
      "location": "bangkok-counter",
      "actions": ["appointment.create", "appointment.reschedule"]
    }
  ]
}
```

The action vocabulary is closed, and it is the vocabulary the runtime knows:

- `hold.create` and `hold.release`
- `appointment.create`, `appointment.reschedule`, and `appointment.cancel`

The bounds a signed claim may carry are bounded exactly as BREG's are:

- at most 64 permissions, each a unique `(service, location)` pair;
- at most 32 actions per permission, each at most 128 bytes;
- service and location values of at most 512 bytes, without whitespace,
  control characters, or a `*`.

Wildcards are refused, unknown members are refused at every level rather than
ignored, and duplicate actions or duplicate pairs are refused. Nothing about a
permission is optional: an empty `actions` list is malformed, not a grant to
read.

An issuer may mint the `scheduling` tag only once every verifier it targets
understands it. A verifier built before the tag existed rejects the whole
grant as malformed, which is the intended fail-closed direction; an operator
rolling a verifier back past that point needs to know it. The review record
in `crates/registry-platform-oidc/README.md` carries the threat model and the
release note to update when the first accepting release is cut.

## How the runtime matches a permission

A permission matches an offering only when its service equals the offering's
service, its location equals the offering's location, and its action list
names the operation the route performs. The match is exact: a broader service
or location never covers a narrower one, and no rule maps one location onto
another. A grant that does not cover the request answers
`operation.not-authorized` and nothing is written.

The bounds are matched at the service before the capacity transaction opens.
When `taskGrantStatus` is configured, Scheduling first obtains a fresh answer
from the authority selected by the signed grant's source issuer. The answer
must say the grant is active and must reproduce the exact grant id, source
issuer, principal, client, resource, purpose, bounds, signed subject values,
and deadline. Scheduling does not cache a positive answer. It checks again for
an idempotent receipt replay, so revocation also closes that path.

The complete status attempt, including acquisition of Scheduling's service
credential, is limited to ten seconds. An inactive, unlisted, mismatched, or
incompletely bound grant answers `operation.not-authorized`. An authority or
service credential outage, including an unusable authority response, answers
`service.unavailable`. HTTP 401 or 403 from the status endpoint indicates
Scheduling's service credential was rejected, so the observation is unavailable;
it does not establish inactive task authority. HTTP 404 remains a grant refusal.
The status call happens
before the capacity transaction opens, so no capacity lock is held while
Scheduling waits on another product. The answer is a fresh observation, not a
distributed transaction with the authority: a withdrawal after a positive
answer can race the in-flight local commit.

Inside the transaction, after every lock wait and immediately before commit,
Scheduling checks the earlier of the verified access token deadline and the
grant deadline against the transaction clock. A credential that expires after
the status answer cannot take capacity through a delayed transaction.

An entirely unconfigured deployment retains the legacy offline path only for
a grant with no more than 900 seconds remaining at request entry. Configuring
even one `taskGrantStatus` entry disables that fallback for every source,
including an unlisted one. Because the token does not name its authorization
mode, the final 15 minutes of an originally deferred grant can use the legacy
path if its deployment remains unconfigured. Configure status for every new
deployment that accepts deferred grants.

## What the audit records

Every commitment writes a `request` entry before its capacity transaction opens
and a `response` entry carrying its authorization decision, under
`authorization.allowed` or `authorization.refused`, once the transaction
commits or rolls back. A permission the service refuses before any commitment
is reached writes one `response` entry. The principal, client, grant, and
approver are keyed pseudonyms scoped to the request's reference class, the
purpose is recorded as presence only and never as a value, and the record adds
the grant's source issuer and its deadline. No bound value, service, location,
or action appears in the audit.

## Where a grant comes from

Scheduling verifies grants; it does not approve them. A grant is minted by the
token-exchange issuer from a template a current human holder approved, and the
approver's identity travels in the claim. Casework's maintained task authority
accepts Scheduling bounds directly, and stock ThunderID's institutional grant
exchange copies those verified bounds into the access token. Scheduling is a
relying party of that authority and inherits no Casework authorization.
The maintained native boundary fixture passes that exact stock-issued bearer,
its public JWKS, and bounded deployment identity over stdin to Scheduling's
real `SchedulingAuthenticator`; the credential never enters argv or test logs.

The Casework project declares the exact destination in a governed template:

```yaml
taskTemplates:
  - id: schedule-registry-update
    version: "1"
    label: Book a registry update
    eligibleTeams: [registry-review]
    eligibleProfiles: [staff]
    source: registry-requests
    itemKinds: [request]
    itemStates: [claimed]
    agent:
      issuer: https://identity.example.test/realms/registry
      subject: scheduling-agent-service-account
    client: scheduling-agent
    resource: urn:example:scheduling
    scopes: [scheduling:read, scheduling:commit]
    purpose: schedule-registry-update
    bounds:
      type: scheduling
      permissions:
        - service: registry-update
          location: bangkok-counter
          actions: [appointment.create]
    subjects:
      subject_reference: subject-reference
    authorizationMode: deferred
    # Deferred grants choose an explicit lifetime, up to seven days.
    # Immediate grants retain their 900-second maximum.
    lifetimeSeconds: 86400
```

`scheduling:commit` is an explicit scope registered at the exchange issuer. The
Scheduling runtime derives mutation authority from the grant bounds rather than
that scope. The native exchange uses the issuer-compatible `scheduling:read`
handle, so this runtime sets `readsScope: scheduling:read`; `scheduling-read`
remains the compatibility default. The read scope lets the same short-lived
token select a currently published free start.

Register `scheduling-agent` as a Casework `taskExchange` service client, and
register `urn:example:scheduling` plus those scopes at the shared issuer. In the
Scheduling runtime, use that issuer and audience, admit the client, and bind it
to the Casework task authority:

```yaml
authentication:
  oidc:
    issuer: https://identity.example.test/realms/registry
    audience: urn:example:scheduling
    scopeClaim: scope
    readsScope: scheduling:read
    allowedClients: [scheduling-agent]
    assertionIssuers:
      scheduling-agent: [https://casework.example.test/task-authority]

taskGrantStatus:
  - sourceIssuer: https://casework.example.test/task-authority
    baseUrl: https://casework.example.test
    tokenEndpoint: https://identity.example.test/realms/registry/protocol/openid-connect/token
    clientAssertionAudience: https://identity.example.test/realms/registry
    clientId: scheduling-task-status
    privateKeyRef: secret:file/scheduling-task-status-private-jwk
    caseworkResource: urn:example:casework
```

Register `scheduling-task-status` with the identity provider for private-key
JWT client authentication and as a Casework client allowed to read grant
status. `privateKeyRef` resolves its private JWK. Add `caBundleRef` when the
token endpoint or Casework uses a private CA. Each configured source issuer is
pinned to its own endpoint and service credential; duplicate sources are a
startup refusal.

After a current holder previews and approves the template, put the approved
grant UUID into the existing Casework development exchange path. Its connection
entry selects the Scheduling destination, not policy fields:

```yaml
secretProviders:
  file:
    root: /absolute/casework/.casework/dev/credentials/scheduling-agent
clients:
  scheduling-agent:
    assertionKeyRef: secret:file/assertion-key.jwk
    resource: urn:example:scheduling
    scopes: [scheduling:read, scheduling:commit]
```

```sh
caseworkctl dev grant scheduling-agent \
  --grant APPROVED_UUID \
  --connection /absolute/scheduling-connection.yaml \
  /absolute/casework
```

The command reports an owner-only header file and the immutable grant deadline.
Use that header to read a free start, then book it. Set `START` and
`POLICY_REVISION` from the availability response:

```sh
curl --fail-with-body \
  -H "$(cat "$HEADER_FILE")" \
  "$SCHEDULING_URL/v1/availability?offering=registry-update-30"

curl --fail-with-body -X POST \
  -H "$(cat "$HEADER_FILE")" \
  -H 'content-type: application/json' \
  -H 'idempotency-key: approved-registry-update-1' \
  --data @- "$SCHEDULING_URL/v1/appointments" <<JSON
{"admission":{"offering":"registry-update-30","start":"$START","party":{"recipients":1,"attendees":1},"duplicateKey":"subject:approved-request","policyRevision":$POLICY_REVISION,"capabilities":[],"prerequisites":[]}}
JSON
```

The approval surface, full template grammar, exchange setup, and revocation are
documented in [`../casework/TASK_GRANTS.md`](../casework/TASK_GRANTS.md) and
[`../casework/DEV-SOURCES.md`](../casework/DEV-SOURCES.md). A standalone
external authority can issue the same closed claim contract; Casework is the
maintained in-stack approval path rather than a required Scheduling runtime
dependency.

Scheduling has no route that books on another party's behalf, and a grant does
not create one: the Phase 1 scope records guest booking, a holder booking for
someone else, as an explicit exclusion.
