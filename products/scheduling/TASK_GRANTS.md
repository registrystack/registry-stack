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

The bounds are matched once, at the service, before the capacity transaction
opens. Inside the transaction, immediately before the claim commits, exactly
one fact is read again: the grant's own expiry, against the clock that
commitment is decided under. A grant that expired between the door and the
commit cannot take capacity, and the attempt answers
`operation.not-authorized` like any other authority refusal.

The bounds themselves are not read again at that point, and this milestone
has no revocation check, so a grant narrowed or withdrawn at the issuer after
its token was minted keeps the authority its token carries until the token or
the grant deadline passes. Keep grant deadlines short. Re-checking the full
bounds inside the capacity transaction is a recorded deferral, not a promise
this milestone keeps.

## What the audit journal records

Every commitment and every refused commitment writes one authorization record
under `authorization.allowed` or `authorization.refused`, and so does a
permission the service refuses before any commitment is reached. The principal,
client, grant, and approver are keyed pseudonyms scoped to the request's
reference class, the purpose is recorded as presence only and never as a
value, and the record adds the grant's source issuer and its deadline. No
bound value, service, location, or action appears in the journal.

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
    scopes: [scheduling-read, scheduling:commit]
    purpose: schedule-registry-update
    bounds:
      type: scheduling
      permissions:
        - service: registry-update
          location: bangkok-counter
          actions: [appointment.create]
    subjects:
      subject_reference: subject-reference
    lifetimeSeconds: 900
```

`scheduling:commit` is an explicit scope registered at the exchange issuer. The
Scheduling runtime derives mutation authority from the grant bounds rather than
that scope. `scheduling-read` is the starter runtime's default read scope and
lets the same short-lived token select a currently published free start.

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
    allowedClients: [scheduling-agent]
    assertionIssuers:
      scheduling-agent: [https://casework.example.test/task-authority]
```

After a current holder previews and approves the template, put the approved
grant UUID into the existing Casework development exchange path. Its connection
entry selects the Scheduling destination, not policy fields:

```yaml
clients:
  scheduling-agent:
    assertionKeyFile: /absolute/casework/.casework/dev/credentials/scheduling-agent/assertion-key.jwk
    resource: urn:example:scheduling
    scopes: [scheduling-read, scheduling:commit]
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
