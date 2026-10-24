# Scheduling runtime configuration

Scheduling reads one versioned operator document selected with
`scheduling --runtime-config ABSOLUTE_FILE serve`, and `schedulingctl plan`,
`schedulingctl apply`, and `schedulingctl status` read the same document with
`--runtime-config ABSOLUTE_FILE`. The selected
file path and every operated resource path are absolute, and none may pass
through a symbolic link. Local development tooling may resolve paths before it
writes the file. The file is read through the shared Registry Stack runtime
configuration loader: it must be a YAML mapping of at most 1 MiB, and unknown
keys are refused with the path of the offending field.

String values in `runtime.yaml` may take a deployment value from the
environment when the runtime starts: `${VAR}` requires `VAR`, `${VAR:-default}`
falls back to `default`, and `${VAR:?message}` refuses to start with `message`
when `VAR` is unset. Substitution never applies to a field whose name ends in
`Ref` or `Refs`, or to any value beneath one, because a secret reference must
be written literally and resolved by a declared provider. It never applies to
the authored `scheduling.yaml` or to the records and fixture documents the
authoring tooling reads either: an environment expression there is refused
with the path of the field that holds it.

The closed envelope is:

```yaml
apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1
kind: SchedulingRuntimeConfig
```

The earlier `registry.registrystack.org/scheduling-runtime/v1alpha1` envelope
is refused with a diagnostic naming this one. So are the renamed keys
`audit.retainDays`, `retention.attemptReceiptDays`,
`retention.attemptReceiptRetentionDays`, `retention.hookPayloadDays`, and
`caseworkResource` in a `taskGrantStatus` entry, each naming the key that
replaced it.
`schedulingctl check PROJECT --runtime-config FILE` reads a runtime file the
way startup does, against the project's policy, with no package, database,
network, or secret material, and reports every refusal at its file, line,
column, and JSON pointer. It does not read `package.root`; `scheduling serve`
verifies the package at startup. `--environment` fills the file's `${NAME}`
expressions from the current environment first.

`package.root` selects one directory. The runtime always loads
`package.root/scheduling.yaml`; no second project selector can override it. In
every listener mode, with or without `package.expectedDigest`, the directory
must be a package `schedulingctl package --output` wrote: a `SHA256SUMS` file
listing exactly `scheduling.yaml`, whose bytes match the listed digest. A
changed, missing, or extra file is refused by name, and so is a directory
without `SHA256SUMS`, such as an authored project; each refusal names
`schedulingctl package`.

`package.expectedDigest` optionally pins the package the runtime must serve:
`sha256:` followed by 64 lowercase hexadecimal digits, the `packageDigest`
`schedulingctl package` prints, which is the SHA-256 digest of the package's
`SHA256SUMS`. Any other package is a startup refusal that names the expected
digest and the one found.

`identity.databaseId` is required: an operator-chosen logical id for the
database this deployment owns, such as `scheduling-production`, non-empty, at
most 256 bytes, without surrounding whitespace or control characters. It is
never derived from a URL or a PostgreSQL database name. The first
`schedulingctl apply` records it in the activation ledger. Every later apply,
`records apply`, and startup refuses a configuration whose
`identity.databaseId` differs from the recorded one, naming only the key, so
two deployments pointed at one database by mistake cannot activate over each
other.

The runtime serves only the package the activation ledger names. Startup
reads the ledger with the runtime credential and writes no activation state:
it refuses when no package has been applied, when the verified package at
`package.root` is not the active one, and when the ledger belongs to another
`identity.databaseId`. Each refusal names `schedulingctl plan --runtime-config
FILE` then `schedulingctl apply --runtime-config FILE`.

`listener` is required. `listener.bind` is required and is one numeric
socket address, including bracketed IPv6 forms. `listener.tlsTermination` is
required. Use
`operator-controlled-upstream` behind an operator-managed TLS edge or
`development-loopback` for direct local development, which the runtime refuses
on any non-loopback bind. `listener.networkExposure` defaults to
`private-address`; `container-private` permits an unspecified bind only for a
listener kept on a private container network. A public unicast address is
refused under every combination: Scheduling does not serve a public interface
by itself.

`secretProviders` explicitly enables each accepted reference form. Declare
`file: {root: ABSOLUTE_DIRECTORY}` before using `secret:file/name`. Declare
`environment: {}` before using `secret:env/NAME`. The runtime does not fall
back from one provider to another. The maintained example uses mounted files.

A secret reference is `secret:env/NAME` with an uppercase environment name, or
`secret:file/name` with a lowercase file name, each of at most 128 bytes. A
resolved value is non-empty text of at most 64 KiB without NUL bytes. A secret
file must be a regular file owned by the runtime user, with mode 0400 or 0600
and exactly one hard link; `openssl rand -hex 32` generates the audit key.

`database.runtimeUrlRef` supplies the least-privilege service connection and
`database.migrationUrlRef` supplies the operator-run migration connection.
`schedulingctl plan` and `schedulingctl status` connect with the runtime
credential and only read; `schedulingctl apply` connects with the migration
credential. A `plan` whose runtime role cannot read an existing activation
ledger, such as one rotated in after the last apply, is refused with
`schedulingctl.activation.ledger-unreadable`, naming `schedulingctl apply
--runtime-config FILE` to grant it, then `schedulingctl plan --runtime-config
FILE`. When the two credentials log in as different PostgreSQL roles
(split role mode), apply grants the runtime role USAGE on the schema,
SELECT, INSERT, UPDATE, and DELETE on its tables, use of its sequences, and
EXECUTE on its functions (only the `scheduling_*` objects and the platform
hook delivery tables Scheduling installs, never another application's objects
in a shared schema), then revokes INSERT, UPDATE, DELETE, and TRUNCATE
on the activation ledger and the schema history. It never grants or revokes
TRIGGER: before any migration it refuses a default privilege of the
migration role that would grant the runtime role TRIGGER on the tables it
creates, naming `ALTER DEFAULT PRIVILEGES FOR ROLE <migrator> IN SCHEMA
<schema> REVOKE TRIGGER ON TABLES FROM <grantee>` then a rerun. The runtime role can read the
ledger but not write it; it keeps ordinary write access to the product tables
it serves from. When both
credentials are the same role (single role mode), `plan`, `apply`, and
`status` say so, because that role can write the ledger and the separation
does not hold. The ledger records the runtime role and the mode it holds
after the grants, read from its privileges: a runtime role that can write the
ledger through a grant, ownership, membership in the migration role, or a
superuser or BYPASSRLS attribute is recorded as `single` even when the two
credentials are different roles. Re-running `apply` with the active package
reissues the grants after the runtime role is rotated or the deployment moves
to split mode, and `scheduling serve` refuses a ledger that recorded `split`
for a credential that can now write it. A runtime role that owns, or is a
member of an owner of, the Scheduling schema or any `scheduling_*` table,
sequence, view, or routine, that holds TRIGGER on a `scheduling_*` table or
view, or that holds CREATE on the schema, can write the ledger indirectly,
and so can a trigger already attached to a `scheduling_*` table, since no
Scheduling migration creates one. With two roles, `plan`, `apply`, and
`serve` refuse them. For ownership, the refusal names an exact `ALTER ...
OWNER TO <migrator>` for each affected Scheduling schema object, followed by
`schedulingctl apply --runtime-config FILE`, which reissues the grants the
moved objects lost; `serve` refuses until it has. After
`REVOKE TRIGGER ON <table> FROM <grantee>`, `REVOKE CREATE ON SCHEMA
<schema> FROM <grantee>` (the grantee being the runtime role, PUBLIC, or a
role it is a member of), or `DROP TRIGGER <name> ON <schema>.<table>` it
names a rerun of the refused command, or `schedulingctl plan
--runtime-config FILE` to confirm.
Transport security on the database connection is not optional: Scheduling sets
`sslmode` to `Require` on both connections and refuses a connection it cannot
protect. `database.trustedRootCertificateRef` is optional and selects the PEM
bundle of a private CA in front of PostgreSQL. The one plaintext escape is
`database.testOnlyPlaintext: true`, and only a build carrying the
`postgres-test` feature accepts it; a production build refuses the setting at
startup instead of opening an unencrypted connection. A test build that skips
because its database URL is absent is not database verification, and the
escape never turns a deployed runtime into a plaintext client.

`authentication.oidc` requires `issuer` and `audience`. `jwksSource` defaults
to `type: discovery`. `type: uri` with `uri` fetches the key set from a fixed
HTTPS address instead of the one discovery names; plain `http` is accepted only
for a loopback host under development loopback. `type: static` with
`documentRef` reads a pinned key set, which does no rotation of its own:
rolling a key means replacing the referenced document and restarting
Scheduling. The removed `jwksUri` key is refused with a diagnostic naming
`jwksSource` `type: uri` as its replacement. `scopeClaim` defaults to `scope`,
the claim stock ThunderID emits. `readsScope` defaults to `scheduling:read`
and `explainScope` to `scheduling:explain`; the two must differ, because the explain path can name member-level causes the public
availability read never discloses. `allowedClients` lists the exact client ids
the runtime admits, and every file writes it, development loopback included:
a list of at least one distinct client. An omitted member, an empty list, and
a repeated client are refused when the file is read (`config.missing-key`,
`config.invalid-value`, `config.duplicate-item`). `unrestricted`, which would
admit every client the issuer verifies, including an application in the same
realm that has nothing to do with booking, is a startup refusal in every mode
(`scheduling.runtime.allowed-clients-required`), because a development file
is copied toward production.
A read or explain request whose token lacks the required scope is refused
with `profile.not-authorized`. A rate-limited `info` diagnostic names the fixed
`scope` stage and the `authentication.oidc.scopeClaim`, `readsScope` and
`explainScope` remediation keys, without claim or scope values.

### Operational appointment read profiles

`authentication.oidc.appointmentReadProfiles` is an optional map of separately
authorized operational roles. An absent or empty map grants no cross-owner
appointment access. Each role selects one distinct OAuth scope and explicit
service/location permissions. Resource access is either `type: exact` with
named `ids`, or explicitly `type: unrestricted`. Selecting a profile in a query
does not grant its scope, and scopes from multiple profiles are not combined.

For example, this entry inside `appointmentReadProfiles` permits one bounded
room work list:

```yaml
desk:
  scope: scheduling:appointments:desk
  maximumPastDays: 7
  maximumFutureDays: 30
  maximumSpanDays: 7
  permissions:
    - service: room-reservation
      location: community-hall
      resources:
        type: exact
        ids: [room-a, room-b]
  projection:
    fields: [occupied-interval, resource, units, party-counts]
```

The response always includes appointment identity, revision, service, location,
offering, state and displayed interval. Optional fields require an explicit
projection. `party-counts` returns persisted counts only when known; it never
derives a headcount from capacity units. `externalReferenceProducts` separately
permits filtering and returning references from listed source products. No
profile exposes owner, actor, manager identity, names, contacts or party
references. Restrict both projection and export storage to the operational need.

`GET /v1/operational/appointments` requires service, location, start, end and
`timeBasis` (`displayed` or `occupied`). `profile` selects exactly one authorized
role. Optional offering, state, resource and exact external-reference filters
only narrow it. A continuation preserves the verified caller, role and query;
it cannot widen scope. Each request spans at most 62 days and the selected
profile may impose tighter past, future and span limits. Pages are current
observations, not an atomic historical snapshot.

Each booking keeps the service and location labels of the policy revision that
recorded it; a later policy never relabels it.

### Calendar busy source profiles

`authentication.oidc.busyImportProfiles` is an optional map of calendar or
workforce systems that contribute resource availability facts. An absent map
keeps the existing booking behavior. Each profile binds one unique `sourceId`
to a write scope and an explicit resource set. Busy profiles may share a write
scope, but every request must select exactly one profile, and a busy write scope
cannot reuse the read, explain, or operational appointment scope. A caller
holding a shared write scope can select any profile bound to it, and so rewrite
the busy facts of every resource those profiles cover; operators who need
per-source isolation give each profile its own scope.

```yaml
staff-calendar:
  scope: scheduling:busy:write
  sourceId: staff-calendar
  resources: [staff-a, staff-b]
  maximumPastDays: 7
  maximumFutureDays: 62
  maximumSpanDays: 31
  maximumFreshnessMinutes: 240
  impactProjection: count-only
```

`POST /v1/source-busy/preview?profile=staff-calendar` compares a bounded source
snapshot without changing it. `POST /v1/source-busy/apply?profile=staff-calendar`
uses the same body and an exact source revision. An exact retry after a lost
success response returns `already-applied` with the request digest; a different
request at a stale revision is refused as HTTP 412 `revision.mismatch`. Callers
should preview and resolve the revision rather than automatically retry a
changed body.

Every request states its covered resources and interval, `observedAt`, and
either a bounded `freshUntil` or `status: unavailable`. Fresh omission deletes
only that source's contained rows. An unavailable or expired feed, missing
coverage, and the uncovered part of a future query all block new allocations
for configured resources. Existing holds and appointments remain unchanged.
Rows outside the selected coverage or the profile's current authority remain
effective and are reported as retained.

Responses always include the exact number of impacted commitments and whether
details were truncated. The default `count-only` projection returns no impact
items. `commitment-intervals` permits resource, kind, and occupied interval
items, up to the response bound. Neither projection returns appointment or
hold identifiers, parties, external references, source references, calendar
descriptions, attendees, or absence reasons.

`assertionIssuers` maps a client id to the assertion authorities that client may
exchange a subject token from. A deployment that performs no token exchange
leaves it empty, and an exchanged token whose authority no entry declares is
refused. A listed client names at least one authority: an empty list is
refused, and a client that is not listed may exchange from no authority. Once
a client is listed, a token it exchanged is accepted only for one
of that client's declared authorities, so an assertion minted by an unrelated
authority the issuer happens to federate cannot become a booking credential
here.

`taskGrantStatus` is a required top-level member that decides how Scheduling
learns whether a task grant is still current. It takes one of two forms, and
every runtime file states which; a file that omits it is refused at startup
with `scheduling.runtime.missing-task-grant-status`, and an empty list is
refused naming both choices.

The keyword `unchecked-final-fifteen-minutes` selects the offline path. No
task authority is asked and no revocation is observed: Scheduling accepts a
grant only while it is unexpired with at most 900 seconds remaining at request
entry, and refuses any grant with more time left as `operation.not-authorized`.

```yaml
taskGrantStatus: unchecked-final-fifteen-minutes
```

A list of Casework task authorities makes a fresh status answer mandatory.
Write it for every deployment that accepts deferred grants:

```yaml
taskGrantStatus:
  - sourceIssuer: https://casework.example.test/task-authority
    baseUrl: https://casework.example.test
    tokenEndpoint: https://identity.example.test/realms/registry/protocol/openid-connect/token
    clientAssertionAudience: https://identity.example.test/realms/registry
    clientId: scheduling-task-status
    privateKeyRef: secret:file/scheduling-task-status-private-jwk
    statusResource: urn:example:casework
    caBundleRef: secret:file/institution-root-ca
```

Offline runtime checks require one to 32 entries with distinct absolute
`sourceIssuer` identifiers, safe service and token URLs, non-empty client and
assertion audience, an absolute status resource, one status scope token, and
a status path with one `{grantId}` segment. They validate secret
reference structure without resolving the private key or CA bundle or contacting
an endpoint. Activation repeats the structural check and verifies key and CA
contents.

`sourceIssuer` must exactly equal the source issuer in the signed task grant.
`baseUrl` selects that authority's HTTPS API. `tokenEndpoint`,
`clientAssertionAudience`, `clientId`, and `privateKeyRef` configure the
private-key JWT client credential used to obtain a token for
`statusResource` with the `statusScope` scope. The private key is a JWK
whose `kid` selects its registered public key. `caBundleRef` is optional and
applies a private CA bundle to both outbound HTTPS connections.

`statusScope` and `statusPath` are optional. Omitted, Scheduling requests the
`casework:grants:status` scope and calls Casework's
`/v1/task-grants/{grantId}/status` route under `baseUrl`. Set them only for a
task authority that answers under another scope or route: `statusScope` is one
scope token, and `statusPath` starts with `/` and holds exactly one whole
`{grantId}` segment.

With the list, a fresh exact status answer is mandatory for every capacity
commitment and idempotent receipt replay, whatever time the grant has left.
The authority must return the signed grant's exact identity and bounds and say
it is active. An inactive, mismatched, unlisted, or incompletely bound grant
answers `operation.not-authorized`; an authority or credential outage,
including an unusable authority response, answers `service.unavailable`.
Positive answers are not cached. The full attempt is
limited to ten seconds and completes before the capacity transaction opens, so
no PostgreSQL capacity lock is held during the outbound call. Duplicate source
issuers or invalid endpoints, credentials, or secret references refuse startup.
The positive answer is an observation rather than a distributed transaction:
a withdrawal after the answer can race the in-flight Scheduling commit.

The list disables the offline path for every source: a grant from a source
issuer no entry names is refused, even with less than 15 minutes left. Because
the signed token does not identify whether its grant was originally immediate
or deferred, a deployment that writes `unchecked-final-fifteen-minutes` lets
the final 15 minutes of a deferred grant through without asking whether it was
withdrawn. On either path, the capacity transaction checks the
earlier of the verified access token deadline and the grant deadline again
after lock waits and immediately before commit. That earlier deadline bounds
the status-to-commit race; it does not make revocation atomic across products.

Scopes authorize reads only. Every commitment takes its authority from a task
grant instead, which [TASK_GRANTS.md](TASK_GRANTS.md) documents.

`audit.hashKeyRef` supplies the key that pseudonymizes principals and grants in
audit entries and in hold and appointment history. It decides no ownership: a
claim is owned by the verified issuer and subject that made it, stored on the
claim, so rotating the key leaves every existing claim with its owner, its
listing, and its read, reschedule, cancel, and hold release. `audit.destination` is `file`, the default, or `stdout`. A `file`
destination requires `audit.path`, the absolute active audit file, which one
process writes at a time; the file rotates at `audit.rotateBytes` (default 100
MiB, at least 1 MiB, at most 4294967295) and rotated files are removed after
`audit.retentionDays` (default 90, at most 36500). `stdout` takes none of the
three and leaves collection and retention to the platform that reads the
stream. The runtime writes its operational logs to standard error whatever the
destination is, so a `stdout` stream carries audit entries alone. `RUST_LOG`
selects their verbosity and defaults to `info` when it is unset or invalid.
`schedulingctl records apply`
writes beside the runtime, to `<stem>.schedulingctl.<ext>` next to
`audit.path`, so the two processes never share a file, or to standard error
with a `stdout` destination, so its own report keeps standard output.

Every entry carries the schema `registry-scheduling-audit/v1`, a `request` or
`response` phase, and a correlation shared by one decision's entries. A
commitment's `request` entry is accepted before its capacity transaction opens,
and its `response` entry after the transaction commits or rolls back; a
permission refused before the transaction is one `response` entry. Audit fails
closed: a refused `request` entry opens no transaction, and a refused `response`
entry for a committed change answers `service.unavailable` with the change
committed. A refusal, whether the ledger decided it (an admission refusal,
the hold ceiling, a lapsed grant, a stale observed revision, or a cancellation
past its cutoff) or the permission check refused it before the transaction
opened, reaches the caller only once its `response` entry is accepted, and
answers `service.unavailable` otherwise. A commitment nothing decided still
answers its `request` entry: a transaction rolled back on a failure, records
replaced under it, or a reused or expired idempotency key writes a `response`
with the outcome `unfinished` and the reason `commitment.failed`,
`commitment.facts-stale`, `idempotency.key-reused`, or `idempotency.expired`,
and one that returns or is canceled before answering writes
`commitment.unfinished`. A capacity commit that is not acknowledged is read
back by its transaction identifier on a separate connection that changes
nothing: one that took effect is answered and recorded as committed, one that
rolled back writes `commitment.failed`, and one whose status cannot be read
writes `commitment.unfinished` and answers `service.unavailable`, because it
may have taken effect; a retry under the same idempotency key then replays
whatever committed. `/readyz` reports unavailable while the destination
refuses writes. An expired hold writes its history entry as `system` and no
audit entry.

`destinations` is optional. `destinations.reminders` is the one place due
reminder intents are delivered, as the shared hook envelope with
`content-type: application/json` over HTTPS POST (see the README Events
section), with `bearerTokenRef` as the optional bearer secret. The independent
optional `hmacSha256KeyRef` enables the shared signed CloudEvents delivery
contract and must resolve to a key of at least 32 bytes. Existing destinations
without this key retain their unsigned behavior. Signed destinations can also
use bearer authentication; receiving an event does not authorize downstream
capacity changes or message delivery. `url` is the fallback endpoint. An
optional closed `purposeUrls` block may override it for any of
`confirmation`, `change`, `cancellation`, and `reminder`; omitted purposes keep
using `url`. Every override must use the fallback's scheme, host, and effective
port. For example:

```yaml
destinations:
  reminders:
    url: https://events.example.org/scheduling
    purposeUrls:
      confirmation: https://events.example.org/scheduling/confirmed
      reminder: https://events.example.org/scheduling/reminder
    hmacSha256KeyRef: secret:file/reminder-signing-key
```

Each URL is one reviewed absolute endpoint without userinfo, query, or
fragment and with a safe parsed path. Plain `http` is accepted only for an
explicit loopback host, so a plaintext destination can
never silently point at another machine. Delivery is attempted once per claim
on the shared dispatch core, with a five-second attempt timeout and a fixed
back-off of thirty seconds doubling to 1920 seconds; a transport failure
schedules a retry, an authorization or routing refusal sets the intent aside
as failed for the operator, and the eighth failed attempt sets it aside. A
cancellation or a reschedule cancels the superseded reminder in its own
transaction when no attempt has started on it; one a dispatcher already
holds is set aside without a send by a liveness read under its lease. An absent reminders destination is a supported
deployment: the intents stay readable in the outbox and are set aside as
local, never pretended delivered. The README documents the envelope and the
event types.

`destinations.hooks` binds the logical destination ids named by policy hooks to
deployment-owned URLs and HMAC-SHA256 keys. It holds at most 128 bindings, and
each id is a lowercase ASCII letter followed by up to 63 lowercase letters,
digits, `-`, or `_`. Each entry requires `url` and
`hmacSha256KeyRef`; `attemptTimeoutMilliseconds` defaults to 5000 and is bounded
from 100 through 10000, while `maximumAttempts` defaults to 8 and is bounded
from 1 through 20. URLs use the same HTTPS and explicit-loopback rules as the
reminder destination. A signing key must contain at least 32 bytes. Every
destination the current policy names must be configured. Explicit extra
bindings are allowed so retained events captured under an earlier policy can
finish with their exact original binding. Startup refuses if a retained event's
binding is no longer available.

`retention.receiptRetentionDays` covers idempotency attempt receipts and
terminal dispatch metadata from 1 through 365 days; listing cursors keep their fixed fifteen-minute
lifetime. `retention.hookPayloadRetentionDays` sets the canonical observer payload's retry and
dead-letter lifetime from 1 through 30 days.
`retention.claimOwnerRetentionDays` bounds the raw owner issuer and subject
from 1 through 365 days after an appointment ends or is cancelled, or a hold
expires, is released, or is consumed. The earlier applicable instant starts
the window. All three configured values default to seven days, a placeholder
that is not a jurisdictional recommendation. The sweep clears both owner
columns together and retains a per-claim SHA-256 reference and erasure time.
The reference grants no authority: the claim is no longer readable, listable,
or actionable by its former owner, and a receipt containing that claim cannot be observed or replayed even if
the independent receipt window remains open. Live claims
keep their owner across audit-key rotation. Claim and history rows remain;
their retention is deferred. Each retention tick prunes up to 256 settled
outbox intents of any purpose (confirmation, change, cancellation, reminder)
at or before the receipt-period cutoff: a delivered intent by its delivery
time, a reminder cancelled before any attempt by its cancellation time, and
a reminder set aside as superseded by its dead-letter time,
and up to 256 terminal observer deliveries whose last transition is at or
before that cutoff. Observer dead letters and expired deliveries also require
completed payload expiry and erasure before their metadata ages out. Pending,
leased, retryable and uncertain work remains, including local and failed
outbox intents. Hook state is removed before delivery metadata;
a shared event remains until its last delivery is removed. These deletions
share one transaction and never erase audit entries or spent-key tombstones. `audit.retentionDays` bounds rotated
audit files. An idempotency receipt past its period is erased, so an
exact retry after expiry answers `idempotency.expired` with HTTP 410 instead of
replaying the first answer. The same sweep clears the attempt's raw token
issuer, subject, and key; the row stays, identified only by a SHA-256 digest of
those three and the command, and is never deleted. The key therefore stays
spent for that caller: a changed retry is still refused with
`idempotency.key-reused`, and another caller's identical key is fresh.

See the complete maintained
[`runtime.example.yaml`](examples/standalone-exact-time/runtime.example.yaml),
which is exactly what `schedulingctl init` writes beside an authored project,
and the generated editor schema at
[`generated/runtime/runtime.schema.json`](generated/runtime/runtime.schema.json).
Regenerate the schema from the owning Rust type with:

```sh
cargo run --locked -p registry-scheduling --features schema \
  --example runtime-schema -- --output products/scheduling/generated/runtime
cargo test --locked -p registry-scheduling --features schema \
  schema::tests::committed_runtime_schema_matches_generated_bytes
```

## Shared access-token profile

See the maintained [per-resource access-token reference](../platform/ACCESS-TOKENS.md)
for algorithms, token type, audience, scope and actor separation, issuer-network
policy, lifetime and safe diagnostics.
