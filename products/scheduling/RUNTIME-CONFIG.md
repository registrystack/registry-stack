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
apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1
kind: SchedulingRuntimeConfig
```

`package.root` selects one directory. The runtime always loads
`package.root/scheduling.yaml`; no second project selector can override it. In
every listener mode, with or without `package.expectedDigest`, the directory
must be a package `schedulingctl package --output` wrote: a `SHA256SUMS` file
listing exactly `scheduling.yaml`, whose bytes match the listed digest. A
changed, missing, or extra file is refused by name, and so is a directory
without `SHA256SUMS`, such as an authored project; each refusal names
`schedulingctl package`. A directory that holds the retired
`scheduling.package.json` is refused the same way.

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
FILE` then `schedulingctl apply --runtime-config FILE`. `scheduling migrate`
is removed and exits 2 naming the same two commands.

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
sequence, view, or function, that holds TRIGGER on a `scheduling_*` table or
view, or that holds CREATE on the schema, can write the ledger indirectly,
and so can a trigger already attached to a `scheduling_*` table, since no
Scheduling migration creates one. With two roles, `plan`, `apply`, and
`serve` refuse them. After `REASSIGN OWNED BY <owner> TO <migrator>` the
refusal names `schedulingctl apply --runtime-config FILE`, which reissues
the grants the moved objects lost, and `serve` refuses until it has; after
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
to `kind: discovery`. `kind: uri` with `uri` fetches the key set from a fixed
HTTPS address instead of the one discovery names; plain `http` is accepted only
for a loopback host under development loopback. `kind: static` with
`documentRef` reads a pinned key set, which does no rotation of its own:
rolling a key means replacing the referenced document and restarting
Scheduling. The removed `jwksUri` key is refused with a diagnostic naming
`jwksSource` `kind: uri` as its replacement. `scopeClaim` defaults to `registry_scopes` for compatibility with
existing deployments; stock ThunderID emits `scope`, so the maintained example
and `schedulingctl init` set that explicit override. `readsScope` defaults to
`scheduling-read` and `explainScope` to `scheduling-explain`; the two must
differ, because the explain path can name member-level causes the public
availability read never discloses. `allowedClients` lists the exact client ids
the runtime admits. A deployment whose `listener.tlsTermination` is
`operator-controlled-upstream` must name them: an empty or absent list is a
startup refusal there, because a forgotten field would otherwise admit every
client the issuer verifies, including an application in the same realm that has
nothing to do with booking. Development loopback keeps the empty-means-any
convenience, since it is not a deployment an unrelated client can reach.

`assertionIssuers` maps a client id to the assertion authorities that client may
exchange a subject token from. A deployment that performs no token exchange
leaves it empty, and an exchanged token whose authority no entry declares is
refused. Once a client is listed, a token it exchanged is accepted only for one
of that client's declared authorities, so an assertion minted by an unrelated
authority the issuer happens to federate cannot become a booking credential
here.

Scopes authorize reads only. Every commitment takes its authority from a task
grant instead, which [TASK_GRANTS.md](TASK_GRANTS.md) documents.

`audit.hashKeyRef` supplies the key that pseudonymizes principals and grants in
audit entries. The same key derives hold and appointment ownership: a claim
records the keyed pseudonym of the issuer and subject that made it, never the
pair itself. Rotating the key therefore orphans every existing claim. The
claims stay committed and keep their capacity, but the caller that made them
no longer sees them in its listing, and its read by identifier, reschedule,
cancel, or hold release is refused with `operation.not-authorized`. An empty
listing proves no booking only if the key has not been rotated since the
attempt. `audit.destination` is `file`, the default, or `stdout`. A `file`
destination requires `audit.path`, the absolute active audit file, which one
process writes at a time; the file rotates at `audit.rotateBytes` (default 100
MiB, at least 1 MiB, at most 4294967295) and rotated files are removed after
`audit.retainDays` (default 90, at most 36500). `stdout` takes none of the
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
reminder intents are delivered, as CloudEvents 1.0 events over HTTPS POST with
`bearerTokenRef` as the optional bearer secret. The URL is one reviewed
absolute endpoint without userinfo, query, or fragment; plain `http` is
accepted only for an explicit loopback host, so a plaintext destination can
never silently point at another machine. Delivery is attempted once per claim
with exponential backoff from half a minute capped at an hour; a transport
failure schedules a retry, an authorization or routing refusal holds the
intent as failed for the operator, and eight failed attempts hold it. An
absent reminders destination is a supported deployment: the intents stay
readable in the outbox and are marked local, never pretended delivered. The
README documents the envelope and the event types.

`destinations.hooks` binds the logical destination ids named by policy hooks to
deployment-owned URLs and HMAC-SHA256 keys. Each entry requires `url` and
`hmacSha256KeyRef`; `attemptTimeoutMilliseconds` defaults to 5000 and is bounded
from 100 through 10000, while `maximumAttempts` defaults to 8 and is bounded
from 1 through 20. URLs use the same HTTPS and explicit-loopback rules as the
reminder destination. A signing key must contain at least 32 bytes. Every
destination the current policy names must be configured. Explicit extra
bindings are allowed so retained events captured under an earlier policy can
finish with their exact original binding. Startup refuses if a retained event's
binding is no longer available.

`retention.attemptReceiptDays` covers idempotency attempt receipts and is at
least one day; listing cursors keep their fixed fifteen-minute lifetime.
`retention.hookPayloadDays` sets the canonical observer payload's retry and
dead-letter lifetime from 1 through 30 days. Both configured values default to
seven days, which is not a jurisdictional recommendation. Appointment, history,
and reminder outbox retention remain deferred; `audit.retainDays` bounds
rotated audit files. An idempotency receipt past its period is erased, so an
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
