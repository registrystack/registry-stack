# Scheduling runtime configuration

Scheduling reads one versioned operator document selected with
`scheduling --runtime-config ABSOLUTE_FILE serve` or `migrate`. The selected
file path and every operated resource path are absolute. Local development
tooling may resolve paths before it writes the file.

The closed envelope is:

```yaml
apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1
kind: SchedulingRuntimeConfig
```

`package.root` selects one directory. The runtime always loads
`package.root/scheduling.yaml`; no second project selector can override it.
With `listener.tlsTermination: operator-controlled-upstream`, the directory
must also contain a matching `scheduling.package.json`. Development loopback
may select an authored project directory without that manifest.

`listener` is required. `listener.bind` is one numeric socket address,
including bracketed IPv6 forms, and defaults to `127.0.0.1:8105` when omitted
from the listener block. `listener.tlsTermination` is required. Use
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
to discovery and can instead select a static `documentRef`, which does no
rotation of its own: rolling a key means replacing the referenced document and
restarting Scheduling. `jwksUri` overrides the discovery document's JWKS
address. `scopeClaim` defaults to `registry_scopes` for compatibility with
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
audit entries. `audit.destination` is `file`, the default, or `stdout`. A `file`
destination requires `audit.path`, the absolute active audit file, which one
process writes at a time; the file rotates at `audit.rotateBytes` (default 100
MiB, at least 1 MiB, at most 4294967295) and rotated files are removed after
`audit.retainDays` (default 90, at most 36500). `stdout` takes none of the
three and leaves collection and retention to the platform that reads the
stream. `schedulingctl records apply`
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
committed. One case is best effort instead: a refusal the ledger itself
decides (an admission refusal, the hold ceiling, a lapsed grant, a stale
observed revision, or a cancellation past its cutoff), and a permission
mismatch refused before the transaction opens, still reach the caller when
their `response` entry cannot be written; the write failure is only logged,
and the journal is left holding a `request` entry with no paired `response`,
or, for a permission mismatch, no entry at all. `/readyz` reports unavailable
while the destination refuses writes. An expired hold writes its history entry
as `system` and no audit entry.

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

`retention.attemptReceiptDays` covers idempotency attempt receipts; listing
cursors keep their fixed fifteen-minute lifetime. `retention.hookPayloadDays`
sets the canonical observer payload's retry and dead-letter lifetime from 1
through 30 days. Both configured values default to seven days, which is not a
jurisdictional recommendation. Appointment, history, and reminder outbox
retention remain deferred; `audit.retainDays` bounds rotated audit files. An idempotency receipt past its period is
erased, so an exact retry after expiry answers `idempotency.expired` with HTTP
410 instead of replaying the first answer.

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
