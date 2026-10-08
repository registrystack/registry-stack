# Casework runtime configuration

Casework reads one versioned operator document selected with
`casework --runtime-config ABSOLUTE_FILE serve`, and `caseworkctl plan`,
`apply`, `status`, and `doctor` read the same file with `--runtime-config`.
The selected file
path and every operated resource path are absolute, and the selected file may
not pass through a symbolic link. Local development tooling may resolve paths
before it writes the file. The file is read through the shared Registry Stack
runtime configuration loader: it must be a YAML mapping of at most 1 MiB, and
unknown keys are refused with the path of the offending field. Every problem
is reported at its line and column. A member written as `null`, `~`, or an
empty value is refused; omit the key to take its default. A secret reference,
URL, or digest that is not written in its form is refused at its position with
`config.invalid-value`, and a number outside its bounds with
`config.out-of-range`, without repeating the value.

`caseworkctl check PROJECT --runtime-config FILE` reads the file the same
way, offline and against the authored project, without the package, the
database, the issuer, a source, or a secret. It reports every problem in the
file at its position, as the runtime does when it refuses the file at
startup. A `${VAR}` expression, and every rule that reads its value, is left
unchecked unless `--environment` fills the expressions from the current
environment.

String values in `runtime.yaml` may take a deployment value from the
environment when the runtime starts: `${VAR}` requires `VAR`, `${VAR:-default}`
falls back to `default`, and `${VAR:?message}` refuses to start with `message`
when `VAR` is unset. Substitution never applies to a field whose name ends in
`Ref` or `Refs`, or to any value beneath one, because a secret reference must
be written literally and resolved by a declared provider. It never applies to
the authored `casework.yaml` either: an environment expression there is
refused, by the runtime and by `caseworkctl check`, with the path of the field
that holds it.

The closed envelope is:

```yaml
apiVersion: registry.registrystack.org/casework-runtime/v1alpha1
kind: CaseworkRuntimeConfig
```

`identity.databaseId` is required: the logical name of the database this
deployment activates packages in, such as `casework-production`. It is chosen
by the operator, is 1 to 256 bytes with no surrounding whitespace or control
character, and is never derived from a URL or a PostgreSQL database name. The
first `caseworkctl apply` records it in the activation ledger. Every later
apply, and every start of the runtime, refuses a database that recorded a
different identity, without naming either value. A file that omits the block
is refused with the key to add.

`package.root` selects one directory. The runtime always loads
`package.root/casework.yaml`; no second project selector can override it. In
every listener mode, with or without `package.expectedDigest`, the directory
must be a package `caseworkctl package` wrote: a `SHA256SUMS` file listing
exactly `casework.yaml` and the source descriptions it names, each matching its
digest. A directory without `SHA256SUMS`, such as an authored project, is
refused and names `caseworkctl package`; so is a directory that holds the
retired `casework.package.json`. `caseworkctl dev` packages the authored
project on every start and serves that package.

`package.expectedDigest` is optional. When set, it is `sha256:` followed by 64
lowercase hexadecimal digits, and the runtime starts only on the verified
package whose package digest, the SHA-256 digest of its `SHA256SUMS`, is that
value. Any other package, or a directory without `SHA256SUMS`, is refused
before the runtime starts, and the refusal names the expected digest and the
one found. The retired `package.expectedPolicyDigest` is refused with
`package.expectedDigest` named as its replacement.
Set it to the digest printed by `caseworkctl package` for the package you
reviewed, so that replacing the files under `package.root` cannot change the
policy a restart loads.

`package.acknowledgeStrandedWork` is optional and takes the same digest form.
Before it registers any source generation, `caseworkctl apply` compares the
package it is about to activate with the in-flight work retained in the
database. Review
requests still under review pinned their kind's policy when they were
admitted, and open work items keep the queue they were routed to. Apply
refuses a package that removes a queue or access profile that work still
needs, that declares a pinned review kind version with different content, that
removes the source of a source-context review, or whose source read would
disclose a field the pinned display schema does not declare or omit one it
requires. The refusal names each conflict with its counts and the package
digest. Let that work finish under the earlier package, or set
`package.acknowledgeStrandedWork` to that exact digest to activate the package
anyway; the acknowledgement admits only the package it names, so it never
carries over to a later one.
`caseworkctl plan` runs the same comparison, so pointing it at a runtime file
whose `package.root` holds the next package previews the refusal before the
apply. `caseworkctl doctor` repeats it for the active package as its
`pinnedWork` check.

`listener` is required. `listener.bind` is required and is one numeric socket
address, including bracketed IPv6 forms. `listener.tlsTermination` is required. Use
`operator-controlled-upstream` behind an operator-managed TLS edge or
`development-loopback` for direct local development. `listener.networkExposure`
defaults to `private-address`; `container-private` permits an unspecified bind
only for a listener kept on a private container network.

`metricsListener` is optional and absent by default. `metricsListener.bind` is
one numeric socket address with a nonzero port, loopback or private (IPv4
private range or IPv6 unique local), never a wildcard, and never the address
and port the API listener occupies; an IPv6 wildcard API listener counts as
occupying that port on both families. When set, the runtime serves `/metrics`
and `/version` there and nowhere else.

`secretProviders` explicitly enables each accepted reference form. Declare
`file: {root: ABSOLUTE_DIRECTORY}` before using `secret:file/name`. Declare
`environment: {}` before using `secret:env/NAME`. The runtime does not fall back
from one provider to another. The maintained example uses mounted files.

`database.runtimeUrlRef` supplies the least-privilege service connection and
`database.migrationUrlRef` supplies the operator-run migration connection.
The runtime, `caseworkctl plan`, `status`, and `doctor` connect only with the
runtime credential; only `caseworkctl apply` resolves the migration
credential. When the two name different PostgreSQL roles, apply grants the
runtime role the privileges it serves with (schema usage, read and write on
the Casework tables, read-only on the activation ledger and the schema
migration table) and records the deployment as `split`; when they name one
role, or the runtime role can still write the ledger, it records `single` and
`status` and `doctor` say that the runtime credential can activate packages.
`database.trustedRootCertificateRef` is optional. Plaintext PostgreSQL is
available only to builds with the `postgres-test` feature and an explicit
`testOnlyPlaintext: true` setting. Unless a database URL sets them, every
Casework connection uses `connect_timeout=5`, `keepalives_idle=15`,
`keepalives_interval=5`, `keepalives_retries=3`, and `tcp_user_timeout=30`,
all in seconds as Casework reads the URL (unlike libpq, which reads
`tcp_user_timeout` in milliseconds), so a connection to a server that stopped
answering fails within seconds. The TCP user timeout applies on Linux only.

`authentication.oidc` requires `issuer` and `audience`. The issuer is an exact
`https` URL without credentials, query, or fragment; plain `http` is accepted only for
an IPv4 loopback address under development loopback, for the issuer and for a
`kind: uri` key set alike. The audience is at most 512
characters. `jwksSource` defaults to `kind: discovery`. `kind: uri` with `uri`
fetches the key set from a fixed HTTPS address instead of the one discovery
names. `kind: static` with `documentRef` reads a pinned key set, which does no
rotation of its own: rolling a key means replacing the referenced document and
restarting Casework. The removed `jwksUri` key is refused with a diagnostic
naming `jwksSource` `kind: uri` as its replacement. `allowedClients` lists the
client identifiers whose tokens the runtime admits, matched against the token's
`azp` claim or, when it has none, its `client_id` claim. Under
`operator-controlled-upstream` the list must name at least one client, because an
empty list admits every client the issuer verifies; development loopback keeps
an empty list as a local convenience. A configured `taskAuthority` requires a
non-empty list in either mode, and its `issuer` is an absolute `http` or
`https` URL with a host and no user information. `scopeClaim` defaults
to `registry_scopes` for compatibility with existing deployments. Stock ThunderID
emits `scope`, so the maintained example and `caseworkctl init` set that explicit
override. `humanIdentity` defaults to claim
`registry_actor_kind` with value `human` and applies only to human roles.
Principal selection belongs exclusively to each authored
`accessProfiles[].principalClaim` in `casework.yaml`. The removed runtime field
`authentication.oidc.principalClaim` is refused with that replacement.

`audit` selects where Casework writes its audit entries and the key that
pseudonymizes the principals and identifiers they name. `audit.hashKeyRef` is
that key's secret reference and must be an exact `secret:env/NAME` or
`secret:file/name` reference. `audit.destination` is `file` (the default) or
`stdout`. A `file` destination requires the absolute `audit.path` of the active
file and accepts `audit.rotateBytes` (default 104857600, at least 1048576, at
most 4294967295) and `audit.retainDays` (default 90, at least 1, at most
36500); `stdout` refuses all three. A
`caseworkctl` command that writes audit, such as an applied erasure or
settlement, writes to a sibling file named for its process role beside
`audit.path`, `audit.caseworkctl.ndjson` for `audit.ndjson`, or to standard
error with a `stdout` destination, so the command's own report keeps standard
output. Every entry carries the schema
`registry-casework-audit/v1`, a phase, and a correlation shared by an
operation's request entry and its response entries. A requested operation
writes one request entry before it opens the operation's transaction, and one
response entry for each domain event it records after that transaction
commits; a destination that refuses either fails the request with
`service.unavailable`, and a refused response leaves the committed change in
place. A requested operation that records no domain event, such as an
idempotent replay, writes one response entry whose `outcome` is `replayed` or
`unchanged`, and returns its result only after that entry is accepted.
Background work no caller requested, such as source reconciliation or a
maintenance pass, writes no request entry: it opens its transaction only while
the writer reports ready, and its response entries share a correlation that
identifies the run. The database holds no audit state. `sources` is keyed by the exact source ids declared by the
selected policy; missing, extra, or empty ids are refused. Source access remains
bound to each source's configured reader profile and does not grant a caller a
Casework access profile.

The BReg source binding generation keys every source-backed work item, task
grant, and saved attempt. It is computed from the source id, the binding's
`eventSource`, and the SHA-256 digest of the imported source description, and
from nothing else. Changing one of those three means the source now says
something different, so the next observation supersedes the work items opened
under the earlier generation and opens fresh ones. Every other binding field is
operational: `baseUrl`, `readerProfile`, `tokenEndpoint`,
`clientAssertionAudience`, `resource`, `scopes`, the client and key references,
`trustedRootCertificatesRef`, both timeouts, `displayReference`,
`contextProjection`, and `reconciliationIntervalMilliseconds`. Rotating a
credential, moving the token endpoint, or tuning a timeout keeps the generation,
the in-flight work items, their claims, and their durable attempts.

`sources.<id>.reconciliationIntervalMilliseconds` controls how often Casework
schedules source readback. When a readback pass lasts longer than the
interval, Casework skips missed ticks instead of replaying them back-to-back
against the source. It also sets how long a reconciled source counts as
current for an empty inbox view: the larger of twice the interval and 2
minutes.

For a BREG source, `tokenEndpoint` selects the reader's OAuth endpoint.
`clientAssertionAudience` explicitly overrides the JWT client assertion audience;
when omitted, it remains the token endpoint. `resource` is the exact RFC 8707
resource indicator and `scopes` is the reader's nonempty bounded OAuth scope
list. Omission preserves an existing issuer's default behavior. Stock ThunderID
1.0.1 deployments must configure all three: its issuer URL as the assertion
audience, the exact BREG resource, and the registered reader scopes. Use the
actual deployment or `bregctl dev export-client` values, not a guessed resource
based on the project directory name. Changing these fields keeps the source
binding generation.

`reviewCompletionDestinations` is keyed by the logical destination ids a
producer's `completion` block names. Each destination has one `url` and exactly
one secret. `bearerTokenRef` presents it as `Authorization: Bearer <secret>`.
`auth: {secretRef}` does the same, and `auth: {header, secretRef}` presents the
raw secret as the value of that header instead, with no `Authorization` header,
for a receiver that authenticates with, for example, `x-api-key`. The header
name is HTTP token characters, at most 64 bytes, and compared case-insensitively
against a reserved set the runtime refuses at load: authentication, host,
cookie, framing, hop-by-hop, forwarding, proxy, and tracing headers, plus the
completion contract's own `idempotency-key` and every `registry-` header. The
secret is visible ASCII, is never logged, and redirects are not followed.
`caseworkctl doctor` reports the same refusal before the runtime starts.

See the complete maintained
[`runtime.example.yaml`](examples/professional-review/runtime.example.yaml) and
the generated editor schema at
[`generated/runtime/runtime.schema.json`](generated/runtime/runtime.schema.json).
Regenerate the schema from the owning Rust type with:

```sh
cargo run --locked -p registry-casework --features schema \
  --example runtime-schema -- --output products/casework/generated/runtime
products/casework/scripts/check-schemas.sh
```
