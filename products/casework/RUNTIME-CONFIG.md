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
database, the issuer, a context provider, or a secret. It reports every problem in the
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
apiVersion: id.registrystack.org/formats/casework/runtime/v1alpha1
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
exactly `casework.yaml`, its referenced display schemas, and the context provider
exports it names, each matching its digest. A directory without `SHA256SUMS`, such as an authored project, is
refused and names `caseworkctl package`. `caseworkctl dev` packages the authored
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

Before activation, `caseworkctl plan` compares the candidate package with
in-flight reviews retained in the database. `caseworkctl apply` refuses a
package that removes a policy, profile, team, producer, provider or contract
those reviews still need, or changes pinned policy content under the same
version. Let the affected reviews finish under the active package before
applying the candidate. `caseworkctl doctor` repeats the check for the active
package. There is no override for orphaned work.

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
`https` URL without credentials, query, or fragment. Its declared origin may resolve to a
private address, and a discovery document may name a same-origin private `jwks_uri`.
A cross-origin private `jwks_uri` named by discovery is refused, and cloud metadata and
link-local addresses are always refused.
Plain `http` is accepted on IPv4 and IPv6 loopback when `listener.tlsTermination` is
`development-loopback`. Set `allowInsecureHttp: true` beside `issuer` to permit it
elsewhere; startup logs a warning while that setting is active. It covers the issuer's
origin and a `type: uri` key set, never a cross-origin `jwks_uri` named by discovery, which
must use `https`.
The audience is at most 512 characters. `jwksSource` defaults to `type: discovery`.
`type: uri` with `uri` fetches the key set from a fixed address instead of the one
discovery names; as an endpoint you declare, it inherits the declared issuer's allowance and
may resolve to a private or loopback address on any origin. `type: static` with `documentRef` reads a
pinned key set, which does no rotation of its own. The removed `jwksUri` key is refused
with a diagnostic
naming `jwksSource` `type: uri` as its replacement. `allowedClients` lists the
client identifiers whose tokens the runtime admits, matched against the token's
`azp` claim or, when it has none, its `client_id` claim. Every file writes the
member: a list of at least one distinct client, or `unrestricted`, which admits
every client the issuer verifies. An omitted member, an empty list, and a
repeated client are refused when the file is read. Under
`operator-controlled-upstream` the member must list its clients; development
loopback accepts `unrestricted` as a local convenience. A configured
`taskAuthority` requires a list in either mode, and its `issuer` is an absolute `http` or
`https` URL with a host and no user information. `scopeClaim` defaults
to `registry_scopes` for compatibility with existing deployments. Stock ThunderID
emits `scope`, so the maintained example and `caseworkctl init` set that explicit
override. `humanIdentity` defaults to claim
`registry_actor_kind` with value `human` and applies only to human roles.
Principal selection belongs exclusively to each authored
`accessProfiles.PROFILE_ID.principalClaim` in `casework.yaml`. The removed runtime field
`authentication.oidc.principalClaim` is refused with that replacement.

`revokedKeyIds` is an optional list of at most 128 distinct nonempty key identifiers.
Casework refuses a token whose protected `kid` appears in the list even while the key
remains in the issuer's key set. The list refuses those keys in Casework only; it does not
revoke them at the issuer. `maximumTokenLifetimeSeconds` optionally limits the
interval from `iat` to `exp` to 1 through 7200 seconds. Omitting either setting preserves
the existing acceptance rule.

During key rotation, publish the replacement key first and confirm that Casework accepts a
test token signed by it. Add the retiring key identifier to `revokedKeyIds` when it must stop
authorizing immediately, apply the runtime configuration, and confirm that a token signed by
the retired key is refused. Remove the old public key from the issuer after all services have
applied the change. A static `jwksSource` also requires atomically replacing its referenced
document and restarting Casework.

`audit` selects where Casework writes its audit entries and the key that
pseudonymizes the principals and identifiers they name. `audit.hashKeyRef` is
that key's secret reference and must be an exact `secret:env/NAME` or
`secret:file/name` reference. `audit.destination` is `file` (the default) or
`stdout`. A `file` destination requires the absolute `audit.path` of the active
file and accepts `audit.rotateBytes` (default 104857600, at least 1048576, at
most 4294967295) and `audit.retentionDays` (default 90, at least 1, at most
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
Background work no caller requested, such as a review clock or retention pass,
writes no request entry: it opens its transaction only while the writer reports
ready, and its response entries share a correlation that identifies the run.
The database holds no audit state.

`contextProviders` binds declared `deploymentRef` values under
`casework.yaml:contextProviders`. Unknown keys are refused; an omitted provider
leaves only its current-source operations unavailable, while submitted-context
reviews continue to work. Each binding provides the BReg base URL,
`tokenEndpoint`, `clientIdRef`, `clientAssertionKeyRef`, and
`statusProfile`. The status profile must equal the authored
`serviceProfiles.service-status` for that provider. Optional
`clientAssertionAudience`, `resource`, and `scopes` configure the OAuth
client-assertion and token request for the status reader; use the exact values
registered by the issuer and BReg deployment. The status credential reads only
review status. It does not supply fields shown to a human reviewer.

For a current-source review, the human request selects a BReg source profile
with the `Registry-Source-Profile` header. Casework forwards that human's
bearer to BReg for the current display read. BReg authorizes the profile,
subject and disclosure. The compiled Casework policy pins the producer's
context contract and vendored schema; the verified package also includes the
provider's exported description. `caseworkctl check --against-breg-package`
compares that export with a checked native BReg package offline. Rotate
transport credentials by updating their secret references without changing
the policy. A changed BReg context contract needs a new export, schema pin and
Casework package.

`reviewCompletionDestinations` is keyed by the logical destination ids a
producer's `completion` block names, kept as written: 1 to 512 characters
without control characters. Each destination has one `url` and exactly
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
[`runtime.example.yaml`](examples/canonical-review/runtime.example.yaml) and
the generated editor schema at
[`generated/runtime/runtime.schema.json`](generated/runtime/runtime.schema.json).
Regenerate the schema from the owning Rust type with:

```sh
cargo run --locked -p registry-casework --features schema \
  --example runtime-schema -- --output products/casework/generated/runtime
products/casework/scripts/check-schemas.sh
```

## Shared access-token profile

See the maintained [per-resource access-token reference](../platform/ACCESS-TOKENS.md)
for algorithms, token type, audience, scope and actor separation, issuer-network
policy, lifetime and safe diagnostics.

## Completion receiver contract

The [completion receiver guide](COMPLETION-RECEIVERS.md) defines POST payload,
headers, bounded retries, acknowledgement and durable receiver deduplication,
with Python and Node examples. Delivery is at-least-once.
