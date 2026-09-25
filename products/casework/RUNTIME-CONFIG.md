# Casework runtime configuration

Casework reads one versioned operator document selected with
`casework --runtime-config ABSOLUTE_FILE serve` or `migrate`. The selected file
path and every operated resource path are absolute. Local development tooling
may resolve paths before it writes the file.

The closed envelope is:

```yaml
apiVersion: registry.registrystack.org/casework-runtime/v1alpha1
kind: CaseworkRuntimeConfig
```

`package.root` selects one directory. The runtime always loads
`package.root/casework.yaml`; no second project selector can override it. With
`listener.tlsTermination: operator-controlled-upstream`, the directory must
also contain a matching `casework.package.json`. Development loopback may
select an authored project directory without that manifest.

`package.expectedPolicyDigest` is optional. When set, it is `sha256:` followed
by 64 lowercase hexadecimal digits, and the runtime starts only on the verified
package whose manifest names that `policyDigest`. A package naming any other
digest, or a directory without `casework.package.json`, is refused before the
runtime starts, and the refusal names the expected digest and the one found.
Set it to the digest printed by `caseworkctl package` for the package you
reviewed, so that replacing the files under `package.root` cannot change the
policy a restart loads.

`listener` is required. `listener.bind` is one numeric socket address, including
bracketed IPv6 forms, and defaults to `127.0.0.1:8100` when omitted from the
listener block. `listener.tlsTermination` is required. Use
`operator-controlled-upstream` behind an operator-managed TLS edge or
`development-loopback` for direct local development. `listener.networkExposure`
defaults to `private-address`; `container-private` permits an unspecified bind
only for a listener kept on a private container network.

`secretProviders` explicitly enables each accepted reference form. Declare
`file: {root: ABSOLUTE_DIRECTORY}` before using `secret:file/name`. Declare
`environment: {}` before using `secret:env/NAME`. The runtime does not fall back
from one provider to another. The maintained example uses mounted files.

`database.runtimeUrlRef` supplies the least-privilege service connection and
`database.migrationUrlRef` supplies the operator-run migration connection.
`database.trustedRootCertificateRef` is optional. Plaintext PostgreSQL is
available only to builds with the `postgres-test` feature and an explicit
`testOnlyPlaintext: true` setting.

`authentication.oidc` requires `issuer` and `audience`. `jwksSource` defaults to
discovery and can instead select a static `documentRef`. `scopeClaim` defaults
to `registry_scopes` for compatibility with existing deployments. Stock ThunderID
emits `scope`, so the maintained example and `caseworkctl init` set that explicit
override. `humanIdentity` defaults to claim
`registry_actor_kind` with value `human` and applies only to human roles.
Principal selection belongs exclusively to each authored
`accessProfiles[].principalClaim` in `casework.yaml`. The removed runtime field
`authentication.oidc.principalClaim` is refused with that replacement.

`audit` selects where Casework writes its audit entries and the key that
pseudonymizes the principals and identifiers they name. `audit.hashKeyRef` is
that key's secret reference. `audit.destination` is `file` (the default) or
`stdout`. A `file` destination requires the absolute `audit.path` of the active
file and accepts `audit.rotateBytes` (default 104857600, at least 1048576) and
`audit.retainDays` (default 90, at most 36500); `stdout` refuses all three. A
`caseworkctl` command that writes audit, such as an applied erasure or
settlement, writes to a sibling file named for its process role beside
`audit.path`, `audit.caseworkctl.ndjson` for `audit.ndjson`, or to standard
output with a `stdout` destination. Every entry carries the schema
`registry-casework-audit/v1`, a phase, and a correlation shared by an
operation's request entry and its response entries. The runtime writes the
request entry before it opens the operation's transaction, and the response
entries after that transaction commits; a destination that refuses either
fails the request with `service.unavailable`, and a refused response leaves the
committed change in place. A requested operation that records no domain event,
such as an idempotent replay, writes one response entry whose `outcome` is
`replayed` or `unchanged`, and returns its result only after that entry is
accepted. The database holds no audit state. `sources` is keyed by the exact source ids declared by the
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

`sources.<id>.reconciliationIntervalMilliseconds` controls only how often
Casework schedules source readback. When a readback pass lasts longer than the
interval, Casework skips missed ticks instead of replaying them back-to-back
against the source.

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
cargo test --locked -p registry-casework --features schema \
  schema::tests::committed_runtime_schema_matches_generated_bytes
```
