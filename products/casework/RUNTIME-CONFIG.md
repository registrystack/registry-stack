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
to `scope`, matching Registry Mint and the Registry Stack local development
tooling. `humanIdentity` defaults to claim
`registry_actor_kind` with value `human` and applies only to human roles.
Principal selection belongs exclusively to each authored
`accessProfiles[].principalClaim` in `casework.yaml`. The removed runtime field
`authentication.oidc.principalClaim` is refused with that replacement.

`audit.path` is the absolute JSONL journal path. `audit.hashKeyRef` supplies its
keyed-chain secret. `sources` is keyed by the exact source ids declared by the
selected policy; missing, extra, or empty ids are refused. Source access remains
bound to each source's configured reader profile and does not grant a caller a
Casework access profile.

`sources.<id>.reconciliationIntervalMilliseconds` controls only how often
Casework schedules source readback. It is deliberately excluded from the BReg
source binding generation because changing polling cadence changes neither
source authority nor saved source state. A cadence change therefore does not
invalidate displayed bindings or durable attempts. When a readback pass lasts
longer than the interval, Casework skips missed ticks instead of replaying them
back-to-back against the source.

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
