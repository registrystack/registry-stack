# Messaging runtime configuration

Messaging reads one versioned operator document selected with
`messaging --runtime-config ABSOLUTE_FILE serve` or `migrate`, and
`messagingctl check --runtime-config ABSOLUTE_FILE` checks the same document
offline. The selected file path and every operated resource path are
absolute. The document is at most one mebibyte.

The closed envelope is:

```yaml
apiVersion: registry.registrystack.org/messaging-runtime/v1alpha1
kind: MessagingRuntimeConfig
```

Every mapping is closed: an unknown key is refused with its path, so a
misspelled setting never falls back to a default silently.
`generated/runtime/runtime.schema.json` states the same grammar for editors;
it is generated from the Rust types with

```bash
cargo run -p registry-messaging --features schema --example runtime-schema -- \
  --output products/messaging/generated/runtime
```

and never hand-edited. `examples/starter/runtime.example.yaml` is a complete,
commented document.

## Environment expressions

A string value may carry `${VAR}`, `${VAR:-default}`, or `${VAR:?message}`.
Substitution happens after the YAML is parsed, one string at a time, so a
substituted value is always text and can never add a key, a list entry, or a
document. An expression is refused in every member whose name ends in `Ref`:
those members name a secret, and a secret is named by a `secret:` reference
the resolver reads, never by text an environment variable spliced in. A
refusal names the member and never repeats the value or the default text.

## Keys

`package.root` is the directory holding the authored package,
`messaging.yaml`. `package.expectedDigest` is part of the grammar for pinning
the package to a `sha256:` digest; this version cannot verify a package
digest, so a document that sets it is refused rather than run with an
unverified pin.

`listener` is required. `listener.bind` is one numeric socket address and
defaults to `127.0.0.1:8107`. `listener.tlsTermination` is required: use
`operator-controlled-upstream` behind an operator-managed TLS edge, or
`development-loopback` for direct local development, which is refused on any
non-loopback bind. `listener.networkExposure` defaults to `private-address`;
`container-private` permits an unspecified bind only for a listener kept on a
private container network. A public unicast address is refused under every
combination.

`metricsListener.bind` is optional. When present, `/metrics` is served on that
socket and nowhere else; when absent, no metrics are served. The address must
be a concrete loopback or private address on a non-zero port, and must not be
the public listener's socket or one a wildcard public listener already covers.

`secretProviders` explicitly enables each accepted reference form. Declare
`file: {root: ABSOLUTE_DIRECTORY}` before using `secret:file/name`, and
`environment: {}` before using `secret:env/NAME`. At least one is required,
and the runtime does not fall back from one provider to another.

`database.runtimeUrlRef` supplies the service connection and
`database.migrationUrlRef` the operator-run migration connection, each a
PostgreSQL URL held in a secret. The runtime requires TLS on both;
`database.trustedRootCertificateRef` optionally selects the PEM bundle of a
private CA. `database.testOnlyPlaintext: true` is accepted only by a build
carrying the `postgres-test` feature.

`authentication.oidc` requires `issuer`, `audience`, and `allowedClients`.
`allowedClients` is never empty, and every requester client an access
profile names must be listed; a profile no admitted client could reach is
refused at load. `scopeClaim` defaults to `registry_scopes`. `jwksSource`
defaults to issuer discovery and can instead select
`{kind: static, documentRef: secret:...}`; `jwksUri` overrides the discovery
document's JWKS address. `assertionIssuers` maps an allowed client to at most
16 assertion authorities it may exchange a subject token from; a deployment
that performs no token exchange leaves it empty, and an exchanged token is
then refused. Tokens must be `at+jwt` access tokens.

`audit.path` is the journal file and `audit.hashKeyRef` the secret keying its
hash chain. The journal records the runtime start with the runtime version and
the retention periods in force.

`retention` bounds how long data is kept:

| Key | Default | Bounds |
|---|---|---|
| `payloadDays` | 7 | 1 to 30 |
| `recordDays` | 90 | `payloadDays` to 3650 |
| `submissionReceiptDays` | 7 | 1 to `recordDays` |

The start record carries the deployed values. The retention sweep that
enforces them arrives with the message store; until then no message data
exists to retain.

## The package

`package.root/messaging.yaml` carries:

```yaml
apiVersion: registry.registrystack.org/messaging-package/v1alpha1
kind: MessagingPackage
accessProfiles: [...]
```

Each access profile is `{id, principalClaim, requiredScopes, requesterClients,
actorKind, role, senderProfiles, templates, allowDirectContent,
requestsPerMinute, burst, dailyLimit}`. `actorKind` is `human`, `agent`, or
`service`, and omitted means any. `role` is `sender` or `operator`. A sender
lists at least one sender profile and one template; an operator lists none and
may not allow direct content. A requester client belongs to exactly one
profile. Rates, bursts, and daily limits must be positive; they are declared
now and enforced when submission lands.
