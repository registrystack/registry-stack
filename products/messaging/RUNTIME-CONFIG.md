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

`package.root` is the directory holding the authored package:
`messaging.yaml` and its `templates/` tree. `package.expectedDigest`, when
set, pins the package to a `sha256:` digest: the runtime, `messagingctl
check`, and `messagingctl apply` refuse a package whose digest differs, before
any database is reached. `messagingctl check` reports the digest to pin.

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

The rest of the manifest declares what callers send through:

```yaml
providers:
  - {id: mail-relay, kind: smtp}
senderProfiles:
  - {id: transactional, channel: email, provider: mail-relay, sender: notices@example.org}
  - {id: reminders-sms, channel: sms, provider: sms-gateway, sender: Registry, maximumSegments: 2}
templates:
  - {id: appointment-reminder, version: "1"}
```

A provider declares only its `kind`, `smtp` or `http`; its endpoint and
credentials are runtime configuration. A sender profile names its `channel`
(`email` or `sms`), a declared provider that can carry it, and the `sender`
identity. An SMS sender profile sets `maximumSegments`, from 1 to 10; a
rendered SMS needing more segments is refused `422
content.too-many-segments`. Each entry of `templates` names a version the
package ships; a version is a label, so quote a numeric one.

### Templates

Each template version lives under `templates/<id>/<version>/`:

- `template.yaml`, closed: `channel`, `locales` (at most 32 simple language
  tags such as `en` or `pt-BR`), and `parts`. An email version renders
  `subject`, `text`, and optionally `html`; an SMS version renders exactly
  `text`.
- `schema.json`, a JSON Schema (draft 2020-12) the data must satisfy before
  anything renders. It may not reference anything outside itself.
- `sample.json`, optional: data every locale must render at load, so
  `messagingctl check` shows each locale's SMS segment count.
- `<locale>/<part>.j2` for every declared locale and part, at most 64 KiB each.

Templates are Jinja without a loader: no `include`, `import`, `extends`, or
macros, no built-in filters or globals, and no file, network, or clock access.
A missing or null value refuses the render rather than printing empty. Two
filters format for the requested locale: `date` for an ISO calendar date and
`number(decimals)` for a number. Each part has a fuel budget and a byte
ceiling (512 bytes for a subject, 64 KiB for text, 256 KiB for HTML). HTML
parts escape every value and cannot opt out; text and SMS parts strip control
characters, and a subject strips newlines. A locale the version does not
declare is refused `422 template.locale-unavailable`, never answered in
another language.

Symbolic links are refused anywhere in the package, and files at the package
root other than `messaging.yaml` and `templates/` are ignored and not part of
the digest.

### The package ledger

The package digest is the SHA-256 of a canonical JSON listing of every
package file with its own SHA-256 and size. `messagingctl apply
--runtime-config FILE` reports whether the package on disk differs from the
one the database's package ledger names active; with `--apply` it records the
package. `messaging serve` refuses to start unless the package on disk has the
digest the ledger names active, so a package change takes effect when the
runtime restarts after `apply --apply`, and an edited file never changes what
a running deployment sends.
