# Document Store runtime configuration

The Document Store reads one versioned operator document selected with
`documents --runtime-config ABSOLUTE_FILE serve`. The selected file path and
every operated resource path are absolute, and the file may not be writable by
its group or by others. The document is at most one mebibyte.

`documentsctl check --runtime-config FILE` checks the same document offline,
with no database, network, or secret. `--environment` fills each `${VAR}`
expression from the environment and checks its value; without it each
expression is checked by its syntax and position. The check reports every
finding at once, each with its code and member, and never repeats a
configured value.

The closed envelope is:

```yaml
apiVersion: id.registrystack.org/formats/documents/runtime/v1alpha1
kind: DocumentsRuntimeConfig
```

Every mapping is closed: an unknown key is refused with its path, so a
misspelled setting never falls back to a default silently.
`generated/runtime/runtime.schema.json` states the same grammar for editors;
it is generated from the Rust types and never hand-edited.
`examples/starter/runtime.example.yaml` is a complete, commented document.

## Environment expressions

The shared runtime loader parses YAML before substituting `${VAR}`,
`${VAR:-default}`, or `${VAR:?message}` inside string values. Expressions are
refused in or below members ending in `Ref` and in secret-provider
declarations: credentials remain literal `secret:` references to a declared
provider.

## Keys

The runtime reads and checks every key below. In this skeleton it acts only on
`listener`, `database`, and `secretProviders`; the other blocks are checked so
a deployment written now keeps its meaning when the behaviour behind them
arrives.

| Key | Meaning |
|---|---|
| `identity.databaseId` | The logical identity of the one database this deployment owns, independent of the connection URL. Required. |
| `package.root` | The directory holding the deployment's `documents.yaml`. `package.expectedDigest` optionally pins it. |
| `listener.bind` | The socket address the HTTP listener binds. The starter uses `127.0.0.1:8116`. |
| `listener.tlsTermination` | `operator-controlled-upstream` behind a TLS proxy, or `development-loopback` for local work only. |
| `listener.networkExposure` | The shared network exposure declaration for the listener. |
| `secretProviders` | The declared secret providers, such as `file.root`. A reference to an undeclared provider is refused. |
| `database.runtimeUrlRef` | Secret reference to the PostgreSQL URL the runtime connects with. |
| `database.migrationUrlRef` | Secret reference to the PostgreSQL URL migrations will run with. |
| `database.trustedRootCertificateRef` | Optional secret reference to the CA that signs the database certificate. |
| `database.testOnlyPlaintext` | Accepted only by builds with the `postgres-test` feature; an operator build refuses it. |
| `authentication.oidc` | The shared OIDC issuer block (`issuer`, `audience`, `jwksSource`), `allowedClients`, and `scopeClaim` (default `scope`). `allowedClients` must list clients; `unrestricted` is refused. |
| `audit` | `destination` (`file`, the default, or `stdout`), `path` for a file journal, and `hashKeyRef`. |
| `storage` | `type: database` with `maximumDocumentBytes`, the deployment ceiling on one document version, at most one gibibyte. A document policy may only set a lower ceiling. |
| `contentVerification` | `type: http` with `url`, `authorizationRef`, `policyId`, and `attemptTimeoutMilliseconds` (100 to 60000). `type: disabled` is accepted only beside `tlsTermination: development-loopback`. |
| `cleanup.erasure` | `active` or `paused`. Expired and revoked document grants stop releasing bytes regardless. |
| `destinations.hooks` | Hook destinations by id: `url`, `hmacSha256KeyRef`, `attemptTimeoutMilliseconds` (100 to 60000), and `maximumAttempts` (1 to 32). A plaintext URL is refused outside development. |
| `retention.receiptRetentionDays` | 1 to 365, default 7. |
| `retention.hookPayloadRetentionDays` | 1 to 30, default 7. |

Seven days is a placeholder, not a jurisdictional recommendation: a
retention schedule approves the deployed values.

## Startup

`serve` reads and checks the whole document and stops, naming every finding,
before it opens a connection or binds a socket. It then connects with the
runtime credential and runs one trivial query; a database that refuses the
connection stops the runtime. Only then does it bind the listener and serve
`GET /health`.
