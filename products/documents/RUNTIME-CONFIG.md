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

The runtime reads and checks every key below. It acts on `identity`,
`package`, `listener`, `secretProviders`, `database`, `authentication`,
`audit`, `storage`, `contentVerification`, `transfers`, and
`retention.receiptRetentionDays`; the other blocks are checked so
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
| `database.migrationUrlRef` | Secret reference to the PostgreSQL URL `documentsctl apply` connects with to apply the schema, record the package in the activation ledger, and grant the runtime role. The runtime never uses it. |
| `database.trustedRootCertificateRef` | Optional secret reference to the CA that signs the database certificate. |
| `database.testOnlyPlaintext` | Accepted only by builds with the `postgres-test` feature; an operator build refuses it. |
| `authentication.oidc` | The shared OIDC issuer block (`issuer`, `audience`, `jwksSource`), `allowedClients`, and `scopeClaim` (default `scope`). `allowedClients` must list clients; `unrestricted` is refused. |
| `audit` | `destination` (`file`, the default, or `stdout`), `path` for a file journal, and `hashKeyRef`. |
| `storage` | `type: database`, or `type: s3` with the shared object storage keys (`url`, `bucket`, `region`, `pathStyle`, `accessKeyIdRef`, `secretAccessKeyRef`, `caBundleRef`, `attemptTimeoutMilliseconds`). `maximumDocumentBytes` is the deployment ceiling on one document version: 16 MiB when omitted, at most 16 MiB for `database` and 64 MiB for `s3`. Startup refuses a package whose policy asks for more. The storage binding is pinned at the first upload, and a later start under another backend, bucket, or scope is refused. |
| `contentVerification` | `type: http` with `url`, `authorizationRef`, `policyId`, and `attemptTimeoutMilliseconds` (100 to 60000). `type: disabled` is accepted only beside `tlsTermination: development-loopback`. |
| `transfers.minimumDeadlineSeconds` | 1 to 3600, default 60. The deadline of the smallest upload or download. |
| `transfers.mebibyteAllowanceSeconds` | 1 to 600, default 8. The time added to a transfer's deadline for every started mebibyte of the document. |
| `cleanup.erasure` | `active` or `paused`. `paused` stops every erasure and the sweep of orphaned objects; a removal request still stops release at once, and lapsed uploads are still expired. |
| `destinations.hooks` | The shared URL hook destination block, keyed by the destination id `documents.yaml` names: `url`, `hmacSha256KeyRef`, `attemptTimeoutMilliseconds` (100 to 10000, 5000 when omitted), and `maximumAttempts` (1 to 20, 8 when omitted). At most 128 destinations. Startup refuses a project hook whose destination is not bound here and a signing key it cannot resolve. Plain `http` is accepted only for a loopback address. Rebinding a destination needs a restart, not an apply. |
| `retention.receiptRetentionDays` | 1 to 365, default 7. How long an `Idempotency-Key` on a reservation or a grant is held; a retry after it answers `idempotency.expired`. |
| `retention.hookPayloadRetentionDays` | 1 to 30, default 7. How long a captured event is held for delivery; a delivery not completed by then expires unsent. |

Seven days is a placeholder, not a jurisdictional recommendation: a
retention schedule approves the deployed values.

Erasure reaches only what the Store serves. Database backups, WAL archives,
replicas, and S3 bucket replicas or provider backups keep erased bytes for as long as
the operator retains them, and a removed document's bytes stay on PostgreSQL
pages until they are overwritten or `VACUUM FULL` rewrites the table. Set the
retention of backups, archived WAL, and bucket replicas to the
longest period the retention schedule allows erased content to survive; no
key in this document controls them.

## Startup

`serve` reads and checks the whole document and stops, naming every finding,
before it opens a connection or binds a socket. It then, in order:

1. reads the package at `package.root`, verifies it, and refuses a digest
   other than `package.expectedDigest` when one is pinned;
2. connects with the runtime credential, reads the activation ledger, and
   refuses a database with no active package, one recorded for another
   `identity.databaseId`, and one whose active package is not the verified
   package; it then refuses a database that does not carry exactly this
   release's schema, or a runtime role that lost its grants or gained
   authority over the schema. Serving never applies the schema:
   `documentsctl apply --runtime-config FILE` does, over the migration
   credential;
3. opens the audit journal;
4. activates content storage and refuses a storage binding other than the
   one pinned at the first upload;
5. activates the content verifier, then suspends and re-queues every
   finalized version verified or queued under another verifier binding;
6. binds the listener, serves `GET /health` and the document routes, and
   runs the content verification worker until shutdown.

`documentsctl plan`, `apply`, `status`, `verification list` and `replay`, and
`erasure status`, `list`, and `replay` read this same document. They write their audit records to a companion
journal under the `documentsctl` process name, beside the runtime's file
journal, so they never contend for the running service's journal.

Every document route verifies a bearer access token against
`authentication.oidc` before it reads a request body. A token the verifier
refuses answers `authentication.refused` with a `Bearer` challenge; a
verifier that cannot be reached answers `service.unavailable`.

## Transfer memory

Every upload, download, and content verification attempt holds the whole
document version in memory while it runs. One transfer budget, shared by all
three, bounds those bytes at the larger of 256 MiB and
`storage.maximumDocumentBytes`. An upload or download that finds no room in
the budget is refused at once with `service.unavailable` and `Retry-After`;
it never waits for room. A background verification attempt waits for room
only within its attempt timeout, then ends as a transient failure and is
retried on its backoff, so it never holds its job lease past the attempt
deadline. A transfer still holds its share until it completes or
reaches its deadline (`transfers.minimumDeadlineSeconds` plus
`transfers.mebibyteAllowanceSeconds` for every started mebibyte), when it is
cut off and lets go. Transient copies made while hashing, storing, and
sending can reach about twice the budget, so size the host for about 512 MiB
of document memory on top of the process's own needs.
