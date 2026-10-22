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
`audit`, `storage`, `contentVerification`, `transfers`, `cleanup`, and
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
| `database.runtimeUrlRef` | Secret reference to the PostgreSQL URL the runtime connects with. The connection always uses TLS and verifies the server certificate and its host name; an `sslmode` in the URL does not change that. |
| `database.migrationUrlRef` | Secret reference to the PostgreSQL URL `documentsctl apply` connects with to apply the schema, record the package in the activation ledger, and grant the runtime role. The runtime never uses it. It requires TLS like the runtime URL. |
| `database.trustedRootCertificateRef` | Optional secret reference to a PEM bundle of the CA certificates that sign the database certificate, for a private CA. When set, these are the only roots trusted; when omitted, the system's trusted roots are used. |
| `database.testOnlyPlaintext` | Accepted only by builds with the `postgres-test` feature, for the PostgreSQL test suites; an operator build refuses it with `documents.runtime.plaintext-database`, so a local run needs a database that serves TLS too. |
| `authentication.oidc` | The shared OIDC issuer block (`issuer`, `audience`, `jwksSource`), `allowedClients`, and `scopeClaim` (default `scope`). `allowedClients` must list clients; `unrestricted` is refused. `jwksSource` defaults to the key set the issuer's discovery document names; see [Signing keys](#signing-keys) for the other sources. [Access tokens](#access-tokens) states what a token must carry. |
| `audit` | `destination` (`file`, the default, or `stdout`), `path` for a file journal, and `hashKeyRef`. A file journal seals its active file at `rotateBytes` (1048576 to 4294967295, default 104857600, 100 MiB) and deletes sealed files older than `retentionDays` (1 to 36500, default 90); the operator commands' companion journal rotates and is kept the same way. Either key beside `destination: stdout` is refused with `documents.runtime.invalid-audit`. Deleting a sealed file is not proof it reached off-host storage: ship the records you must keep before `retentionDays` passes. |
| `storage` | `type: database`, or `type: s3` with the shared object storage keys (`url`, `bucket`, `region`, `pathStyle`, `accessKeyIdRef`, `secretAccessKeyRef`, `caBundleRef`, `attemptTimeoutMilliseconds`). `maximumDocumentBytes` is the deployment ceiling on one document version: 16 MiB when omitted, at most 16 MiB for `database` and 64 MiB for `s3`. Startup refuses a package whose policy asks for more. The storage binding is pinned at the first upload, and a later start under another backend, bucket, or scope is refused. |
| `contentVerification` | `type: http` with `url`, `authorizationRef`, `policyId`, and `attemptTimeoutMilliseconds` (100 to 60000). `type: disabled` is accepted only beside `tlsTermination: development-loopback`. |
| `transfers.minimumDeadlineSeconds` | 1 to 3600, default 60. The deadline of the smallest upload or download. |
| `transfers.mebibyteAllowanceSeconds` | 1 to 600, default 8. The time added to a transfer's deadline for every started mebibyte of the document. |
| `cleanup.erasure` | `active` or `paused`. `paused` stops every erasure and the sweep of orphaned objects; a removal request still stops release at once, and lapsed uploads are still expired. |
| `destinations.hooks` | The shared URL hook destination block, keyed by the destination id `documents.yaml` names: `url`, `hmacSha256KeyRef`, `attemptTimeoutMilliseconds` (100 to 10000, 5000 when omitted), and `maximumAttempts` (1 to 20, 8 when omitted). At most 128 destinations. Startup refuses a project hook whose destination is not bound here and a signing key it cannot resolve. Plain `http` needs both a loopback address (`127.0.0.1`, `localhost`, or `[::1]`) and `listener.tlsTermination: development-loopback`; without the listener mode it is refused with `documents.runtime.insecure-url`, and a non-loopback `http` address is refused at startup. A pending or leased delivery pins the binding it was captured under (id, URL, key reference, timeout, attempts): startup refuses while one remains whose binding is no longer here, so to move a hook bind a new destination id, point the hook at it and apply, and remove the old entry once its deliveries have drained or expired. |
| `retention.receiptRetentionDays` | 1 to 365, default 7. How long a replay of an `Idempotency-Key` on a reservation or a grant is answered with the original outcome. After it the key stays spent: a replay answers `idempotency.expired`, and the row keeps only the key and request digests and the resource id. |
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
2. checks this document against the package's project and refuses it with
   the report `documentsctl check --project` gives for the same files: a hook
   whose destination `destinations.hooks` does not bind is
   `documents.runtime.unbound-hook-destination` at `/destinations/hooks`, on
   its line of this document;
3. connects with the runtime credential and refuses a runtime role that
   cannot use the schema or read the activation ledger, and says to restore
   its grants with `documentsctl apply`; it then reads the activation ledger,
   and refuses a database with no active package, one recorded for another
   `identity.databaseId`, and one whose active package is not the verified
   package; it then refuses a database that does not carry exactly this
   release's schema, or a runtime role that lost its grants or gained
   authority over the schema. Serving never applies the schema:
   `documentsctl apply --runtime-config FILE` does, over the migration
   credential;
4. opens the audit journal;
5. activates content storage and refuses a storage binding other than the
   one pinned at the first upload;
6. activates the content verifier, then suspends and re-queues every
   finalized version verified or queued under another verifier binding;
7. binds the listener, serves `GET /health`, `GET /ready`, and the document
   routes, and
   runs the content verification worker until shutdown.

An upload that finalizes a version wakes the verification worker of its own
process, which claims the job at once. The worker also looks for due jobs
every five seconds while idle, which picks up a job enqueued by another
instance or by an operator command, and one due again after a backoff.

`documentsctl plan`, `apply`, `status`, `verification list` and `replay`, and
`erasure status`, `list`, and `replay` read this same document. They write their audit records to a companion
journal under the `documentsctl` process name, beside the runtime's file
journal, so they never contend for the running service's journal. The
`verification` and `erasure` commands, like `serve`, need an activated
database: a runtime role that cannot use the schema or read the activation
ledger is refused as `documentsctl.activation.ledger-unreadable` at
`database.runtimeUrlRef`. Run `documentsctl apply` with the migration
credential, which grants the runtime role what it lacks, then retry.
`verification replay` also activates the project's hooks, so it refuses a
hook whose destination `destinations.hooks` does not bind with the
diagnostic `serve` gives, on its line of this document.

Every document route verifies a bearer access token against
`authentication.oidc` before it reads a request body. A token the verifier
refuses answers `authentication.refused` with a `Bearer` challenge; a
verifier that cannot be reached answers `service.unavailable`.

## Access tokens

Every route but `GET /health` and `GET /ready` takes
`Authorization: Bearer <token>`
holding an RFC 9068 access token. The runtime verifies:

- the header: `typ` is `at+jwt` or `application/at+jwt`, in any case; `alg`
  is `RS256` or `ES256`; and `kid` names a key of that algorithm in the
  issuer's key set;
- the signature, and the claims `iss`, equal to `authentication.oidc.issuer`;
  `aud`, holding `authentication.oidc.audience`; and `exp`, in the future.
  `nbf` is checked when present;
- the client: `azp` must be listed in `allowedClients`, or, when the token
  has no `azp`, `client_id` must be. A listed `client_id` does not rescue an
  unlisted `azp`;
- an exchanged token, one carrying `registry_assertion_issuer`, is refused
  unless `assertionIssuers` names that authority for its client.

The verified client then selects the one access profile in `documents.yaml`
whose `requesterClients` lists it, and the token must satisfy that profile:

- the claim `scopeClaim` names (`scope` by default), a space-separated string
  or an array of strings, carries every scope in the profile's
  `requiredScopes`;
- `registry_actor_kind` is the profile's `actorKind`, `service` or `human`.
  No profile admits `agent`;
- the claim the profile's `principalClaim` names, usually `sub`, is a
  non-empty string. It is the caller's identity: the subject a custody
  record holds and a grant names.

A token that fails verification, a `registry_actor_kind` that is not a
string, and a missing or empty principal answer `401 authentication.refused`
with a `Bearer` challenge. A verified token that matches no profile, through
its client, a missing scope, or an absent or different actor kind, answers
`403 profile.not-authorized`. A missing scope is the one refusal the runtime
logs, at `info`, naming the configured claim, the scope, and the profile,
never a value from the token.

## Signing keys

`authentication.oidc.jwksSource` selects where the runtime finds the issuer's
signing keys:

- `type: discovery`, the default, fetches the key set the issuer's discovery
  document names, and fetches it again as its cache ages or when a token
  names a `kid` it does not hold, so it follows the issuer's key rotation.
- `type: uri` with `uri` fetches the key set from that fixed address instead,
  in the same way.
- `type: static` with `documentRef`, a secret reference, reads a pinned key
  set once at startup and fetches nothing. Use it when the runtime cannot or
  should not reach the issuer, such as an isolated host or a local test
  issuer that publishes no discovery document. It never rotates on its own:
  to change keys, replace the secret and restart `serve`. The document is a
  JSON Web Key Set of at least one RSA or EC public key, and every key needs a
  non-empty `kid` no other key in the set repeats; startup refuses a
  symmetric key, a key without a `kid`, and a repeated `kid`.

## Operational logs

`documents` writes its operational log as JSON lines on standard error,
whatever `audit.destination` is, and only from the Document Store's own
crates: a dependency's log lines never reach it. `DOCUMENTS_LOG` selects the
level, one of `error`, `warn`, or `info`, and defaults to `info` when unset.
Any other value, including an empty one or a `RUST_LOG`-style directive,
stops `documents serve` before it reads its runtime configuration, with
`documents: DOCUMENTS_LOG must be one of error, warn, or info` and exit
status 2; `documents --version` and `--help` answer whatever the variable
holds. There is no `debug` level.

The log records startup, the background workers, and failures. It holds no
access log: a request writes no log line at any level unless something fails
behind it (the database, the content storage, or the token verifier cannot
answer, stored content fails its integrity check, the transfer budget is
full, a transfer runs out of time, or a stored document names a policy the
active package does not declare) or its token lacks a required scope. A
refused request is explained by its problem response, whose `code` names the
refusal. Who did what is recorded in the audit journal: each audited
operation, such as a reservation, an upload, a download, a grant issued or
revoked, and a removal request, writes a request entry before it acts and a
response entry with its outcome. `RUST_LOG` has no effect.

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
