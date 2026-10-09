# Changelog

## Unreleased

- A removed key's `next` sentence now opens with a capital letter, whatever case
  the product wrote its replacement in. Render writes its own with code formatting.
- `registry-platform-yaml` is the shared configuration reader: one YAML
  subset (no anchors, aliases, merge keys, tags, or several documents), one
  scalar table, the `apiVersion` and `kind` envelope check, and a serde
  decoder that refuses unknown keys and null and reports every problem with
  a two-segment code, a JSON pointer, a line and column, and the fix, never
  a value from the file. Input is bounded at 1 MiB and 128 levels. It parses
  with `saphyr-parser` 0.1.0, which has no unsafe code.
- BREAKING: `registry-platform-config` `RuntimeConfigLoader` reads
  `runtime.yaml` through `registry-platform-yaml`. It now refuses anchors,
  aliases, null members, and keys the product's type does not declare, and
  it checks the envelope before removed keys. Substitution runs on string
  scalars while the document is read, so a diagnostic about a substituted
  value points at the expression; a substituted value never fills a number or
  boolean, and an expression in a key, `apiVersion`, or `kind` is refused.
  `RuntimeConfigError` carries `file()` and `diagnostics()`, and its `Display`
  renders every diagnostic as `error[code] file:line:col /pointer`, then the
  message and `next:` with the fix. The text of a diagnostic is no longer the
  `serde` decoder's. `reject_environment_expressions_in_authored_yaml`
  reads authored files with the same reader, so it also refuses YAML outside
  the shared subset.
- BREAKING: `registry-platform-config` removes the second, legacy code system
  from `RuntimeConfigError`. `RuntimeConfigErrorKind`, `kind()`, `code()`,
  `field()`, and `message()` are gone, with the `runtime_config.*` and
  `authored_config.*` codes they reported. Match on a diagnostic's `code`
  instead: `deciding_diagnostic()` is the error a consumer words the refusal
  from, `diagnostics()` lists them all, and `Display` renders them. The code
  of a refusal for a file that cannot be read is `UNAVAILABLE_CODE`
  (`platform.runtime-config.unavailable`). The dotted field becomes the
  diagnostic's JSON pointer `path`; a missing `apiVersion` or `kind` is
  reported at the root, where the reader reports it.
- BREAKING: `registry-platform-config` `RuntimeConfigLoader` refuses a
  `${VAR}` value that holds a control character other than tab, line feed, or
  carriage return, with `config.substitution` naming only the variable, as the
  reader refuses the same character written in the file. Migration: remove
  the control character from the variable.
- BREAKING: `registry-platform-yaml` refuses a mapping key that holds a control
  character other than tab, line feed, or carriage return with
  `yaml.control-character`, at the key's position and at the enclosing mapping's
  pointer, so the diagnostic never repeats the key. Migration: remove the
  control character from the key.
- `registry-platform-yaml` `Debug` output for a node shows its kind and
  position and no scalar value, and an entry's key is redacted, where integers,
  floats, booleans, and keys printed.
- `registry-platform-config` decides a refusal by `config.unknown-key` ahead
  of any other value problem, so a typo of a required key names the typo, not
  the missing member.
- `registry-platform-httputil` adds the bounded same-key resend the BReg,
  Casework, Messaging, and Scheduling clients share:
  `client::retry_keyed_mutation`,
  `DEFAULT_MUTATION_RETRIES` and `MAXIMUM_MUTATION_RETRIES` (both 2),
  `MAXIMUM_MUTATION_RETRY_AFTER_SECONDS` (5), the `KeyedMutationAttempt`
  outcome, `RetryAfter`, which reads one delta-seconds `Retry-After` field,
  and `classify_keyed_attempt`, the one rule that resends an unknown outcome
  on a 5xx answer and never after a 4xx status line. Waits are 250 ms, then
  500 ms, or a longer `Retry-After` of at most 5 seconds; a longer or unusable
  `Retry-After` ends the retries, and a count above the maximum is clamped.
- `registry-platform-httputil` `client::send_failure_kind` reports a connect
  timeout as `TransportKind::Connect`, where it reported `Timeout`, because no
  request was sent on a connection that was never established. The BReg,
  Casework, Messaging, and Scheduling clients therefore treat a connect
  timeout as a known failure and never resend it; Casework's
  `mutation_class` reports it as `Deterministic`. The review, Discovery, and
  Evidence clients and the token exchanges change only the reported kind,
  from `timeout` to `connect`; the review client still classifies the
  failure as ambiguous.
- BREAKING: `registry-thunderid-tooling` reads the task connection file that
  `evidencectl dev grant`, `bregctl dev grant`, and `caseworkctl dev grant`
  share through `registry-platform-yaml`. The file opens with
  `apiVersion: id.registrystack.org/formats/platform/task-connection/v1alpha1`
  and `kind: PlatformTaskConnection` in place of `version: 1`; each client
  names its key as `assertionKeyRef: secret:file/<name>` or
  `secret:env/NAME`, resolved through a top-level `secretProviders` block,
  in place of `assertionKeyFile`. The file may be readable by others but not
  writable by group or others. A refusal reports every finding with a
  `platform.task-connection.*` or reader code and repeats no value; an
  unopenable file makes `evidencectl dev grant` exit 3. Migration: replace
  `version: 1` with the envelope, and move each `assertionKeyFile` to
  `secretProviders.file.root` plus `assertionKeyRef: secret:file/<name>`.
  Its JSON Schema is `products/platform/schemas/task-connection.schema.json`.
- BREAKING: the ThunderID development session state file, `session.json`,
  opens with `apiVersion` and `kind: PlatformThunderidSession` and uses
  camelCase members; the unused `schema_applied` member is gone. A file
  written by an earlier release is refused. Migration: stop the development
  session, delete the directory that holds `session.json`, and start it
  again.
  Migration steps and the diagnostic code table for both files:
  `release/notes/config-conventions/platform.md`.
- `evidencectl dev check <file>` checks a task connection file or a session
  state file offline, without resolving a secret reference, and exits 0, 1,
  or 3 under the shared check contract; `--format json` reports the
  diagnostics.

## v0.39.0 - 2026-10-06

- `registry-platform-hooks` lets a product's `DeliverySeams` note each worker
  iteration that completed without failure, idle or not, through the defaulted
  `iteration_succeeded` method, so the product can report how recently its
  delivery worker made progress. The default notes nothing.
- BREAKING: `registry-platform-hooks` `delivery_schema::install` no longer
  upgrades delivery tables created by builds older than v0.38.0. It no longer
  backfills `payload_expires_at`, `handler_kind`, `data_schema`, or the
  proposal columns, no longer replaces the legacy answer constraint, and no
  longer refuses pre-Version 1 webhook history. It still adds the dead-letter
  reason column and its constraint to a delivery-state table created without
  them. A product that installs once on an empty schema, as Registry
  Scheduling does, is not affected.

## v0.38.0 - 2026-10-01

- Add `registry-platform-activation`, the shared PostgreSQL activation ledger,
  database identity, and runtime privilege checks used by Casework, Scheduling,
  and Messaging. Products keep ownership of transactions, migrations, audit,
  and package-specific activation hooks (#1731).
- `registry-platform-httputil` refuses `localhost` and every `*.localhost`
  name for a `productionHttps` or `privateServiceHttp` data destination when
  the binding is constructed, whatever private ranges are allowed. Local
  receivers require `loopbackDevelopmentHttp`.
- `registry-platform-hooks` records a closed, value-free dead-letter reason
  when the installed schema has the column, lists work captured under a
  superseded binding, and can discard pending work, a dead letter, or an
  expired lease under its exact generation without rebinding or sending it.
- `registry-platform-sdjwt` closes the inline proof key member set to `kty`,
  `crv`, `x`, `y`, `alg`, `kid`, and `use`, with `use` only as `sig`.

## v0.37.0 - 2026-09-29

- Add `registry-platform-ratelimit`, a shared crate with two in-memory
  keyed limiters, `TokenBucketLimiter` and `FixedWindowCounter`, each capped
  at a fixed number of tracked keys. Evidence uses it for its request budget
  and failed-selector counter with no change in behavior: the same refill,
  key cap, pruning, and refusals. A cost above the burst is refused as
  `CostExceedsBurst` before any bucket is touched.
- Add `registry-platform-dispatch`, the shared at-least-once dispatch core:
  the idempotency-key recipe, the policy frozen with each job, and, behind
  the `postgres` feature, a fenced PostgreSQL lease machine with claim,
  lease-expiry recovery, retry, dead letter, expiry, replay, cancellation,
  and an opt-in quarantine. The product owns the job table, the audit around
  every transition, and the send. The `registry-platform-hooks` notification
  delivery worker runs its lease state machine on it.
- `registry-platform-crypto` gains a `mac` module with HMAC-SHA256 and, for
  verifying schemes a provider already signs that way, HMAC-SHA1 tags, each
  verified in constant time, and `constant_time_eq` for shared secrets such
  as URL tokens. A `MacMismatch` refusal carries no tag, key, or message.
- `registry-platform-httputil` gains a side-effecting send class for data
  destinations, compiled only by
  `DataDestinationRequestTemplate::new_script_send`: a POST with a JSON or
  form body, or a GET whose content travels in the query string only behind
  a `QueryStringContentAcknowledgement`. It also gains a typed AWS SigV4
  path for bounded JSON 1.0 sends, `ProductionAddressPolicy` for a product
  that opens its own non-HTTP connection, and
  `DestinationSendError::delivery_certainty`, which reports a failed send as
  `NotSent` before the connection is established and `MaybeSent` after.
- `ExchangeAuthorization::upstream` sends an optional actor token with an
  RFC 8693 exchange.
- `PrivateKeyJwt::redeem_authorization_code` redeems an authorization code
  with PKCE and the configured resource, and returns any ID token
  unverified.
- `CspBuilder::deny_by_default` starts a policy from `default-src 'none'`,
  and `with_form_action` and `with_style_src` add directives to it.
- `AuthorizationAuditEvent::without_purpose` builds an allowed or denied
  event for a product that records no purpose.
- The `test-authorization-server` feature of `registry-platform-testing`
  adds a local authorization server for authorization code, client
  credentials, and token exchange tests.

## v0.36.0 - 2026-09-29

- Recover a torn final line at open instead of refusing to start: the file
  writer copies the bytes after the last complete line to the owner-only side
  file `<path>.torn`, syncs it, truncates the active file to its last complete
  line, and logs the side file's path and byte count, never the bytes. An
  existing side file holding other bytes is never overwritten and refuses open.
  `check_writable` accepts what open would recover.
- Refuse a `FileDestination` whose file name ends in a companion suffix
  another stream at the shorter name owns (`.lock`, `.seq`, `.seq.tmp`,
  `.torn`, or a sealed-segment `.<8 digits>`), with
  `AuditDestinationError::PathNamesReservedCompanion` naming the collision.
- Add `AuditSegments` and `SealedSegment`, a read-only view of a stream's
  companion names, sealed segments oldest first, and next sequence, for
  inspection tooling.

## v0.35.0 - 2026-09-28

- Add `AuditWriter::begin`, which appends a `request` entry and returns an
  `AuditRequest` that owes its `response`. A response the handle writes, or
  one appended under the same schema and correlation, answers it; a handle
  dropped unanswered, by an early return, a panic, or a canceled future,
  writes the product's `unfinished` record as the response, so a request
  entry stays unpaired only when the process stops while a write is in
  flight, or when the writer has already stopped after a failed write: the
  response a dropped handle owes is then logged and discarded while the
  process keeps running, as is a response the stopped writer refuses. A file
  destination flushes that line on the runtime, or when the last reference
  to the writer is dropped at shutdown.

- Refuse an audit file name longer than 246 bytes, including a process
  role's sibling name, so the writer's rotated and lock files fit a 255-byte
  file-name limit instead of stopping the writer at its first rotation.
- Refuse to reopen an audit file ending in an incomplete JSONL entry, preserving
  its bytes for operator archival before starting a fresh stream.
- Keep queued stream appends stopped after an earlier write fails, and finish
  accepted file writes when their request task is canceled. Group commits retain
  every waiting entry and update the pinned file state before accepting later
  writes.

- Add `AuditWriter`, the one audit writer every product uses. It appends a
  plain JSON envelope (`schema`, `eventId`, `time`, `phase`, `correlation`,
  `record`) to an owner-only file with fsync and group commit, size rotation,
  and age-based retention, or writes one flushed line to stdout. A failed write
  stops the writer until restart so the caller fails closed. The file
  destination refuses a second writer on the same path and a directory that is
  group- or world-writable.
- BREAKING: remove the audit hash chain. Tamper evidence is now a deployment
  concern: ship the audit stream to append-only storage. Removed from
  `registry-platform-audit`: `ChainState`, `AuditChainHasher`,
  `AuditChainProfile`, `AuditProfile::chain_hasher`,
  `AuditProfile::bootstrap_or_start_empty`, `AuditEnvelope`, `AuditSink`,
  `JsonlFileSink`, `JsonlStdoutSink`, `SyslogSink`, `DurableSegmentedJsonlSink`,
  `DurableSegmentedAuditLog`, `SegmentedAuditSummary`,
  `verify_segmented_audit_chain`, `visit_stopped_segmented_audit_chain`,
  `segmented_audit_paths`, `verify_chain`, `verify_jsonl_lines`,
  `verify_jsonl_lines_with_hasher`, `quarantine_and_recover_chain`,
  `ChainRecoveryOutcome`, `CHAIN_BREAK_EVENT`, `ChainBreakRecord`,
  `OptionalHashHex`, `ChainVerification`, `ChainVerificationError`, and the
  `AuditError` variants `InvalidHashHex`, `NonTailableSink`, `HashMismatch`,
  `ChainVerification`, `ChainForkDetected`, and `SegmentMissing`. Removed from
  `registry-platform-testing`: `assert_chain_integrity` and
  `ChainAssertionError`. Keyed audit references from `AuditProfile` and
  `AuditKeyHasher` are unchanged byte for byte.

- BREAKING: `OidcIssuerConfig::check` refuses an issuer carrying a query
  component, as it already refused credentials and a fragment. The refusal
  names the field and does not repeat the configured value.
- BREAKING: `TransitSigner::initialize` returns `TransitInitializationError`,
  which names the fault it met: an unreachable socket, a refused metadata read,
  a provider server error on that read, a malformed response, unsafe custody,
  a key version above `latest_version`, a key version below
  `min_encryption_version`, a public key mismatch, or a failed self-test. The
  causes carry no path, provider response, or key material.
- Add `ValidatedFetchUrl::immediate_get_with_additional_roots` and
  `JwksFetcher::new_trusting_additional_roots`, so a key set served under a
  private certificate authority is fetched with that authority trusted beside
  the system roots for that connection alone, without a process-wide trust
  store change.

- Add the shared runtime configuration loader: a bounded, strict YAML reader
  for `runtime.yaml` that refuses symbolic links, removed keys, and a wrong
  envelope, then substitutes `${VAR}`, `${VAR:-default}`, and
  `${VAR:?message}` inside string values after parsing. Substitution is
  refused inside `*Ref` fields, under `secretProviders`, and in authored
  package files; the authored-file check refuses text it cannot read. No
  refusal repeats a configured value: a `:?` message, an invalid variable
  name, and a refused enum variant are all withheld.
- Add the shared configuration blocks (`secretProviders`, `database`,
  `jwksSource`, `package`, `listener`) and their canonical JSON Schema under
  `products/platform/generated/`. The blocks also serialize back to the form
  they were read from, so a runtime that renders its configuration keeps the
  same key names.
- Add `registry_platform_config::package`, the one package format every
  runtime serves. A package directory holds `SHA256SUMS`, one `sha256sum`
  line per file sorted by path, and an optional one-line `REVISION` that is
  listed and hashed like any other file. The package digest is the `sha256:`
  label of the `SHA256SUMS` bytes. `write_package` and `write_sum_file` write
  a package, `plan_package` reports its digest without writing, and
  `verify_package` recomputes every digest and refuses a changed, missing, or
  extra file by name, a symbolic link, a special file, or a package over its
  `PackageLimits`. `PackageConfig::verify_package` also compares the digest
  with `package.expectedDigest` when it is set, with the same expected and
  found message in every runtime.
- Add the runtime configuration conformance gate,
  `products/platform/scripts/check-config-conformance.py`, run in root CI. It
  fails when a runtime's generated schema re-declares a shared block, when a
  runtime without a generated schema stops holding a shared block type in its
  runtime struct, when a hand-written schema copy of a shared block widens it,
  when no non-test code reads `runtime.yaml` through the shared loader, when a
  runtime still expands its configuration outside the shared loader, when the
  tests proving `*Ref` fields and authored files refuse `${VAR}` go missing, or
  when the committed canonical schema differs from its generator.
- Add the shared `audit.hashKeyRef` and `authentication.oidc` blocks
  (`AuditKeyConfig` and `OidcIssuerConfig`). The OIDC block holds the exact
  issuer URL, one bounded audience, and the `jwksSource`; a product embeds it
  beside its own token rules. `SecretReference` now reads and writes as its
  reference text, so a configuration struct can hold one directly.
- Add the shared `authentication.oidc` client block (`OidcClientsConfig`):
  `allowedClients` and the bounded `assertionIssuers` map, at most 64 clients
  of at most 128 bytes, each with at most 16 distinct issuers of at most 512
  bytes. Add `registry_platform_oidc::parse_static_jwks`, which refuses a
  static key set that is empty, holds a symmetric key, or leaves a key without
  a unique `kid`.
- Add `REMOVED_OIDC_JWKS_URI`, the removed `authentication.oidc.jwksUri` key
  with its `jwksSource` replacement, and, behind the `schema` feature,
  `schema::jwks_document_provider_requirements`, the root `allOf` rule that a
  static `jwksSource.documentRef` enables the secret provider it names.
- Add Ed25519 and ES256 private key generation beside ES384, with RFC 7638
  thumbprint tests for RSA, EC, and OKP keys.
- BREAKING: remove `reject_deprecated_config_fields`; runtimes declare removed
  keys on the loader instead.
- BREAKING: `JwksSource::Discovery` is an empty struct variant, so a `uri` or
  a `documentRef` written beside `kind: discovery` is refused.
- BREAKING: `expand_config_env_vars` no longer repeats a `${VAR:?message}`
  message or an invalid variable name in its refusal.
- BREAKING: remove `expand_config_env_vars`, `expand_config_env_vars_with`, and
  `ConfigEnvExpansionError`. Every runtime reads `runtime.yaml` through
  `RuntimeConfigLoader`, which substitutes `${VAR}` inside parsed string values.

## v0.34.0 - 2026-09-25

- The shared platform crates have no user-visible changes in this release.

## v0.33.0 - 2026-09-22

- Read a token response that states an empty `scope` as granting no scope
  instead of refusing it as malformed. Keycloak states `"scope": ""` for a
  grant whose client scopes are all kept out of the token scope; a
  private-key-JWT provider that requested no scope now uses that credential,
  and one that requested scopes refuses it as narrowed.
- Add the shared hook declaration, signed delivery envelope, retained delivery
  worker, and product apply seam used by BReg and Casework.
- Add the feature-gated Rhai and WebAssembly execution adapters used by BReg
  action handlers. The WebAssembly feature remains non-default in the shared
  platform crate and is enabled by BReg's default feature set.

## v0.32.0 - 2026-09-15

- Add `registry_assertion_issuer`, derived by the exchange issuer from the
  verified subject-token issuer and reserved against configurable claim names
  and signer-declared attributes alike. A resource server may declare the
  assertion authorities each client is allowed to present, and refuses a token
  naming any other. An unconfigured server applies no rule, and a token that
  was not obtained by token exchange carries no such claim and is unaffected.
- Add the shared RFC 8693 exchange authorization used by the service clients to
  obtain tokens bound to one verified person or one approved task grant.
- Update `rustls` to 0.23.45 for RUSTSEC-2026-0285.

## v0.31.0 - 2026-09-13

- Add the closed contextual task-grant claim contract used by Casework,
  ThunderID, Evidence, and Base Registry Engine, including bounded clients,
  resources, purposes, subjects, permissions, approval, and expiry.
- BREAKING: remove `registry_grant_authority`. The exchange issuer derives
  `registry_grant_source_issuer` from the verified subject-token issuer instead
  of trusting a signer-chosen authority label or assertion-supplied source.

## v0.30.0 - 2026-09-12

- OIDC access-token type matching treats `at+jwt` and
  `application/at+jwt` as equivalent RFC 9068 spellings when either is the
  configured type. Other token types remain refused.

## v0.29.0 - 2026-09-10

- The shared platform crates have no user-visible changes in this release.

## v0.28.0 - 2026-09-09

- The shared platform crates have no user-visible changes in this release.

## v0.27.0 - 2026-09-07

- Runtime dependency checks can require an explicitly configured audit root.
- OIDC permission parsing rejects malformed present scope claims instead of
  ignoring malformed values. A present claim must be a string or an array of
  strings; a missing claim remains allowed and supplies no permissions.

## v0.26.1 - 2026-09-04

- The shared platform crates have no user-visible changes in this release.

## v0.26.0 - 2026-09-03

- `registry-platform-config` exposes a parsed `SecretReference` for the exact
  `secret:env/NAME` and `secret:file/name` grammars. Its debug form redacts the
  reference name, and callers may resolve an already parsed reference without
  interpreting it again.
- `registry-platform-httputil` adds a closed event-delivery destination and
  request shape for bounded canonical-JSON CloudEvents HTTP posts. The shared
  boundary fixes the path, header names, body and request limits, forbids an
  authorization slot, and keeps redirects disabled for Base Registry Engine
  webhook delivery.

## v0.25.0 - 2026-08-22

- No separately versioned Registry Platform API changes.

## v0.24.0 - 2026-08-21

- No separately versioned Registry Platform API changes.

## v0.23.0 - 2026-08-20

- No separately versioned Registry Platform API changes. The shared
  outbound HTTP utilities gained crate-private DNS-pinned credential
  clients used by the platform's own OAuth client authentication.

## v0.22.0 - 2026-08-14

- Shared file-secret validation accepts owner-only mode `0400` for read-only
  mounts and mode `0600` for read-write files. It continues to reject linked,
  non-regular, executable, group-readable, and world-readable secret files.
- No separately versioned Registry Platform API changes.

## v0.21.0 - 2026-08-13

- No separately versioned Registry Platform API changes. This release adds
  official Evidence Gateway and Registry Mint runtime image distribution.

## v0.20.1 - 2026-08-12

- No separately versioned Registry Platform API changes. This patch release
  carries the Evidence source-outcome contract needed for governed Relay V2
  unresolved consultations.

## v0.20.0 - 2026-08-12

- Shared HTTP utilities now separate client and server boundaries. Evidence,
  Relay, and Registry Mint reuse the bounded outbound HTTP, private-key-JWT,
  token, destination, and transport checks without importing a retired product
  configuration model.
- Removed unused Relay V1 configuration, audit, operations, and policy
  primitives from the current workspace. Current products keep the smaller
  shared authentication, cryptography, HTTP, SD-JWT, SQLite, and testing
  foundations they exercise.

## v0.19.0 - 2026-08-11

- The shared SQLite boundary now applies one end-to-end deadline to admission,
  statement execution, and snapshot verification. Readiness checks coalesce
  concurrent probes and keep schema and digest work within the same bound.
- Exact-tag builds add the `relay` and `relayctl` release identities. Source
  and development builds continue to report the `-dev` suffix.

## v0.18.0 - 2026-08-09

- Executables report a development version, such as `0.18.0-dev`, unless they
  were produced by the release build. `registry-relay`, `registryctl`,
  `evidence`, `evidencectl`, `mint`, and `evidence-oid4vci` all take their
  `--version` text from the new `registry-platform-buildinfo` primitive.
  Released binaries and the published Relay image still report the bare
  released version.
- The shared SD-JWT verifier validates RFC 9901 key-binding JWTs and the closed
  OID4VCI proof-JWT profile used by the Evidence wallet-delivery adapter.

## v0.17.0 - 2026-08-07

- Registry Platform carries the shared audit, HTTP security, OpenID Connect,
  cryptographic, and operations primitives used by Registry Relay and
  Evidence. There is no separately versioned Registry Platform API release.

## v0.16.3 - 2026-08-01

- No user-visible Registry Platform changes. The v0.16.2 workflow stopped at
  an unpublished draft before public image promotion. Install v0.16.3.

## v0.16.2 - 2026-08-01

- No user-visible Registry Platform changes. This release fixes forward from
  the v0.16.1 tag workflow, which stopped after creating an unpublished empty
  draft. Install v0.16.2; no final v0.16.1 images, assets, or documentation
  were published.

## v0.16.1 - 2026-08-01

- No user-visible Registry Platform changes. This release fixes forward from
  the v0.16.0 tag workflow, which failed before any job or public write.
  Install v0.16.1; no final v0.16.0 images, assets, or documentation were
  published.

## v0.16.0 - 2026-08-01

- No separately versioned Registry Platform API changes. This release carries
  the shared security, configuration, audit, and issuance primitives used by
  Registryctl, Relay, and Notary v0.16.0.

## v0.15.2 - 2026-07-28

- No user-visible Registry Platform changes. This release fixes forward from
  the incomplete v0.15.1 publication.

## v0.15.1 - 2026-07-28

- No user-visible Registry Platform changes. This release fixes forward from
  the failed v0.15.0 publication workflow.

## v0.15.0 - 2026-07-28

- No separately versioned Registry Platform API changes. This release carries
  the shared configuration, diagnostic, and operations primitives exercised by
  the Registryctl, Relay, and Notary onboarding and release gates.

## v0.13.0 - 2026-07-25

- BREAKING: `registry-platform-ops` replaces deployment-waiver `reason` with
  required `reference` plus optional omitted `summary` in the shared posture
  contract. It now owns the common 128-byte reference and 256-character summary
  validation authority used by Relay and Notary. The default posture allowlist
  continues to exclude all waiver metadata. Relay, Notary, and posture schemas
  now share the portable structural reference and summary constraints;
  contextual credential and private-key marker checks remain in the shared
  semantic validator.

## v0.12.2 - 2026-07-20

- No user-visible Registry Platform changes. This release fixes forward from
  the incomplete v0.12.1 publication.

## v0.12.1 - 2026-07-20

- No user-visible Registry Platform changes. This release fixes forward from
  the incomplete v0.12.0 publication.

## v0.12.0 - 2026-07-19

### Added

- `registry-platform-ops` now carries the restricted per-resource Relay
  refresh-health posture contract and a matching reference fixture.
- `CredentialFingerprintProvider`, `KeyProviderKind`, and `KeyStatus` expose
  declaration-ordered `ALL` rosters so config-schema generation consumes the
  same closed labels as runtime parsing and diagnostics.

## v0.11.0 - 2026-07-18

- BREAKING: shared configuration `${VAR}` expansion now rejects environment
  variables that are unset or empty. `${VAR:-fallback}` uses its fallback for
  either state, `${VAR:-}` explicitly expands to empty, and `${VAR:?message}`
  reports its message for either state. Whitespace-only values remain non-empty.

## v0.10.0 - 2026-07-17

### Added

- `registry-platform-canonical-json` is the single shared RFC 8785 JSON
  Canonicalization Scheme implementation for Registry Stack hashes,
  signatures, JWK thumbprints, manifests, policies, and generated artifacts.
- `registry-platform-httputil` now provides the fixed-destination transport,
  closed JSON response decoding, signed DCI verification, bounded OAuth
  client-credentials flow, and typed Relay client primitives used by governed
  consultations.
- `registry-platform-audit` now provides typed durable-operation and governed
  pseudonym-keyring contracts for product-owned PostgreSQL state planes.

### Changed

- BREAKING: `registry-platform-ops` Notary posture now reports the global
  `notary.state` backend and uses `postgresql`, `in_memory`, and `state`
  vocabulary. The retired per-domain Redis replay and credential-status
  values are removed from the schema, examples, redaction fixtures, and
  allowlist.
- `registry-platform-cache` and `registry-platform-replay` retain only bounded
  in-memory implementations for focused tests and explicit single-process
  local development. Product runtimes own typed durable correctness state.

### Security

- Raw signed, hashed, or structurally interpreted JSON now uses the shared
  strict parser. Duplicate object members and integer tokens that are not
  exactly representable as IEEE 754 binary64 are rejected before
  interpretation instead of being silently overwritten or rounded.
- Public JWK and `did:jwk` parsing is bounded to 64 KiB, rejects duplicate
  members, and rejects symmetric or asymmetric private members. Non-secret
  extension metadata remains accepted, so implementers do not need to strip
  ordinary provider metadata from public keys.

## v0.9.0 - 2026-07-10

### Added

- Registry Config Bundle v1 is the shared offline configuration contract for
  Relay and Notary. The CLI `config apply-bundle` command and live HTTP apply
  surfaces are removed. First use `registryctl bundle verify` for stateless
  signature and binding verification, then place the signed bundle on the
  node. For a genuinely absent, version-specific antirollback state path,
  start the product server with `--initialize-state`; that boot verifies the
  bundle and initializes state. The product's read-only
  `config verify-bundle` command remains, but it requires accepted state to
  exist, so use it only for later candidate validation and restarts. Replace
  retired TUF-era fields inside `config_trust` with the
  current Config Bundle v1 trust fields because strict parsing rejects the old
  schema. Acceptance uses the durable
  `config_trust.antirollback_state_path`. Missing state fails closed except
  during that intentional first boot; a lower sequence or a different bundle
  at the accepted sequence is rejected as non-monotonic.
- `registry-platform-audit`: `JsonlFileSink::with_rotation_single_writer`, a
  constructor that takes a process-lifetime advisory lock on `<path>.lock`
  (refusing to start if another process holds it) and verifies the on-disk
  tail before each append, failing with `ChainForkDetected` instead of
  extending a diverged chain. Registry Relay and Registry Notary file sinks
  use it; `new` and `with_rotation` are unchanged.
- `registry-platform-audit`: `quarantine_and_recover_chain`, the offline
  recovery primitive behind `registry-relay audit quarantine` (#196). It
  archives the corrupt file set to `<name>.corrupt-<ts>`, starts a fresh
  chain whose first record is a hash-linked `audit.chain.break` event chained
  onto the last verifiable tail (torn trailing lines from an unclean stop are
  treated as a break, not an abort), and leaves off-host shipping as the
  completeness guarantee. Recovery also quarantines a legacy
  `<active-path>.anchor.json` sidecar left behind by pre-removal releases,
  renaming it with the same `.corrupt-<timestamp>` suffix as the quarantined
  data files.
- `registry-platform-ops`: `AuditSinkKind` and `audit_shipping_target(sink,
  offhost_shipping_declared)`, a shared classifier that maps a sink kind and
  the `deployment.evidence.audit_offhost_shipping` attestation onto the
  posture/doctor shipping-state fields (`shipping_target_configured`,
  `shipping_target`), so Registry Relay and Registry Notary cannot drift on
  the classification.
- `registry-platform-ops`: `registry.audit.ack_cursor.v1`, the JSON Schema
  contract for the local state file written by whatever ships audit events
  off-host (`acked_at`, `last_acked_hash`, optional `writer`), plus
  `evaluate_ack_health(cursor_path, now, max_age)`, a shared helper that reads
  the cursor and classifies it as `stale`, `missing`, `invalid`, or
  `unverified`; a fresh cursor becomes `ok` only after
  `AckObservation::bind_to_audit_tail` confirms that `last_acked_hash` equals
  the runtime's current keyed audit-chain tail. The default freshness window is
  `DEFAULT_AUDIT_ACK_MAX_AGE` (900s); a cursor whose `acked_at` is more than
  300s ahead of `now` is treated as `invalid` rather than perpetually fresh.
  An unreadable file, malformed JSON, a contract violation, or a
  non-RFC3339 `acked_at` all fail closed to `invalid` with a `detail` message,
  never silently to `ok`. Reads are capped at 16 KiB and reject non-regular
  files and symlinks, which prevents FIFO reads and allocation from an unbounded
  file. Relay and Notary add a 500 ms bounded worker around this synchronous
  helper in public runtime handlers. Tail equality proves the trusted shipper's
  claimed watermark belongs to the live chain and that the local backlog is
  zero. Because the cursor is unsigned local state, it is still not
  cryptographic proof of remote receipt.

### Changed

- Operators must back up antirollback state before an upgrade and keep
  release-specific bundle and state restore sets. A rollback restores the
  antirollback state belonging to that release. Deleting or reinitializing
  state to force an older bundle to load breaks the antirollback guarantee and
  is not a supported recovery procedure.
- Parked `registry-platform-sts` outside the active workspace until Assisted
  Access or delegation-profile work promotes a release-surface consumer (#298).
  The source remains in git, but the crate is no longer built as part of
  workspace CI or listed as a load-bearing platform crate. Its standalone fuzz
  target and Lab commons-check caller are parked with it, and NP-23 denial-audit
  parity is deferred until a named consumer reactivates the crate (#246; revisit
  tracked by #298).
- `registry-platform-audit`'s `JsonlFileSink::new` default rotation retention
  is raised from 5 files to 50 files (~500 MiB at the 10 MiB default file
  size), so the crate default no longer silently discards audit history after
  ~50 MiB. Consumers that pass explicit rotation settings via
  `JsonlFileSink::with_rotation` (Registry Relay and Registry Notary both
  configure 100 MB x 14 files) are unaffected. The safer default remains for
  future standalone consumers when a release-surface consumer is promoted.
- `registry-platform-audit` chain verification now treats the first retained
  record's `prev_hash` as the retained-set boundary. **Removed the local
  trusted-anchor verification API**: `ChainVerificationAnchors`,
  `verify_chain_with_anchors`, `verify_jsonl_lines_with_anchors`, and the
  `LastHashMismatch` error variant are gone, and the `.anchor.json`
  completeness-anchor sidecar is no longer written or read. Consumers verify
  retained-set internal consistency with `verify_chain`; completeness comes
  from off-host shipping evidence
  (`deployment.evidence.audit_offhost_shipping`), not a local anchor. Local
  verification detects edits, insertions, reordering, and interior deletions
  within the retained set only; leading or trailing truncation and a
  self-consistent full rewrite of the retained set are not locally
  detectable.
- `registry-platform-ops`'s `registry.ops.posture.v1` schema:
  `posture.audit` gains two required fields, `shipping_target_configured`
  (bool) and `shipping_target` (one of `stdout`, `syslog`,
  `declared_external`, `none`, `unknown`), reporting the sink type and the
  off-host shipping attestation. These are declared, config-derived state;
  the separate fields described next report observed delivery health. The schema is
  `additionalProperties: false` and keeps the `v1` identifier, so posture
  documents produced before this release fail against the new schema and
  vice versa: producers and strict validators pinned to
  `registry.ops.posture.v1` must upgrade together.
- BREAKING: `registry-platform-ops`'s `registry.ops.posture.v1` schema:
  `posture.audit` gains two more required, nullable fields, `shipping_health`
  (one of `ok`, `stale`, `missing`, `invalid`, `unverified`, or `null`) and
  `shipping_observed_at` (an RFC3339 timestamp, or `null`), reporting the
  observed freshness of off-host audit shipping from the ack cursor described
  above under Added. `shipping_health` is `null` iff
  `shipping_target_configured` is `false`; `shipping_observed_at` is `null`
  when no contract-valid cursor timestamp was read. `shipping_health` is
  `"unverified"` when a shipping target is
  declared but no cursor is configured or an offline caller cannot bind it to a
  live chain. `ok` requires a fresh cursor whose watermark equals the live
  keyed chain tail. This fills the delivery-health gap without claiming the
  unsigned local cursor cryptographically proves remote receipt. The schema keeps the `v1`
  identifier and `additionalProperties: false`, so this is the second breaking
  change to `posture.audit` under the `v1` identifier in this release:
  producers and strict validators pinned to `registry.ops.posture.v1` must
  upgrade together, and a validator built against the previous field set
  rejects documents carrying the new fields.
- BREAKING: `AckObservation` gains the public `last_acked_hash` field and the
  `unverified` and `invalid` constructors. Rebinding an `ok` observation now
  rechecks the supplied live tail and fails closed if the tail changed.
  Product gate inputs rename `audit_shipping_declared_external` to
  `audit_shipping_target_configured` in Notary `GateInput` and Relay
  `DeploymentFacts`, because stdout and syslog now require observed shipping
  health under `evidence_grade` too.
- `registry-config-report`'s `registry.config.diagnostic_report.v1` schema:
  the `audit_shipping` block gains optional `shipping_health` and
  `shipping_observed_at` fields with the same semantics as the posture fields
  above. Optional, so existing diagnostic report consumers are unaffected.
- `registry-config-report`'s `registryctl.validation.report.v1` schema now
  preserves the optional product `audit_shipping` block in aggregated doctor
  output, so valid Relay and Notary reports continue to validate after
  registryctl combines them.

### Fixed

- The named Relay and Notary `registry.ops.posture.v1` examples now match the
  live product projections and no longer claim checkpoint hashes or successful
  verification that those endpoints do not emit.

## v0.3.1 - 2026-06-21

### Security

- (AUDIT-03) `registry-platform-audit` now derives independent, domain-separated
  sub-keys for the audit chain HMAC and the identifier HMAC from the master
  environment secret using an internal HKDF-Expand (RFC 5869) over SHA-256, with
  distinct per-purpose `info` labels (`registry-platform-audit/chain-key/v1` and
  `registry-platform-audit/identifier-key/v1`). Previously both HMACs used the
  identical raw env material, so a leak of one key exposed the other. **This
  changes persisted chain and identifier hash values**; acceptable pre-beta
  (crate is `version 0.3.1`, `publish = false`) and only affects legacy
  pre-beta logs, which were already unkeyed/dev-only. Explicit `keyed(secret)`
  construction is unchanged (caller-owned key material).
- (AUDIT-02) `AuditHashSecret` now holds its HMAC key behind a
  `Zeroize`/`ZeroizeOnDrop` newtype so the raw key bytes are scrubbed when the
  last shared reference is dropped.
- (AUDIT-05) The query-redaction secret-parameter denylist now covers OAuth /
  OIDC and generic credential parameter names (`access_token`, `refresh_token`,
  `id_token`, `client_secret`, `client_assertion`, `assertion`, `bearer`,
  `code`, `private_key`, `credential`, `credentials`, `passwd`, `pwd`,
  `session_token`).
- (AUDIT-01 / AUDIT-06) The unkeyed verification and tail-hash convenience paths
  (`verify_jsonl_lines`, `AuditSink::tail_hash`) are now `#[deprecated]` and
  carry prominent warnings; production callers must use the keyed
  `*_with_hasher` variants with an explicit `AuditChainHasher`.
  `AuditSink::tail_hash_with_hasher` now fails closed by default so legacy custom
  tailable sinks cannot silently ignore the supplied keyed hasher through an
  unkeyed trait fallback.
- (REPORT-01) `registry-config-report` now exposes `ConfigExplanation::resolved_config`
  as a `RedactedConfig` newtype that can only be constructed via
  `RedactedConfig::redacted(..)` (which runs redaction internally), making
  redaction unbypassable at the type level for producers. Deserializing
  `RedactedConfig` now treats the input as untrusted and collapses it to
  `REDACTED_VALUE`; consumers that need to inspect rendered report JSON can use
  the wire-only `ConfigExplanationDocument` type. The wire format is unchanged
  (`#[serde(transparent)]`).
- (REPORT-03) `RequiredEnvVar` is documented as operator-sensitive (it enumerates
  secret env-var names and presence) and now offers `RequiredEnvVar::public_safe()`,
  a compatibility projection that collapses non-public entries to a generic
  not-checked placeholder. `RequiredEnvVar::public_safe_entries(..)` omits
  non-public entries entirely for public-facing lists so names, presence, and
  sensitive-entry counts are not disclosed.
- (OIDC-01) `registry-platform-oidc` `fetch_discovery_with_policy` now fails closed
  with `OidcError::MissingIssuer` when `jwks_uri_override` is set but `issuer` is
  empty, preserving an issuer binding when discovery is skipped.
- (HTTPSEC-01) `registry-platform-httpsec` `security_headers` now emits
  `Strict-Transport-Security` (`max-age=63072000; includeSubDomains`) by default,
  with `SecurityHeadersLayer::without_hsts()` / `with_hsts(..)` opt-outs.
- (HTTPSEC-02) `CorsPolicy::layer()` (which panics on an invalid policy) is now
  `#[deprecated]` in favor of the fallible `CorsPolicy::try_layer()`.

## v0.3.0 — 2026-06-13

### Added

- Posture profile gate vocabulary in `registry-platform-ops` (#55, PR #58): shared
  `DeploymentProfile`, `GateSeverity`, `DeploymentFinding`, `DeploymentWaiver`,
  `DeploymentFindingWaiver`, and `AuditAssurance` types plus the
  `registry.ops.posture.v1` finding and waiver shapes consumed by the Notary and
  Relay deployment-profile gates.
- Parser fuzz regression jobs (#51, PR #57): CI fuzz coverage for platform parsers.
- Emergency posture schema (#61, PR #62): adds the six `configuration.emergency`
  posture leaves to the default-tier allowlist and break-glass approval metadata
  shapes; contract tests pin schema validation, default-tier filtering, the
  change-class grammar, and the no-reason / no-approver-identity rule.
- STS bridge in `registry-platform` (PR #64): security-token-service bridge that
  backs Assisted Access token exchange.

## v0.2.1 — 2026-06-12

### Fixed

- (Issue #50) `authcommon::parse_bearer_token` now byte-compares the `Bearer `
  scheme prefix before calling `split_at(6)`, preventing a panic when a
  multibyte UTF-8 character straddles the scheme boundary.

## v0.2.0

### Security

- (F-P3-1) `crypto::sign` now wraps the decoded Ed25519 seed in
  `Zeroizing<[u8; 32]>` so key material is zeroed on drop.
- (F-P2-1) `AuditHashSecret` `Debug` impl confirmed to emit `<redacted>`,
  never the raw bytes; regression test added.
- (F-P2-2) `SdJwtIssuer` `Debug` impl confirmed to redact the private
  scalar; regression test added.
- (F-P6-1) `OidcDiscoveryConfig::jwks_uri_override` now carries a doc
  comment warning that setting it bypasses issuer-to-key-endpoint binding.

### Changed

- (Issue #10) Added provider-backed EdDSA signing via
  `SigningProvider`/`LocalJwkSigner`; SD-JWT issuance is now async and uses the
  provider `kid` as the JWT header source of truth.
- Added `registry-platform-ops` with the public
  `registry.ops.posture.v1` JSON Schema, Relay and Notary examples, shared
  finding/artifact/audit summary shapes, and sensitivity-tier redaction
  fixtures. Runtime services currently emit default posture; restricted posture
  is a contract tier for future/admin-gated surfaces, not runtime-emitted yet.
- (F-oid4vci-1) Remove `pub const PKCE_METHOD_S256`. Callers use the
  literal `"S256"`; the constant added no value and implied ownership of
  the PKCE method name.

### Fixed

- (F-P10-1) `getrandom = "0.4"` hoisted from `sdjwt/Cargo.toml` into
  `[workspace.dependencies]`; all consumers now share one pin.
- (F-testing-1) Sibling path-dep versions aligned to `"0.1.2"` across
  `testing`, `sdjwt`, `oid4vci`, and `oidc` `Cargo.toml` files
  (previously pinned at stale `"0.1.0"`).
- (F-crypto-2) `jsonwebtoken` removed from `crypto/Cargo.toml`; it was
  never referenced in source.

### Tests

- (F-P4-1) Integration test proves `RequestBodyLimitLayer` rejects a
  body 1 byte over 1 MiB with 413, and `body_limit_problem_response`
  returns the full RFC 7807 shape.
- (F-httpsec-2) Integration test asserts non-allowlisted Origin does not
  receive `Access-Control-Allow-Origin`.
- (F-httpsec-3) Unit test for `Problem` JSON serialisation shape
  (`type`/`title`/`status`/`detail`); cross-crate integration test
  extended with same assertions.
- (F-crypto-3) Unit tests for all three `DidError` variants: missing
  prefix, method not allowed, unsupported method.
- (F-sdjwt-2) `validate_holder_proof` rejects structurally malformed
  compact JWTs (no dots, two segments, four segments, invalid
  base64url characters).
- (F-oid4vci-2) Test confirms `validate_proof_jwt` does not track nonce
  reuse across calls (caller responsibility documented).
- (F-oid4vci-3) Serialisation round-trip tests for
  `CredentialConfigurationMetadata` (SD-JWT VC) and `CredentialOffer`
  (authorization_code flow).
- (F-P8-1) `#[ignore]` micro-benchmarks added for EdDSA sign and verify;
  doc comments cite measured µs/op on M5 Max (release mode).
- Focused posture contract tests validate the Relay and Notary examples, reject
  malformed posture documents including missing `posture.audit` and invalid
  artifact SHA-256 references, and prove the default redaction fixture omits
  secrets, subject ids, raw rows, claim values, SD-JWT disclosures, token hashes,
  private key material, private source URLs, and restricted topology while the
  restricted fixture may include restricted-only contract fields.

### Docs

- (F-oid4vci-4) `crates/registry-platform-oid4vci/README.md` created.
- (F-testing-2) `crates/registry-platform-testing/README.md` rewritten
  to document all public items.
- Added pre-release review report at `docs/release-review-0.1.2.md`.
- `docs/SECURITY_PRINCIPLES.md` §9 clarified: platform crates surface
  outcomes as `Result` types; consumer applications own audit wiring.
- `README.md`: toolchain pins and `cargo-deny` install hint added.

## v0.1.2

- Hardened OIDC verifier policy against mixed symmetric/asymmetric algorithm
  allowlists, JWK/header algorithm mismatches, and multi-audience ID-token
  `azp` gaps.
- Tightened OID4VCI proof validation, SD-JWT holder-proof headers, and JWK
  thumbprint construction.
- Added OpenID4VCI metadata primitives consumed by Registry Notary.

## v0.1.1

- Hardened shared security primitives for registry consumers, including
  outbound fetch validation, auth helpers, audit handling, and credential key
  utilities.

## v0.1.0

- Initial registry-platform workspace with eight crates: audit, authcommon,
  crypto, httpsec, httputil, oidc, sdjwt, and testing.
- Adds fail-closed Bearer/API-key parsing, outbound SSRF policy, bounded body
  reads, OIDC discovery/JWKS/token verification, tamper-evident audit chaining,
  RFC 7807 Problem Details, HTTP security middleware, Ed25519 JWK helpers,
  SD-JWT issuance/holder-proof validation, and shared test fixtures.
- Supports EdDSA/Ed25519 for platform-owned signing and verification in
  v0.1.0. Other JWK algorithms are rejected as unsupported until a consumer
  requires them.
- Ships canonical `clippy.toml`, `rustfmt.toml`, `deny.toml`, hygiene checks,
  versioning docs, and security principles for consumer alignment.
