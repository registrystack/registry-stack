# Registry Adapter changelog

## Unreleased

- Start a local development run from the starter with `rstack dev start`.

- BREAKING: an Adapter job sends each Coordinator event with Standard
  Webhooks. The POST carries `accept`, `content-type`, `webhook-id`,
  `webhook-timestamp` and `webhook-signature`. The signature covers the
  envelope id, the send time in Unix seconds and the exact body bytes. A retry
  keeps the envelope id as `webhook-id` and signs with the time of that send.
  The Version 1 headers are no longer sent.
- BREAKING: in the job runtime file, `destinations.<binding>.signingKeyRef` is
  now `hmacSha256KeyRef`. A job that declares a revised receiver also sets
  `destinations.<binding>.revisedReceiver.hmacSha256KeyRef`, and a job that
  declares none omits `revisedReceiver`. Startup refuses `signingKeyRef` with
  the replacement, a missing or extra `revisedReceiver`, and a key that is
  unavailable, shorter than 32 bytes, longer than 64 bytes or starts with
  `whsec_`. It also refuses the same key bytes in two triggers, including
  previous keys. Each refusal names the path and never a key byte.
- To rotate a trigger key, set `previousHmacSha256KeyRef` beside its
  `hmacSha256KeyRef`. The job sends two `v1,<base64>` entries, current first.
  Remove the previous reference after Coordinator holds the new key.

- A job pass records the declared posture when it takes the store lease.
  A pass, preview, rescan or identity rebind refuses with
  `adapter.job.posture-mismatch` when the store records a different posture.
  Use the recorded posture or use a fresh store when you change posture.
- BREAKING: an undeclared posture is production.
  Migration: Set REGISTRY_STACK_POSTURE=development for laptop and test runs; rstack dev sets it for you.
- BREAKING: `check` without a declared posture reports development settings as errors.
  Migration: Pass --posture development, or set REGISTRY_STACK_POSTURE, when checking a laptop file.
- BREAKING: the payment simulator collection provider is development only.
  Migration: Collections run under development until a live collection provider is accepted.
- Use `tlsTermination: loopback-plaintext` for new loopback listener configurations.
  Both `development-loopback` and `loopback-plaintext` relax the hook-listener port rule in either posture for loopback placement.
- BREAKING: issuer `allowInsecureHttp: true` is development only.
  Migration: Delete allowInsecureHttp where the issuer is on loopback: no setting is needed in any posture.
- BREAKING: production refuses `oidc.jwksSource.type: test-issuer`.
  Migration: Configure a production issuer or declare development for test runs.
- Development deployments can reach a database container using `transport: private-network-plaintext`.
- A payment reservation whose integrity check fails leaves the idempotency key available.
- BREAKING: the pool refusal gains the code `platform.database.test-only-plaintext`.
  Migration: Update scripts that match the old codes.
- BREAKING: `/ready` gains `posture` and `developmentSettings`.
  Migration: No change for probes that read the status code.
- BREAKING: development responses carry `Registry-Posture: development` and production refuses marked payment peer responses.
  Migration: Point production runtimes at production peers.
- The facade and job store accept loopback PostgreSQL plaintext in either posture.
  PostgreSQL job sources accept `tls.type: loopback-plaintext` for loopback hosts.
- Adapter startup records each explicit `anonymousHttps: operator-approved` acknowledgement.

- `adapterctl verify` and `adapterctl job check` accept `--posture` and read
  `REGISTRY_STACK_POSTURE`. Their JSON reports include the declared posture and its source.
- `adapter-job check` reports `posture`, `developmentSettings` and
  `explicitProductionSettings`. The `posture` object includes its value and source.
- `adapter-job status` reports `adapter.job.posture-mismatch` in `findings` when the
  store records a different posture.
- `adapter-job init-store` upgrades the job store to schema 105. Earlier binaries
  refuse the upgraded store.
- The facade journal upgrades to schema 600. Each new journal row carries the
  declared posture.
- New payment access and disbursement audit rows carry the declared posture.
- A PostgreSQL job source using loopback plaintext with `localhost` requires
  every resolved address to be loopback.
- `adapterctl check` lists `anonymousHttps: operator-approved` in
  `explicitProductionSettings`. The acknowledgement passes `--deny-warnings`.

- BREAKING: the upgraded journal (schema 600) refuses journal writes from
  earlier Adapter releases.
  Migration: Stop every earlier Adapter process before upgrading the same
  database. Restore a backup before rolling back past this release.

- A secret file the Adapter or an Adapter job refuses names the failed
  check and its fix. A link below the secret root now loads, so the hint
  that a link reads as a missing file is gone.

- `adapterctl provision --runtime-config FILE` creates the migration and
  runtime roles and the database from the runtime file's two database URLs, as
  a non-superuser administrator over verified TLS, or prints the script with
  `--print-sql`. Running it again creates only what is missing and refuses a
  role whose password differs from its URL. The runtime role gets only
  `CONNECT`, and `adapter serve` grants its table privileges at startup as
  before.
- A scope refusal on the facade and the payment routes now writes the scope
  claim name, the scope the operation requires and the access profile or
  payment connection it applies to on its `request refused` line. The values
  come from the deployment's configuration and never from the caller's token.
  No answer changes.
- A static key set that the facade refuses at startup states the rule it
  broke, so the operator can correct the document without reading the source.
- BREAKING: an Adapter job whose runtime document names a plain `http://`
  endpoint by host name must now list the address range that host resolves to
  in `allowedPrivateCidrs`. An omitted or empty list admits no private
  address, where before it admitted every one for such a host. To migrate, add
  the smallest range that contains the endpoint, serve the endpoint over
  https, or bind it on loopback. An affected job now fails `check` with
  `adapter.runtime.insecure-origin`. The job host's hook ingress also counts
  and logs every refused credential and rate limit under
  `adapter_job_request_refusals_total{check}`, with no answer change, and the
  fixture destination and the plaintext test RabbitMQ and PostgreSQL sources
  use the Adapter's one loopback definition (the RabbitMQ and PostgreSQL test
  sources still take address literals only).
- The payment routes count and log every refused caller under the check that
  refused it, in the same `adapter_request_refusals_total{check}` counter and
  `request refused` line as the facade. No answer changes. The simulator
  provider connection and a payment provider base URL accept the same
  loopback address literals as the rest of the Adapter (the rest of
  `127.0.0.0/8`, `::1` and the IPv4-mapped forms) and still refuse the name
  `localhost`.
- The facade counts and logs every refused caller under the check that
  refused it. `adapter_request_refusals_total{check}` rises by one and the log
  carries one `request refused` line with the fixed `failed_check` label, at
  most five lines per check per minute, replacing the per-stage
  authentication log line. No answer changes. Loopback is one definition
  everywhere the Adapter decides it: the rest of `127.0.0.0/8`, `::1` and the
  IPv4-mapped forms count beside `127.0.0.1`, the name `localhost` is pinned to
  loopback addresses, and `a.localhost` and `localhost.` stay named hosts. A
  plain `http://` origin named by host name now fails the runtime check with
  `adapter.runtime.insecure-origin` when `allowedPrivateCidrs` is empty.
- BREAKING: the facade listener answers `GET /health` and `GET /ready` without
  authentication. `/health` answers `{"status":"ok"}`. `/ready` answers
  `{"status":"ready"}` when the journal migrations match the binary and the
  runtime role holds its journal privileges, and a constant 503
  `{"status":"not-ready"}` otherwise. The bodies never vary with the
  project. A project operation whose facade path is `/health` or `/ready` is
  unserved under `adapter.operation.reserved-facade-path`. To migrate, rename
  the record type or change the operation path so no binding's concrete path
  is `/health`, `/ready` or the effective-contract path. `adapterctl check`
  refuses such a binding with `adapter.project.reserved-facade-path` and
  `adapterctl compile` refuses it with `adapterctl.compile.reserved-path`.
- `adapter serve` grants the runtime database role the table privileges its
  deployment needs, after it migrates and before it listens, when the runtime
  and migration sessions run as different roles. The grantee is the role the
  runtime session reports as its `current_user`, read before any grant, never
  the name in a URL. A runtime connection that fails stops startup before any
  grant. The grants are the ones the startup check already required, plus
  `USAGE` on the schema. Only privileges the role lacks are granted, in one
  transaction under an advisory lock, and nothing more: no default privileges,
  no revoke. A successful grant logs one line naming the role and the number
  of privileges. No grant is made to a role that lacks a privilege and has
  members that would inherit it. A member that holds `ADMIN OPTION` on the
  role and has no members of its own does not count. A grant the migration
  role has no right to make (it does not own the object) stops startup with
  the missing privilege named and rolls everything back. With one role in both
  sessions, no grant is issued. The payment tables under
  `--payments-config` follow the same rules: the collection tables always, the
  G2P tables when `payments.yaml` declares disbursement connections, with
  `USAGE` on their events sequences, in the facade's grant transaction or, when
  serving payments without a project, in a grant step of their own that also
  grants `USAGE` on the schema. The runtime role must exist,
  and the migration role must own the tables.
- `adapter serve --payments-config` hosts typed synthetic payment collection
  operations on the shared listener and PostgreSQL store, including without
  a record project. Connections bind institution/service scope, admitted
  callers, provider tenant/biller and separate BReg reporting credentials.
  Retained attempts preserve their original binding and exact commands across
  response loss and restart. Only a confirmed, correlated receipt can mark
  the authoritative bill paid. One attempt is permitted per bill version,
  including after definitive failure. Collections are simulation-only: a
  collection binding other than the simulator with `simulation: true` is
  refused with `adapter.payment.collection-simulation-only`. Live collection
  providers, replacement attempts, refunds and settlement are outside this
  slice.
- The same host serves typed G2P disbursements: request a disbursement from an
  approved BReg instruction, read its correlated provider observation, and
  report verified provider confirmation through a restricted BReg Action. An
  uncertain submission is never sent again. Disbursement connections pin a
  provider pack, passed to `adapter serve` with a repeatable
  `--payment-provider-pack`, and authenticate with `bearer` or, for Mifos
  Payment Hub EE, `mifos-legacy-signature`, which signs the exact Bulk request
  through a pinned Transit key and reads Operations status under a separate
  bearer credential. Full Linux CI exercises the signature with OpenBao and
  a synthetic provider. Verify your deployed provider pack and Mifos route
  in a sandbox before moving money. Verify beneficiary credit and settlement
  separately.
- `adapterctl payments check` validates connections offline and
  `adapterctl payments contract` exports their typed HTTP contract. Generated
  schemas, a native Coordinator workflow, the restricted BReg fee fixture,
  and a joined native acceptance runner accompany the payment host.

## 0.47.0 - 2026-11-21

- Accept an optional `project.label` and `project.description` in the project
  block, as the shared project block does. They are display text for
  people and change no compiled output.

- BREAKING: `database.trustedRootCertificateRef` -> `database.caBundleRef` in
  the runtime configuration, and `store.trustedRootCertificateRef` ->
  `store.caBundleRef` in the job runtime configuration, as a pre-1.0 cleanup,
  to match the `caBundleRef` the other TLS blocks use. The old key is refused
  as an unknown key. The value is unchanged: a secret reference to the PEM CA
  bundle the connection trusts.

- Serve Prometheus metrics from the facade and from `adapter-job pass --loop`
  on an optional `metricsListener.bind` in the runtime document, off by default
  and loopback or private only. An address equal to the serving or hook
  listener is refused when the document is read. The facade reports requests by
  route template and status class, upstream failures by class (including
  status polls and recovery checks), journal write failures and retention sweep
  failures. The job reports items by state, including `held` and `refused`, the
  age of its last settled pass, pass failures, hook refusals and failed item
  samples. Item counts are read one scrape at a time, reused for 5 seconds and
  bounded by one 5 second scrape deadline. A metrics listener closes within 10
  seconds of a stop signal, even with a stalled client. Held items stay
  read-only: the owning product resolves them.
- The facade and job metrics listeners accept
  `metricsListener.networkExposure`. Set `metricsListener.networkExposure:
  container-private` to also allow the unspecified address (for example
  `0.0.0.0`), for a container whose network is private to the deployment. The
  default, `private-address`, keeps the loopback-or-private rule.
- The job's item counts take their statement timeout from one 5 second scrape
  deadline. Failed reads are logged by error class.

- PostgreSQL jobs can project bounded JSONB values, including the geometry
  and related rows in the [QField PostGIS example](examples/qfield-postgis/README.md).
  Item keys and query parameters keep their existing scalar contract.
- BREAKING: an ingestion job counts an item as possibly admitted when its
  BReg or Coordinator answer was lost and the retry was then refused,
  because that refusal says nothing about the first attempt. A later source
  edit or `rescan` of the item goes to the job's revised trigger, or is held
  as `adapter.job.revised-item` on a direct BReg job or a Coordinator job
  without one. An item whose first attempt never arrived is held the same
  way: correcting its source record does not deliver it, and no Adapter
  command releases a held item. A Coordinator item with no revised trigger
  to select is held instead of stopping the pass as
  `adapter.job.coordinator-receiver-changed`, and restoring the trigger does
  not resend it. A `rescan` of a refused item sends it to the receiver
  selected at that time, so adding a revised trigger after a refusal does
  not stop the pass. A refused item whose revised event may have been
  admitted is the exception: a `rescan` sends that event only to the same
  revised receiver with the same body, and a changed revised trigger,
  binding, `job.version` or projection stops the pass as
  `adapter.job.coordinator-receiver-changed` or
  `adapter.job.coordinator-body-changed` before any request. Store schema
  104 treats every refused revised event with a frozen receiver this way.
  It also marks a refused first registration with a recorded retry as
  possibly admitted. Before running `init-store` and resuming ingestion,
  check BReg or Coordinator for admissions of legacy refused items whose
  earlier attempts the store did not record.
- BREAKING: an asynchronous write is polled only at the source origin it was
  sent to. Before the send, its store row pins the configured `baseUrl` of
  every endpoint its write, status and uncertainty routes reach. A status GET,
  a bounded wait and a same-key retry poll only while the runtime
  configuration still gives those endpoints the same `baseUrl`; rotating a
  credential changes nothing. After a `baseUrl` change, an unfinished write is
  held and never polled: its status link answers the stored 202 and a retry
  answers 409 without `Retry-After`, until the original `baseUrl` is restored
  or the write expires. Each held poll logs a value-free warning. Let async
  writes settle before upgrading; rows written by an earlier version are
  quarantined and expire.
- BREAKING: an `oauth2-private-key-jwt` runtime credential and an adapter job's
  `direct-breg` destination require `clientAssertionAudience`, with no
  default. The client assertion carries it as its only audience and has the
  header `typ: client-authentication+jwt` (RFC 10070 section 4). A configuration
  without it fails to load with a refusal that names the member. Migration:
  set the audience member to the authorization server's issuer identifier,
  exactly as its metadata publishes it. The direct BReg receiver identity
  includes `clientAssertionAudience`, so a direct BReg item left pending by a
  previous binary whose stored receiver identity did not include it stops the
  pass as `adapter.job.breg-receiver-changed`
  before any BReg call, with the job position unchanged, and no configuration
  under this version releases it: run passes with the previous binary until
  `adapter-job status` lists no pending items, and take a database backup,
  before upgrading. After `init-store` the store is at schema 104, which the
  previous binary refuses: restore that backup, settle the items with the
  previous binary, then upgrade and run `init-store` again.

- An Adapter job can receive a governed offline QField submission. The
  [QField PostGIS example](examples/qfield-postgis/README.md) reads a completed
  submission (a site point, its boundary polygon and repeated contact rows) from
  the collection database that QFieldSync returns to, and starts a BReg Action
  or Proposal from it. A reconciliation step authorizes the result written back
  to the source.
- A projection pack whose `fieldsSchema` constrains which fields are present is
  refused when the projection compiles. Remove `required`,
  `minProperties`, `maxProperties`, `dependentRequired`, `dependentSchemas` and
  top-level composition keywords from the schema and describe each field only;
  each view already requests its own fields and every requested field must be
  returned.
- A reviewed projection operation serves BReg's read-only external views. See
  the BReg changelog and the
  [external projections pack](examples/external-projections/README.md).

## 0.46.0 - 2026-11-08

- A host protocol's verified response can carry one opaque attachment
  (`VerifiedHostProtocolResponse::with_attachment`) that the engine hands to
  the embedding Evidence host without reading it; the engine stays free of
  Evidence semantics. A second attachment in one Evidence acquisition fails
  the lookup as a protocol refusal, and an attachment the host does not read
  has no effect. Every acquisition now fixes one evaluation instant (the
  host-supplied one, or the wall clock read once at the start), and a host
  protocol verifier receives it from `HostProtocolWireResponse::evaluation_instant`
  so it never reads the wall clock itself. `registry-adapter-engine` depends
  on `chrono` in every build.
- BREAKING: pack scripts run on a deterministic engine, so the call deadline
  holds for every call a script can make. `timestamp`, `elapsed`, `sleep`,
  `exit`, `take`, `tag`, `set_tag`, `parse_json` and `get_fn_metadata_list`
  are no longer available, and string `pad` with an empty padding string,
  which never returned, now fails. A script that uses the `curry` keyword no
  longer compiles. A script that makes such a call fails the
  call as any failing script does; `adapterctl check` does not flag it.
  Evidence Sources run their packs on the same engine. Remove those calls.

- A mapping's preview samples can record the result each should give in
  `preview/expected.yaml` beside them, an `AdapterPreviewExpectations`
  document (`type: accepted`, or `type: refused` with an optional `target`
  the refusal must name). `adapterctl mapping preview` reads the file in the
  directory of its `--input` files and adds `expected` and `matched` to each
  judged result and `mismatched` to the report. A result that differs from
  its expectation raises `adapterctl.mapping-preview-mismatch` and exits 1; a
  sample the file does not list has no expectation. A name with no sample
  file, or a refusal target no assignment reads from the source, is refused
  (`adapter.mapping.expectation-sample-unknown`,
  `adapter.mapping.expectation-target-unknown`). `expected.yaml` is never a
  sample. `mapping preview` also takes `--deny-warnings`. The new format has a
  generated schema, `preview-expectations.v1alpha1.schema.json`, and the
  KoboToolbox example ships its `preview/expected.yaml`.
- `adapterctl mapping check` reports the `title` of the target schema's root
  as `targetTitle`, beside `targetTree`, so a tool can name what the mapping
  fills. It is display only, absent when the root has no title or the schema
  cannot be read, and present on a refusal.
- A quoted mapping selector key or filter literal takes any Unicode
  character except a control character, a text-direction control or a line
  or paragraph separator (joiners stay allowed), so a source key such as `prénom` can be mapped. `\"`
  and `\\` are its only escapes, keys compare byte for byte with no
  normalisation, and the 128-character bound stays. Every selector valid
  before parses to the same segments; unquoted names are unchanged. The
  `targetTree` of `adapterctl mapping check` now marks a target key with a
  non-ASCII character, a quote or a backslash as mappable, and findings name
  such a target with the quote and backslash escaped.
- `adapterctl job check` warns with `adapter.job.mapping-unprojected` when a
  generated `direct-breg` destination mapping reads a source key that the
  job's `projection.fields` does not list, once per assignment, at the
  assignment's `from` in the model and with the assignment's `target`. Such a
  mapping previews cleanly over a sample but refuses every live item, or
  always omits the field under `whenMissing: omit`. `--deny-warnings` makes it
  a refusal; a missing, invalid or drifted model adds nothing beyond the
  existing drift warning.
- `adapterctl mapping check`, `generate` and `preview` refuse a
  `mapping.targetSchema` that resolves, through a symbolic link, outside the
  model's directory, with `adapterctl.mapping-schema-outside` at
  `/mapping/targetSchema`, and write nothing. A link that stays inside the
  directory is still followed.
- `adapterctl job lock job.yaml` and `adapterctl mapping generate` on a model
  named without a directory write in the current directory instead of
  failing with `adapterctl.io-failure`.
- `adapterctl mapping check` compares an integer constant with the target's
  `enum` and `const` members exactly, as the runtime does: a constant above
  2^53 no longer matches a member it only rounds to, and `1` still matches
  `1.0`. A model that passed the check with such a constant and then failed
  every record at runtime is now refused by `check`, `generate` and
  `preview`.
- `adapterctl job lock` rewrites a pin under a section header that carries a
  comment, such as `mapping: # note` or `source: # note`, instead of refusing
  with `adapterctl.job-lock-layout`. The comment is kept.
- `adapterctl fixtures replay` accepts built-in GovStack projects that serve
  Write. It detects the built-in target, composes the profile and assembles
  the contract exactly as `check` and `compile` do, so a read+write project
  no longer fails with `adapter.project.unknown-operation` on its Create and
  Update bindings, a Write-only project no longer asks for a `profile.yaml`,
  and a Create or Update fixture entry is held against its compiled
  operation.
- Continuation cursors (GovStack List and Search, and every other paginated
  facade operation) are bound to the verified client the caller acts
  through (`azp` or `client_id`) as well as the issuer and subject, so a
  cursor issued to one client is refused with `invalid-cursor` when the
  same subject presents it through another. A refreshed token for the same
  subject and client still continues. The cursor length and the published
  cursor `maxLength` are unchanged. Cursors issued before the upgrade are
  refused after it; a caller restarts the traversal from its first page.
  Committed fixtures that pin sealed cursor bytes carry the new values.
- GovStack Update: the ETag validator closure also binds the companion
  read's route (its steps, the direct routes they call and the pinned
  digests of their scripts) and the pack's code maps, so changing a mapping
  the read applies invalidates outstanding ETags. Client, OIDC and deployment
  identity stay outside it. The closure domain is now `v3`; ETags issued
  before the upgrade return 412 and need a fresh companion read.
- GovStack generated OpenAPI declares the runtime bounds of its identifiers:
  `recordId` path parameters carry the same single-path-segment restriction
  the facade enforces and the effective contract already declared, and
  `Idempotency-Key` carries a pattern for the quoted Structured Field String
  the facade parses. Regenerate committed `generated/openapi.json` files with
  `adapterctl compile`.
- GovStack Lookup with a selector the Collection does not declare points its
  422 `invalid-content` at `/selector` instead of `/values`; Search with an
  undeclared search points at `/search` instead of `/criteria`.
- GovStack Update: a retry under the same Idempotency-Key and fingerprint
  replays its stored answer even when its If-Match can no longer be opened,
  after a redeploy changed the guard's closure or its sealing key was rotated
  out, instead of returning 412. A retry while the first attempt still runs
  gets 409 `idempotency-in-flight` with `Retry-After`, as it would under a
  guard that opens. Authentication and authorization still run first.
- GovStack Update no longer returns 406 for an `Accept` that admits neither
  JSON form; its success has no body and its Problems are always
  `application/problem+json`. Create and reads keep the 406.
- GovStack Update refuses a merge-patch member whose value is an object with
  422 `invalid-content` and one `errors` pointer per such member, even when
  the project input schema admits it.
- `adapterctl mapping check` reports the target schema as `targetTree`: each
  property's path, key, type, required flag, `mappable` flag (a scalar leaf
  whose path the target-path grammar can express; never an object), format,
  const, enum, children and, for a mappable leaf, the `convert` values the
  checker accepts. It is also present on a refusal, including one raised by
  `--deny-warnings`, whenever the schema root is supported.
- `adapterctl mapping check` findings about one target field carry a `target`
  member naming it in the format's target syntax; message text is unchanged.
- The `adapter.mapping.script-drift` warning from `adapterctl mapping check`
  carries `cause`: `model-changed` (the header's model digest is stale) or
  `script-differs` (the digest matches, or the header itself was edited, yet
  the bytes differ; a hand edit or another adapterctl version's generator can
  cause it). Its message now names the cause. The text output of
  `mapping check` leaves `targetTree` to `--format json`.
- The GovStack Write path through the Adapter (direct Create and conditional
  Update) is experimental. `CONSULTATION.md` now lists what a source must
  offer to back it; BReg is the one maintained source that does.
- BREAKING: the GovStack Digital Registries facade no longer sends the
  `x-registry-idempotency-replay-window-seconds` response header. Capability
  discovery publishes the window as `write.idempotencyReplayWindow` (integer
  seconds, equal to the deployment's response retention) on every Create and
  Update entry, and the generated OpenAPI describes the member. A read-only
  deployment publishes no window.
- BREAKING: Lookup and Search answer an invalid field or value with the problem
  type `https://govstack.global/problems/digital-registries/invalid-content`
  instead of `.../invalid-field`, the type Write already used. The `errors`
  pointer list is unchanged; the internal class `facade.invalid-field` is
  unchanged.
- A built-in Lookup whose identifier cannot travel as a source path segment
  (for example `.`) answers 404 `record-not-available`, as Retrieve does,
  instead of 500.
- The Write receipt schema allows a `collectionId` of 128 characters, matching
  the published contract.
- BREAKING: the configured `govstack-consultation` profile, the
  `dhis2-govstack` example and its fixtures are removed. A deployment moves to
  the built-in GovStack Consultation profile by declaring a `consultation:`
  section in its project (see `examples/dhis2-consultation`). A configured
  profile that names itself `govstack-consultation` no longer gets any
  GovStack behaviour.
- BREAKING: the `dhis2-tracker` pack's `page-tracked-entities` and
  `page-tracked-entities-by-org-unit` routes take a required
  `tie_breaker_attribute` parameter, the UID of a unique program attribute.
  They page by `createdAt:desc,<attribute>:asc` because DHIS2 2.43 refuses
  `trackedEntity` as a sort key. Add the parameter to each templated route
  that uses them and re-lock the project.
- Remove the `range`, `set-membership` and `prefix` source comparisons, which
  no pack used. Only `equality` remains.
- A pack route's `writeSupport` is flat: `type` is `create-one` or
  `conditional-update-one`, with `replayWindowSeconds`. The single-value
  `identity`, `replay` and `precondition` members are removed.
- An Adapter project needs less configuration. A Consultation collection's
  `view` defaults to its `dataSchema`; its `transform` applies to every
  Retrieve, Lookup, List and Search binding of that record type unless
  `bindingTransforms` names one for the binding. `recordTypes` entries with no
  fields are derived from the collections. `maximumUpstreamCalls` defaults to
  4. A Write Update's `companionRead` is inferred when exactly one Retrieve or
  `writable-read` binding serves the record type, and is required when the
  choice is ambiguous. The explicit forms stay valid.
- A `writable-read` binding that no Write Update names as its companion read
  is refused by `adapterctl check` and at load, naming the binding, instead of
  stopping the Adapter.
- A credential kind mismatch names the bound kind and the endpoint's
  declared kind, for example ``the runtime credential's kind (`none`) does
  not match the endpoint's declared kind (`basic`)``, in `adapterctl check`,
  `adapterctl verify`, and the facade and job startup refusals.
- A job pass stops as the new `adapter.job.projection-flat-dotted-name`
  when a declared dotted projection field (`household.size`) misses as a
  path but the row carries a flat member of exactly that name, as a CSV
  column or SQL alias can. The projection handed off `null` for it. The
  stop comes before any item of the page is staged, and its next step says
  to group the columns into a nested object in the route.
- BREAKING: a local file job source must declare how it knows a file is
  complete, so a read never takes a file the producer is still writing.
  `adapterctl job check` and `adapter-job` startup refuse a source with no
  `doneFileName`, no `readLock: changed`, and no `producerAtomicHandover:
  true` (the SFTP `completed-name` promise, for a producer that renames each
  finished file into the directory). Migration: add one of the three to
  each `sources.file` entry; `readLock: changed` suits a producer you do not
  control.
- BREAKING: the maintained `kobotoolbox` pack authenticates with the
  account's API token (`static-authorization`, `scheme: Token`) instead of
  Basic, so a leaked adapter credential no longer signs in to the Kobo web
  UI. The pack digest changes. Migration: in the runtime, replace the
  `kobo-api` credential's `usernameRef` and `passwordRef` with `type:
  static-authorization` and a `tokenRef` naming the token, and repin the pack
  digest in `project.yaml` and the job file. A deployment that must keep
  Basic pins its own copy of the pack with `type: basic`.
- The maintained `dhis2-tracker` pack's two Evidence lookups send
  `orgUnitMode=SELECTED` with their organisation unit, so the lookup scope
  stays that one unit on a DHIS2 version whose default mode differs. The pack
  digest changes, and the DHIS2 Evidence reference bundle captures the new
  pack.
- BREAKING: the maintained Kobo Coordinator workflow gives the unresolved-lookup
  revision its own finish outcome, `unresolved-reviewed`; it finished as
  `revised-reviewed`, the same as a resolved one. Its README lists every
  outcome, notes that a review or Proposal timeout finishes the Run as
  `review-timeout` or `proposal-timeout` rather than raising attention, and a
  new `scenarios.yaml` covers the revised branches and the timeout. A client
  that matches the outcome of an unresolved revision must now match
  `unresolved-reviewed`.
- An Adapter job profile may omit `read` when its source route reads no file
  and no PostgreSQL row (an HTTP-only route). A route that reaches a
  `pollEnrich` step or a `postgres:` send or enrich still needs the bounds,
  and `adapterctl job check` refuses their absence with the new
  `adapter.job.profile-read-required`. Existing jobs are unaffected.
- BREAKING: job item and check codes are renamed in one pass, with no alias.
  A refusal a destination answered is now stored as
  `adapter.job.breg.<word>` or `adapter.job.coordinator.<word>` (the
  destination's own word is the last segment), so `holdsByCode` and
  `adapter-job status` counts no longer mix the two destinations. A stored
  item row written by an earlier release keeps its old spelling; a script
  that matches a code must match both spellings until those rows are
  settled. Folded authoring codes are split so each names its own fault:
  `adapter.job.trigger-hook-unserved` is retired for
  `adapter.job.trigger-hook-binding` (a hook trigger with no binding, or a
  repeated one), `adapter.job.trigger-hook-path` (a missing, malformed or
  repeated path) and `adapter.job.trigger-member` (a member the trigger kind
  does not accept, such as `path` on an interval trigger); the Postgres send
  member faults move to `adapter.job.postgres-send-members` and the missing
  JSONL key pointer to `adapter.job.poll-key-pointer`. The `adapter-job`
  host codes `adapter.job.hook-configuration` and
  `adapter.job.hook-not-compiled` are split by cause:
  `adapter.job.hook-configuration-trigger`, `-ingress-missing`,
  `-ingress-unused`, `-binding` and `-path`, and
  `adapter.job.hook-not-compiled-trigger` and `-ingress`. Each authoring
  code has a bad-corpus member.
- BREAKING: `asyncCompletion.mode` is renamed `asyncCompletion.type` in an
  Adapter project binding. There is no alias and the project `apiVersion` is
  unchanged, so a project that still writes `mode` is refused at that key
  with `config.removed-key`, which names `type` as the replacement. Rename
  the member and keep its value (`status-link` or `bounded-wait`).
- `adapter serve` takes its access-token algorithm roster from
  `registry-platform-oidc`. The facade still accepts exactly RS256 and ES256,
  now pinned by a test. It already installed SIGTERM and SIGINT before serving
  and refused startup when one could not be installed; it now does so through
  `registry_platform_httpsec::shutdown_signal`, with the same startup error
  text and no change in behavior.
- Continuation cursors are sealed and opened through the shared XChaCha20-Poly1305
  primitive in `registry-platform-crypto`. The wire format is unchanged (golden
  tokens pin it), including under the previous key after a rotation; cursors
  issued before the upgrade are still refused because of the client binding
  described above.
- A pending direct BReg delivery is now fenced before it is retried: the job
  freezes the BReg binding, base URL, token endpoint, caller, TLS trust
  profile, access profile, Action and mode, and the mapped operation, and a retry that differs stops the pass before any
  BReg call as `adapter.job.breg-receiver-changed` or
  `adapter.job.breg-body-changed`. A direct BReg item left pending by
  v0.45.0 has no recorded identity, so its first retry under this release
  adopts the current destination and mapping: settle pending direct BReg
  items with v0.45.0, or keep the destination and mapping unchanged, before
  upgrading. A row staged before store schema 103 stops as
  `adapter.job.breg-identity-unrecorded`.
- Registry Stack releases publish the `adapter` and `adapterctl` binaries for
  Linux amd64, Linux arm64, and macOS arm64, with an `adapter-<tag>-install.sh`
  installer and an `adapter` component for `rstack install`. `rstack adapter`
  runs `adapterctl`. There is no Adapter container image. `adapter-job` is not
  released yet; build it from source.
- `adapter` gains `--version`, and `adapter-job --version` reports the
  Registry Stack display version instead of its crate version, as the other
  release binaries do.
