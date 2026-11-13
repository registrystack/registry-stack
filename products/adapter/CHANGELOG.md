# Registry Adapter changelog

## Unreleased

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
  104 treats every refused revised event already in the store this way; run
  `init-store` once. Items refused this way by an earlier version carry no
  mark: before you edit or rescan one, check BReg or Coordinator for an
  admission of that item.
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
  includes `clientAssertionAudience`, so a direct BReg item still pending
  from an earlier version stops the pass as `adapter.job.breg-receiver-changed`
  before any BReg call, with the job position unchanged, and no configuration
  under this version releases it: run passes with the previous binary until
  `adapter-job status` lists no pending items before upgrading, or return to
  the previous binary to settle them.

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
