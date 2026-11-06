# Registry Adapter changelog

## Unreleased

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
- BREAKING: `asyncCompletion.mode` is renamed `asyncCompletion.type` in an
  Adapter project binding. There is no alias and the project `apiVersion` is
  unchanged, so a project that still writes `mode` is refused at that key
  with `config.removed-key`, which names `type` as the replacement. Rename
  the member and keep its value (`status-link` or `bounded-wait`).
