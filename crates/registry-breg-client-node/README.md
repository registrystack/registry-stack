# registry-breg-client-node

Internal napi-rs binding for the Base Registry Engine (BReg) Rust client. It is built
into the public `@registrystack/client` package and is not published as a
standalone npm package.

```js
const { breg: { BaseRegistryClient } } = require('@registrystack/client');
const client = new BaseRegistryClient({ baseUrl: 'https://registry.example.invalid/' });
const health = await client.health();
```

Writes never accept caller-supplied operation routes as authority. Fetch a
caller-filtered registry contract, select the expected operation and profile,
then pass the returned opaque binding to `createRecord` or `patchRecord`.
Actions use `selectAction`; Proposal transitions use links promoted from an
authorized `BRegProposal`, separately from Registry Record writes.

Every call accepts only a bounded, acyclic graph of plain JSON inputs. Proxies,
accessors, symbols, exotic objects, sparse arrays, non-finite numbers, more
than 128 levels or 100,000 nodes, and more than 4 MiB of string data are
rejected before native conversion.

Authentication is optional. Configure a static bearer token, private-key-JWT,
or the context-bound `exchange` provider declared in `client.d.ts`. For a
person, pass attributes derived from a fresh host verification, never browser
claims, and give each verified generation its own client. For an institutional
agent, pass the exact Casework assertion endpoint, a Casework-only bootstrap,
and the approved exchange resource and scopes. A remote grant refresh obtains
a fresh authority assertion and can be refused after revocation. The client performs one
exchange per method, never follows redirects, never uses ambient proxy
configuration, and never follows links automatically; the one resend is the
bounded same-key retry of a keyed mutation described under the actions below.

Failures are `BaseRegistryClientError` values with a stable `kind`, a boolean
`outcomeUnknown`, and, where available, `code`, `refusalCode`,
`fieldPath`, `status`, `traceId`, `transportKind`, and `tokenKind`. Errors do
not expose token, private-key, record, or Proposal payload values.

## Hook verification

`verifyHookDelivery({ method, path, headers, body, key })` authenticates one
exact Base Registry Engine Version 1 delivery with the shared Rust verifier.
Header lookup is case-insensitive. The result carries the CloudEvents
attributes, generation, attempt, delivery time, idempotency key, and exact body.
Generation and attempt remain decimal strings so the Node number boundary
cannot round a signed value.

Body and key buffers must not use a shared backing store. Accepted buffers are
copied before native verification so another worker cannot change the bytes
being authenticated.

The helper does not apply clock-skew or deduplication policy. Bound the returned
`deliveryTime` against the receiver clock. `idempotencyKey` collapses automatic
retries within one delivery generation; an effect that must remain once-only
across operator replay uses a durable apply-once operation keyed by authenticated
`source` plus `id`, or by an application business key, before acting on `body`.

Refusal throws `BaseRegistryClientError` with kind `hook-verification` and a
code from `missing-header`, `invalid-delivery-time`, `duplicate-header`, `body-too-large`, `invalid-key`, `malformed-signature`, `signature-mismatch`, or `unsupported-version`.
The message names the input to check and never includes a header value, body,
or key.

## Exact values and application metadata

Use the public server-side package `@registrystack/client` and its `breg`
namespace. `registryContract(profile).operations` exposes typed,
caller-filtered field, request, and query descriptors.
Labels are inert presentation text;
`schemaJson` preserves JSON Schema numbers. Descriptors grant no authority.
Continue to use `selectCreate`, `selectPatch`, and `selectAction` to obtain
opaque authorities bound to the client source and selected profile.

The same contract exposes lookup selectors, named read paths, code labels,
reference operations, storage validation, spatial-query limits, and Action
descriptors with their declared immediate or Proposal mode. These values are
descriptive. Mutation authority comes from the fetched contract's selectors,
including `selectAction`, `selectBatch`, and `selectTombstone`. Proposal Get
and List use `selectProposalGet` and `selectProposals` separately.

Methods ending in `Json` keep domain values on the Rust side of the JavaScript
number boundary. `getRecordJson`, `listRecordsJson`, `continueListJson`,
`lookupRecordJson`, `createRecordJson`, `patchRecordJson`, and
`invokeActionJson` return `valueJson` with the same trace, ETag,
location, and opaque continuation semantics as their object counterparts.
Proposal methods use JSON text for inputs and transition bodies and expose the
validated representation as `BRegProposal.documentJson`.

```js
const { breg } = require('@registrystack/client');
const client = new breg.BaseRegistryClient({ baseUrl, authorization: { static: token } });
const contract = await client.registryContract(profile);
const operation = contract.operations.find(value => value.kind === 'create');
const binding = contract.selectCreate(operation.id, profile);
const result = await client.createRecordJson(binding,
  '{"quantity":9007199254740992,"amount":"12.3400","date":"2026-09-08"}',
  'caller-chosen-idempotency-key');
// Keep result.valueJson intact, or inspect it with a lossless JSON library.
```

Inputs are the same domain data object or field-based patch array accepted by
the corresponding object method, encoded as JSON text. They are not arbitrary
HTTP request bodies. The client refuses duplicates, invalid JSON, bounds
violations, and numeric literals whose value would change during decoding.
Structured JavaScript inputs reject every integer-valued `Number` outside
`Number.isSafeInteger`, including nested Create, PATCH, action, and batch
values, because JavaScript may already have rounded the caller's value. Use the
corresponding `...Json` method with exact JSON text when a governed integer may
be wider than JavaScript's safe range.
Exact JSON mutation builders also enforce BReg's existing numeric model: for example,
`9007199254740992` is supported while `9007199254740993` is refused before
network I/O. Exponent or decimal spellings cannot bypass the exact-value check.
Fixed-scale decimals remain JSON strings. Null and absent members remain distinct.
Do not round unsupported input to make it pass. JSON whitespace and equivalent
number spellings may be canonicalized; the promise concerns values and types.

Client configuration uses `maximumResponseBytes`; the retired
`maxResponseBytes` spelling is refused. Optional configuration values are
omitted rather than set to `null`. `trustedRootCertificates` accepts PEM text,
and the supplied bundle keeps the Rust client's explicit trust-root semantics.
`attemptTimeoutMilliseconds` bounds one outbound attempt, including its body,
and `connectTimeoutMilliseconds` bounds connection setup.

Actions retain their original opaque authority and exact retry semantics.
A keyed mutation (create, patch, attachment upload or delete, Proposal
transition, immediate Action, batch, tombstone, statistics publish or withdraw)
whose outcome is unknown is resent identically under the same key up to
`maximumMutationRetries` additional times: 0 to 2, default 2, and 0 sends it
once, while the default permits up to three total attempts. The
outcome is unknown after a timeout or broken exchange once the request was
sent, an unusable answer, or a 5xx other than `action.handler_failed` and
`statistical_dataset.domain_violation`, which the engine returns only with the
attempt rolled back. When the returned error still reports `outcomeUnknown`,
the mutation may have taken effect, and the caller must explicitly choose
whether to retry the same action with the same idempotency key; a new key
could apply it twice. Reads, unkeyed calls, connection failures, and every 4xx
refusal are never resent. A `410 idempotency.expired` does not report
`outcomeUnknown` either, but there an earlier attempt under the key committed
and only its held response is gone: read the resource before choosing a new
key.

## Specialized reads

Ordinary list calls accept `bbox: [west, south, east, north]` as four exact
decimal strings when the served query contract supports it. GeoJSON has a
separate `getGeoJsonRecord` and `listGeoJsonRecords` surface, with typed
features, GeoJSON media checks, and its own continuation type.

`listCurrentRecords`, `listRecordsAsOf`, and `listSnapshotRecords` keep their
temporal parameters and continuations distinct. Snapshot continuations bind
the returned snapshot and optional `validAt` identity. Relationship lists
bind the root record and relationship path. `getRecordRevision` returns one
validated retained record as inert bytes, while `recordRevisions` returns the
bounded revision collection. Every specialized object read has an exact `...Json`
variant when record or GeoJSON values may cross JavaScript's integer boundary.

Standalone Proposals use `getProposal` or one explicit `listProposals` page.
An applied Proposal's result links record application provenance and grant no
record authority. Read targets through ordinary authorized record methods;
result revisions are not current ETags or write preconditions.

## Immediate and atomic mutations

For an immediate action, select its opaque binding, fetch target conditions
when the contract requires them, and pass those same opaque conditions to
`invokeAction`. Inputs are checked against the served field types before I/O.
Conditions keep strong entity tags opaque and bound to the selected action and
original target input. Invocation performs one request with the caller's
idempotency key.

When the selected immediate Action advertises `availabilityPath`, call
`actionAvailability(binding, targetInput, inputs)` for each selected reference.
It accepts a validated subset of the Action inputs and is a single unkeyed POST.
The answer can be available, guard-not-satisfied, input-required with missing
API input names, or not-disclosed. It is a current hint; `invokeAction` still
performs the authoritative guard check and may return `action.guard_failed`.
Proposal submit and apply return the same problem for a readable field-guard
failure; a stale Record revision stays `precondition.failed`.

`batchRecords` accepts an ordered array of create and patch items plus an
optional change or correction context. It enforces the served item and body
bounds, writable fields, per-patch ETags, bounded reason text, and source
references before sending one atomic request. `tombstoneRecord` requires the
selected Record type binding, record UUID, current strong ETag, and caller-chosen
idempotency key. Exact JSON variants preserve large integer values in inputs
and receipts.

For recovery across a process restart, call `prepareCreate` before the first
send and persist the returned capsule's `toBytes()` value in owner-protected
storage. Use
`BRegPreparedCreate.fromBytes` after restart, fetch caller-filtered metadata
again, and call `recoverCreate` with freshly selected authority. Recovery is a
pure revalidation step. The returned opaque operation remains inert until the
application calls `executeRecoveredCreate`. The saved
bytes contain the original request values and idempotency key, but no token or
metadata authority, and their diagnostic representation is redacted. The
`...Json` variants preserve values outside the JavaScript safe-integer range.

Immediate actions follow the same pattern. Call `prepareAction` with the same
binding, inputs, idempotency key, and target conditions you pass to
`invokeAction`, and persist its `toBytes()` value before invoking. After a lost
response, restore it with `BRegPreparedAction.fromBytes`, select the action
again from fresh metadata, and call `recoverAction` with the original inputs
and idempotency key. Recovery refuses a different key, different inputs, or
another selected action, reuses the saved target conditions exactly, and never
fetches new ones. `executeRecoveredAction` is the explicit send under the
original key. The saved bytes contain input values and must be treated as
private application state.

## Standalone Proposals

Select a Proposal-mode Action with `selectAction`, then call `startProposal`
with its input object encoded as JSON text and a caller-chosen idempotency key.
`prepareProposal` binds an available transition's promoted condition, exact
body, and key; `executeProposal` is the explicit send.

```js
const contract = await client.registryContract(profile);
const action = contract.selectAction('correct-address', profile);
const draft = await client.startProposal(action, inputsJson, 'correction-start-1');
const submit = client.prepareProposal(draft, 'submit', '{}', 'correction-submit-1');
// Persist submit.toBytes() in owner-protected storage before dispatch.
const submitted = await client.executeProposal(submit);
```

Transitions are `edit`, `submit`, `revise`, `rebase`, `retry`, `cancel`, and
`apply`, subject to current availability and caller authority. `prepareProposal`
also refuses locally any operation that is not a legal transition from the
Proposal's observed state: `cancel` is prepared only for a Draft or Submitted
Proposal, so cancelling an Applied or Cancelled Proposal throws before any
request is sent. A conformance test that needs the server's own terminal-state
refusal must call the HTTP route directly rather than the typed client. Apply's body
binds `submissionVersion` and `effectDigest`; optional `reason` text is limited
to 4096 Unicode characters with NUL refused. Proposal conditions are distinct
from record ETags. Use `readProposal` or `getProposal` for a current observation.
Read review status or context explicitly through `readProposalReviewStatus`
or `readProposalReviewContext` when their links are promoted. A Proposal
document carries a derived `turn` (`party`, `official` or `nobody`) and, once a
review has decided, a `decision` with its status, `decidedAt` and optional
`publicReason`. `readProposalSubmission(proposal, version)` reads one retained
submission version, its review, application receipt and decision, with the
Proposal Get authority; an expired version is the `proposal.submission_expired`
problem.
When that profile also holds `get-application-actor`, Proposal Get and the
submission read include `appliedBy` and `appliedAt` together in the application
member. Proposal List omits both.

After restart, restore `BRegPreparedProposal.fromBytes`, fetch the current
authorized Proposal, and call `recoverProposal` before `executeProposal`.
Recovery retains the original condition, body and key. A later status read
does not recover an uncertain command. To retain a Start attempt, use
`prepareActionJson` before `startProposal`, then `recoverActionJson` and
`executeRecoveredProposalStart` with fresh Action authority and the original
inputs and key. Protect saved bytes as private application state.

Transition recovery requires a freshly authorized Proposal observation, obtained
with Get or as an item from List, and a matching transition or receipt-only
recovery link. The Get flow needs a current `get` grant; an authorized List item
can also supply the observation. Losing all such read access, including access
to a current target row, prevents recovery by that caller. Preserve the original
attempt for an authorized operator; do not infer failure or send it under a new key.

## Proposal attachments

Governed binary slots are engine-owned and advertised on an authorized
Proposal. They are never set through record creation or JSON Patch. Use the
Proposal's promoted slot links through the dedicated methods.

```js
const contract = await client.registryContract(profile);
const binding = contract.selectProposalGet(profile);
let proposal = await client.getProposal(binding, proposalId);
proposal = await client.uploadProposalAttachment(proposal, 'supporting-document',
  'application/pdf', bytes, 'upload-supporting-file-1');
const stored = await client.downloadProposalAttachment(proposal, 'supporting-document');
proposal = await client.deleteProposalAttachment(proposal, 'supporting-document',
  'remove-supporting-file-1');
```

`BRegProposal.documentJson` retains the disclosed slot policy and value.
Uploads refuse an empty body, a body larger than `maximumBytes`, and a content
type outside `contentTypes` before I/O. Uploads and removals use the promoted
slot condition and caller-chosen idempotency key and return a new Proposal.
Downloads follow the promoted link and return bounded bytes with their stored
content type. Keep the returned Proposal for subsequent operations; do not
substitute a Registry Record ETag or construct an attachment route.

## Explicit OAuth token exchange

`breg.PrivateKeyJwt` wraps the shared Rust OAuth provider. Construct it with the
same `PrivateKeyJwtConfig` used by client authorization. Call
`await provider.exchange(subjectToken)` to exchange a short-lived signed task
assertion for an access token. Set `resource` and `scopes` explicitly. Every
exchange authenticates the client afresh and bypasses the ordinary service
cache; `await provider.bearerToken()` uses that separate client-credentials
cache. Neither method logs or persists the returned credential. The application
must protect it and pass it explicitly to a resource client. The resource server
still validates the signed authority and bounds.
