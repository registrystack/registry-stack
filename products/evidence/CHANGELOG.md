# Registry Evidence changelog

## Unreleased

### Protocol words

- BREAKING: four transport and token words the Node.js and Python clients
  pass through from the shared HTTP primitives are kebab-case (CFG-NAME-2):
  the transport kind `response-too-large` (was `response_too_large`), the
  token kinds `invalid-credential` and `scope-narrowed` (were
  `invalid_credential` and `scope_narrowed`), and the refused-token code
  `unregistered-error-code` (was `unregistered_error_code`). The codes
  RFC 6749 section 5.2 registers keep the specification's spelling.
  Migration: change what a consumer of a client error compares. No file an
  adopter writes changes.
- BREAKING: five Evidence problem codes and the `type` URI derived from each
  are spelled in kebab-case: `evidence.invalid_request` is
  `evidence.invalid-request`, `request.selector_invalid` is
  `request.selector-invalid`, `auth.invalid_credential` is
  `auth.invalid-credential`, `evidence.rate_limited` is
  `evidence.rate-limited`, and `resource.not_found` is `resource.not-found`.
  The `error` label of `evidence_http_requests_total` carries the
  same words. The Version 1 problem contract and the generated schema and
  OpenAPI document state the new codes. The clients register the new codes
  only and report a body in the old spelling as a protocol failure.
  Migration: upgrade the gateway and every client in one step, and respell
  any match on `code`, `type`, or the `error` label. See "Protocol words" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: an unavailable item of the request-batch response states
  `result: evidence-not-available` in place of `evidence_not_available`. The
  Version 1 request-batch response contract and the generated schema and
  OpenAPI document state the new word, and the verifier, the client, and
  both bindings refuse a response that carries the old one. Migration:
  upgrade the gateway and every client in one step; code of your own that
  reads the envelope matches the new word.
- BREAKING: five error kinds are spelled in kebab-case. The verifier's
  `malformed_jws`, `protected_header`, and `key_binding` are `malformed-jws`,
  `protected-header`, and `key-binding`; the client's `not_available` and the
  nonce error's `not_canonical` are `not-available` and `not-canonical`. The
  Node.js and Python bindings carry the same words in `kind` and, for a
  verification failure, in `code`. Migration: a caller that catches by error
  class changes nothing; a comparison with one of the five words is
  respelled.
- BREAKING: `evidencectl audit view` prints each `reason=` word as the
  audit record spells its decision: `not_authorized`, `no_match`,
  `fact_missing`, `dependency_failure`, `evaluation_failure`, and
  `signing_failure` are `not-authorized`, `no-match`, `fact-missing`,
  `dependency-failure`, `evaluation-failure`, and `signing-failure`. The
  `artifact` of a deployment-target refusal in an `evidencectl` diagnostic is
  `deployment-target` in place of `deployment_target`. Migration: a script
  that matches the view's output or a diagnostic's `artifact` matches the
  new spelling. No audit record changes.
- BREAKING: the five fixed problems of the local source mock that
  `evidencectl` serves state their `code` in kebab-case:
  `source-mock.not-found`, `source-mock.method-not-allowed`,
  `source-mock.unsupported-route`, `source-mock.generation-failed`, and
  `source-mock.busy`. Migration: a local script that matches a mock
  problem `code` matches the new word.
- BREAKING: the metric label values Evidence defines are spelled in
  kebab-case. The `status` label of `evidence_http_requests_total`,
  `evidence_http_request_duration_seconds`, and the two
  `evidence_oid4vci_http_*` series is `client-error` or `server-error` in
  place of `client_error` or `server_error`, and so is the `status` field
  of a structured request log. The `outcome` label of
  `evidence_oid4vci_outcomes_total` carries its eighteen words with hyphens
  (`nonce-tampered`, `credential-issued`, `evidence-not-available`, ...).
  Metric names, label names, and the OAuth and OID4VCI error codes the
  delivery front end passes through its `error` label are unchanged.
  Migration: respell the label values in every dashboard query, recording
  rule, alert rule, and log filter. See "Protocol words" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: `evidencectl dev` reads the `mapping` of an exchange issuer in
  the borrowed Base Registry Engine owner's `.breg/dev/clients.json` in the
  spelling the owner writes: `institutional-grant` and `first-party`. It
  matched `institutional_grant` and `first_party`, which the owner no
  longer accepts, so every borrowed exchange registration was refused.
  Migration: none for a `clients.json` already upgraded for the Base
  Registry Engine; an owner file in the old spelling is refused by
  `bregctl` first.

### Stable move

- BREAKING: `evidence.yaml` opens with `apiVersion:
  id.registrystack.org/formats/evidence/bundle/v1` and `kind: EvidenceBundle`
  in place of `version: 1`, which is refused as `config.removed-key` with the
  two lines named. Migration: replace the first line of a hand-written bundle
  with the two members, regenerate `SHA256SUMS`, and re-pin
  `configurationRevision`; rebuild a compiled bundle with `evidencectl build`.
  See "Stable move" in `release/notes/config-conventions/evidence.md`.
- BREAKING: the runtime file declares `apiVersion:
  id.registrystack.org/formats/evidence/runtime/v1alpha1`. The earlier
  `registry.registrystack.org/evidence-runtime/v1alpha1` is refused as
  `config.retired-api-version` with the new value named. Migration: replace
  the `apiVersion` line of `runtime.yaml` and of the `runtime` member of each
  target settings file.
- BREAKING: a code list opens with `apiVersion:
  id.registrystack.org/formats/evidence/codelist/v1alpha1` and `kind:
  EvidenceCodelist`, names its identifier `uri`, states its form with `type:
  code-list` or `type: mapping`, and spells a mapping's outputs
  `allowedOutputs`. `id` and `allowed_outputs` are refused as
  `config.removed-key` with the replacement named, and
  `evidence.codelist.invalid-form` is no longer reported. Migration: add the
  two envelope lines and the `type` member, rename the two keys, regenerate
  `SHA256SUMS`, and re-pin `configurationRevision`.
- BREAKING: a code list `uri` holds no whitespace and no control character,
  and its limit of 512 is counted in characters, as the code list schema
  states it. An identifier with a space, tab, or line break at either end or
  inside is refused with `config.invalid-value` at `/uri`; it was accepted and
  kept as written while the URI parser read it without the character. An
  identifier of at most 512 characters that takes more than 512 bytes is now
  read; a `bucketScheme` that cites one is still held to 512 bytes.
  Migration: remove the character from the identifier, regenerate
  `SHA256SUMS`, and re-pin `configurationRevision`.
- BREAKING: the policy files `evidence verify --policy` and `evidence
  verify-presentation --policy` read open with `apiVersion` and `kind`
  (`id.registrystack.org/formats/evidence/verification-policy/v1` with
  `EvidenceVerificationPolicy`, and
  `id.registrystack.org/formats/evidence/holder-bound-verification-policy/v1`
  with `EvidenceHolderBoundVerificationPolicy`). A file without them is
  refused as `config.missing-envelope`. Migration: add the two lines at the
  top of every retained policy file. Rust, Node.js, and Python prepared
  requests and batches now return the complete enveloped policy document;
  retained contexts carry that same document under `verificationPolicy`.
  Prepare fresh retained contexts with the updated client. With independently
  pinned subject expectations, write `verificationPolicy` directly to a
  standalone CLI policy file. A first-use draft retains its existing empty
  `expectedSubjects` and is not a standalone CLI policy. The retained schema
  marker remains `registry.evidence-client.retained-verification/v1`; contexts
  with an unenveloped policy are refused. Rust struct literals for
  `EvidenceVerificationPolicyDocument` and `HolderBoundPresentationPolicyDocument`
  must supply typed `api_version` and `kind` fields; `Default::default()`
  selects each field's only supported value. Prepare options and verification
  decisions are unchanged.
- BREAKING: in the bundle, a request's `timeoutMilliseconds` is
  `attemptTimeoutMilliseconds`, and `concurrencyLimit` on a request and on a
  source connection is `maximumConcurrency`. The old keys are refused as
  `config.removed-key` with the replacement named. Migration: rename the keys
  in `evidence.yaml`, in authored `sources/*.yaml`, and under
  `sourceConnections` in target settings; keep the values, regenerate
  `SHA256SUMS`, and re-pin `configurationRevision`.
- BREAKING: in the runtime file, `audit.retainDays` is `audit.retentionDays`
  and the Transit signer's `timeoutMilliseconds` is
  `attemptTimeoutMilliseconds`. The old keys are refused as
  `config.removed-key` with the replacement named. Migration: rename the two
  keys in `runtime.yaml` and under the `runtime` member of each target
  settings file; keep the values.
- The bundle and runtime schemas type every `...Ref` secret member as
  `$defs/SecretReference`, the shared definition name, in place of
  `$defs/secret-ref`. The grammar and every file are unchanged.
- BREAKING: the bundle union tags are spelled `type`: a source's `transport`,
  an authentication's `kind`, a path binding's `from`, a statement parameter
  binding's `kind`, and an acquisition's `kind` are refused as
  `config.removed-key` with `type` named. Migration: rename the five tags and
  keep the values, in `evidence.yaml`, in every authored `sources/*.yaml`, and
  under `sourceConnections` in every target `settings.yaml`; regenerate
  `SHA256SUMS` and re-pin `configurationRevision`.
- BREAKING: the access-token key source is tagged by `type`:
  `authentication.oidc.jwksSource.kind` is refused as `config.removed-key`
  with `type` named. Evidence still reads keys from `type: uri` only.
  Migration: rename the key and keep the value, in `evidence.yaml`, in every
  target `governance.yaml`, and in the governance part of every authored
  target `settings.yaml`; regenerate `SHA256SUMS` and re-pin
  `package.expectedDigest` and `configurationRevision`.
- BREAKING: every bundle states `authentication.oidc.allowedClients` and
  `authentication.oidc.requiredScopes`, each as the keyword `unrestricted` or
  a list of at least one value. An omitted member is refused as
  `config.missing-key` and an empty list as `config.invalid-value`; neither
  means "no gate" any longer. Migration: add the absent member under
  `authentication.oidc` with `unrestricted` to keep today's behavior, or list
  the admitted values, then regenerate `SHA256SUMS` and re-pin
  `package.expectedDigest` and `configurationRevision`. See "Stable move" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: the runtime file tags its signer with `signer.type`; `signer.kind`
  is refused as `config.removed-key` with the replacement named. Migration:
  rename the key in `runtime.yaml` and under the `runtime` member of every
  target `settings.yaml`; keep the value.
- BREAKING: a client profile opens with `apiVersion:
  id.registrystack.org/formats/evidence/client-profile/v1` and `kind:
  EvidenceClientProfile`, and a reviewed contracts file with `apiVersion:
  id.registrystack.org/formats/evidence/client-contracts/v1` and `kind:
  EvidenceClientContracts`, in place of the `schema` header, which is refused
  as `config.removed-key` with the two members named. A profile tags its
  private key reference with `privateKey.type`; `privateKey.source` is
  refused the same way. The SDK types carry `api_version` and `kind` in place
  of `schema`. Migration: replace the `schema` line of each file with the two
  members and rename `privateKey.source` to `privateKey.type`, keeping the
  value; a Base Registry Engine project does the same in
  `evidence/contracts.json` and rebuilds its package. See "Stable move" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: the key of every id-keyed map in `evidence.yaml` and
  `runtime.yaml` is a local identifier as every Registry Stack format writes
  one: a lowercase letter, then up to 63 lowercase letters, digits, `_`, or
  `-`. That covers `selectorProfiles`, `sourceConnections`, `sources`,
  `authorityProfiles`, a selector profile's `fields`, `pathBindings` and path
  placeholders, `valueClaims`, `derivation.parameters`, and the runtime
  `outboundTls.trustProfiles` and `sourceExtracts`. A key with a dot or over
  64 characters is refused at the key. Adapter and statement parameter names
  and `assertionIssuers` client identifiers keep their spelling. Migration:
  rename each such key and every reference to it, coordinate a renamed
  selector profile or field with the callers that send it, regenerate
  `SHA256SUMS`, and re-pin `configurationRevision`.
- BREAKING: the bundle names the issuer URI `issuer.uri` and each concept URI
  `requirements[].concepts[].uri`. The old `id` keys are refused as
  `config.removed-key` with `uri` named.
  Migration: rename the two keys and keep the values, in `evidence.yaml`, in
  each target `governance.yaml`, and in the governance part of each authored
  target `settings.yaml`; then regenerate `SHA256SUMS`, update
  `package.expectedDigest`, and re-pin `configurationRevision`.
- BREAKING: a bundle requirement names its URI `requirements[].uri`. The old
  `id` key is refused as `config.removed-key` with `uri` named. A request,
  the definitions document, and an assertion are unchanged. Migration: rename
  the key and keep the value in every requirement of `evidence.yaml`; then
  regenerate `SHA256SUMS`, update `package.expectedDigest`, and re-pin
  `configurationRevision`.
- BREAKING: the holder-bound batch ceiling is `maximumHolderBoundBatchSize`
  in every place Evidence writes or reads it: the bundle (`evidence.yaml`,
  top level and `sources.*.evidence.contract`), the
  `registry.evidence-definitions/v1` document served at
  `GET /v1/evidence/definitions`, the OpenAPI document, and the
  `maximum_holder_bound_batch_size` field of the Rust client's
  `EvidenceDefinitionsDocument`. It was `holderBoundBatchMaxSize`
  (`holder_bound_batch_max_size`). The value, its range of 1 through 16, and
  the meaning of omission in a bundle are unchanged. There is no alias: a
  bundle that writes the old key is refused as `config.removed-key` with the
  new name, and the client, `evidence-oid4vci`, and `evidencectl doctor`
  refuse a definitions document carrying the old member as they refuse any
  unknown member. Migration for an operator: rename the key in
  `evidence.yaml`, then regenerate `SHA256SUMS`, update
  `package.expectedDigest`, and re-pin `configurationRevision`. Migration
  for a relying party or an SDK caller: upgrade Evidence Gateway and every
  client, binding, and protocol adapter that reads its definitions response
  in one step, and rename the member wherever your own code reads the
  document.
- BREAKING: a bundle concept states its value form as
  `requirements[].concepts[].type`. The old `form` key is refused as
  `config.removed-key` with `type` named; the values and the constraints
  each one fixes are unchanged, and the definitions document, a verification
  policy, and a source's fact contract keep `form`. Migration: rename the
  key and keep the value in `evidence.yaml`, then regenerate `SHA256SUMS`,
  update `package.expectedDigest`, and re-pin `configurationRevision`.
- BREAKING: a concept's `form` is a mapping named by `type` in every place
  Evidence writes or reads it: the fact contract a bundle pins under
  `sources.*.evidence.contract`, a verification policy and a holder-bound
  verification policy file, a reviewed contracts file, the
  `registry.evidence-definitions/v1` document served at
  `GET /v1/evidence/definitions`, the OpenAPI document, and the policy object
  handed to a client library. `form: boolean` becomes `form: {type: boolean}`,
  the same for `integer`, `string`, `date-bucket`, `time-bucket`,
  `entity-reference`, and `structured`, and
  `form: {list: {items: string, minimumItems: 1, maximumItems: 8, unique: true}}`
  becomes
  `form: {type: list, items: string, minimumItems: 1, maximumItems: 8, unique: true}`.
  The form names, the list's members, and their bounds are unchanged, and so
  are the Rust variants `DefinitionConceptForm` and `ExpectedFormDocument`
  expose. There is no alias: a file in the old shape is refused, a bare name
  as `config.invalid-type` and a `list` member as `config.removed-key` with
  the shape to write, and a client refuses a definitions document or a policy
  object in the old shape. A signed assertion, an SD-JWT VC, and an audit
  record never carried this union and are unchanged. Migration for an
  operator: rewrite each form under `sources.*.evidence.contract` in
  `evidence.yaml`, then regenerate `SHA256SUMS`, update
  `package.expectedDigest`, and re-pin `configurationRevision`. Migration for
  a relying party or an SDK caller: upgrade Evidence Gateway and every
  client, binding, and protocol adapter that reads its definitions response
  in one step; rewrite the `form` of each `expectedOutputs` entry in every
  retained policy file and in code that builds the policy object; and fetch
  each reviewed contracts file again. See "Stable move" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: a source that authenticates to its token endpoint with a signed
  client assertion declares `authentication.type: oauth2-private-key-jwt`.
  `oauth2-client-credentials` is the shared-secret form alone and requires
  `clientSecretRef` and `credentialPlacement`; `clientAssertionKeyRef` or
  `clientAssertionAudience` under it is refused as `config.unknown-key` at
  the key, with the new type named. The token request is unchanged.
  Migration: change `type` to `oauth2-private-key-jwt` wherever an
  `authentication` mapping carries `clientAssertionKeyRef`, in
  `evidence.yaml`, an authored `sources/*.yaml`, and an authored target
  `settings.yaml`, then regenerate `SHA256SUMS`, update
  `package.expectedDigest`, and re-pin `configurationRevision`.
- BREAKING: a source request states one `path`, a literal or a template.
  A path that names a placeholder requires `pathBindings`, and a path
  without one takes none. `pathTemplate` is refused as `config.removed-key`
  with `path` named, and `path` is 2 to 2048 bytes in both forms. The
  request the runtime sends is unchanged. Migration: rename
  `request.pathTemplate` to `request.path` and keep the value, in
  `evidence.yaml` and in an authored `sources/*.yaml`, then regenerate
  `SHA256SUMS`, update `package.expectedDigest`, and re-pin
  `configurationRevision`.
- A bundle requirement that repeats the `uri` of an earlier requirement is
  refused as `config.duplicate-id` at the copy's `uri`, with the first
  requirement as a related position, in place of
  `evidence.bundle.invalid-requirement`. A script that matches on the code
  matches on the new one.
- `evidence check` reports a bundle, a code list, or a fixture file over the
  1 MiB document cap as `yaml.too-large` at that file, in place of
  `evidence.package.too-large` at the package directory. A package file
  that is no configuration document keeps the package code.
- `evidence check` reports a package entry that is no regular file, such as
  a symbolic link, at each bundle member that names it, with the line and
  column of the value. The code stays `evidence.package.unsafe-entry`, and
  an entry no bundle member names stays at the package directory.
- A bundle whose derivation parameter is an integer outside the safe
  integers, or whose list concept declares `minimumItems` or `maximumItems`
  outside 1 to 64, is refused as `config.out-of-range` at the value, in
  place of `evidence.bundle.invalid-requirement` at the requirement.

### Evidence clients and OID4VCI

- BREAKING: the `evidence-oid4vci` runtime file has an envelope
  (`apiVersion`, `kind`) and a published schema, binds listeners with
  `bind`, names the delivery client key as a secret reference
  (`tokenClient.privateKeyRef`) where it was a file path, and states
  `offers.authorizedClients` and `offers.requiredScopes`. `evidence-oid4vci
  check` reports positioned, coded diagnostics, supports `--format json` and
  `--deny-warnings`, and exits 0, 1, 2, or 3. Every change, its migration
  step, and the old-message-to-code table are in
  `release/notes/config-conventions/evidence.md`, section "Evidence clients
  and OID4VCI".
- BREAKING: `evidencectl check --file <path> --deny-warnings` is refused as
  a usage error (exit 2). A single-file check reports no warnings, so the
  flag silently did nothing. Drop `--deny-warnings` from `--file` invocations.
- BREAKING: the Evidence client reads its profile and reviewed contracts
  through the shared configuration reader. Their schemas are generated and
  published under `id.registrystack.org`, replacing the hand-written
  `client-profile.schema.yaml` and `client-contracts.schema.yaml`; `null`
  members, contracts over 1 MiB, and control characters in `clientId` are
  refused. The added `read_client_profile` and `read_reviewed_contracts`
  return positioned, coded diagnostics. Migration steps and codes are in the
  same release-note section.

### Evidence authoring tools

- BREAKING: `evidencectl source mock serve`, `generate`, and `check` no longer
  accept the retired `--project` flag (use the positional project directory),
  and `evidencectl client profile create` and `client contracts fetch` no
  longer accept `--out` (use `--output`). See "Evidence tooling files" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: `evidencectl` no longer accepts the second spellings of arguments
  that have a current one. `--project` is refused on `target explain`,
  `dev stop`, `dev clean`, `source add`, `source suggest`, `source detach`,
  `fixtures run`, and `tooling editor` (use the positional project directory);
  `keygen` refuses `--out-dir`, `--public-out`, and `--out` (use
  `--output-dir`, `--public-output`, and `--output`); `jwks` refuses `--out`
  (use `--output`). The seed of a mock plan is bounded by the shared reader
  and refused as `config.out-of-range`. See "Evidence tooling files" in
  `release/notes/config-conventions/evidence.md`.
- BREAKING: a file under `sources/` opens with `apiVersion`
  (`id.registrystack.org/formats/evidence/source/v1alpha1`) and `kind`
  (`EvidenceSource`), and a file under `selectors/` with
  `id.registrystack.org/formats/evidence/selector/v1alpha1` and
  `EvidenceSelector`. Both are read by the shared configuration reader, have a
  generated schema mapped for editors, and lose the two lines before the
  compile. A BReg export writes them. Migration: add the two lines at the top
  of every such file; see "Evidence tooling files" in
  `release/notes/config-conventions/evidence.md`.
- `evidencectl` writes the mock plan and the access policy and client
  documents with sequences indented beneath their keys, and reports a refused
  `source mock` argument combination (`--http-addr`, `--path-parameter`) as a
  diagnostic with an `evidence.mock.*` code and a fix sentence.
- `evidencectl check --file <file>` checks one client profile, reviewed contracts
  file, development state file, source-import baseline or journal, source
  resolution file, or source export manifest offline, with the shared
  diagnostics and exit codes 0, 1 and 3.
- BREAKING: the resolution file `evidencectl source diff` and `evidencectl
  source update` read through `--resolutions` opens with `apiVersion`
  (`id.registrystack.org/formats/evidence/source-resolution/v1alpha1`) and
  `kind` (`EvidenceSourceResolution`) in place of `formatVersion`, names each
  resolution with `type` in place of `choice`, and is read by the shared
  configuration reader. A resolution of `keep` or `adopt` takes no other
  member. A generated JSON Schema ships with it. See "Evidence
  tooling files" in `release/notes/config-conventions/evidence.md`.

- BREAKING: the source-import baseline (`.evidence/source-imports/state.json`)
  and transaction journal (`.evidence/source-imports/transaction.json`) open
  with `apiVersion` and `kind` in place of `formatVersion`. `evidencectl source
  import` refuses a file in the earlier shape with a message that names the
  fix. See "Evidence tooling files" in
  `release/notes/config-conventions/evidence.md`.

- BREAKING: the session state `evidencectl dev` retains in
  `.evidence/dev/state.json` opens with `apiVersion`
  (`id.registrystack.org/formats/evidence/dev-state/v6`) and `kind`
  (`EvidenceDevState`) in place of `schema`, and omits `caller`,
  `issuerProject`, `issuerOwner`, and `failure` when unset where it wrote
  `null`. `evidencectl` refuses state in the earlier shape with a message that
  names the fix. Migration: see "Evidence tooling files" in
  `release/notes/config-conventions/evidence.md`.

- BREAKING: every `evidencectl --format json` report carries `apiVersion`
  (`id.registrystack.org/formats/evidence/ctl-report/v1alpha1`) and `kind`
  (`EvidenceCtlReport`) after `ok`, `command`, and `status`. A consumer that
  compared a whole report for equality, or rejected unknown members, must
  accept the two new members. The release note "Evidence tooling files" has
  the migration step.

- BREAKING: every authored YAML document
  opens with `apiVersion` and `kind`, and is read by the shared configuration
  reader: `${...}`, anchors, aliases, tags, unknown, duplicate, and null keys
  are refused at their line and column. `evidencectl check --deny-findings`
  is now `--deny-warnings`, its report lists `diagnostics` with
  `severity: warning`, its codes follow `evidence.<area>.<condition>`, and
  `--production` requires `--target`. `release/notes/config-conventions/evidence.md`
  ("Evidence authoring tools") gives each migration and the full code table.
- BREAKING: a question answer's concept URI is written `answers[].uri`, no
  longer `answers[].id`; a file that keeps `id` under an answer is refused as
  `config.removed-key`. Migration: rename the key in every
  `questions/*.yaml`.
- BREAKING: `evidencectl test` and `evidencectl fixtures run` read every
  `fixtures/*.yaml` of an editable project through the shared configuration
  reader before compiling or running anything, so a file the reader refuses
  is reported with its own code, pointer, line, and column
  (`yaml.anchor`, `config.wrong-kind`, `yaml.too-large`, and the rest) and no
  `evidence` step runs against it; the generic `evidencectl.fixtures.failed`
  stays for a run whose cases fail. A `fixtures/*.yaml` file that no question
  references and that is not an `EvidenceFixture` is now refused. Migration:
  move such a file out of `fixtures/`, or give it the fixture envelope.
  `evidencectl test --deny-warnings` and `evidencectl fixtures run
  --deny-warnings` are new and make a reader warning exit 1.

- BREAKING: a question refuses, at the member that carries it, each name its
  compiled bundle would refuse: an `id` over 47 bytes when the question reads
  an `operation` and has one subject, an `id` and a `role` over 46 bytes
  together or a `role` with a dot when it has several, and a dot in a
  `selector`, a `profile`, an entry of `profiles`, or a `source.ref`. The codes
  are `evidence.question.compiled-name-length` and
  `evidence.question.compiled-name-dot`. Such a project already failed, later,
  at the bundle check. Migration: shorten or rename the member in the
  question file.
- An access policy compiles to an authority profile named by the first 42
  characters of its requester tag, which fits the bundle's 64-character local
  identifier; the profile's `requesterTags` carries the tag whole, and callers
  are matched as before.

### Evidence runtime

- `evidence check --format json` and `evidence check-policy --format json`
  carry `apiVersion` (`id.registrystack.org/formats/evidence/ctl-report/v1alpha1`)
  and `kind` (`EvidenceCtlReport`) after `status`, as every `evidencectl`
  report does. Two members are added and none moves, so this is not breaking
  for a consumer that ignores unknown members.
- BREAKING: plain `evidence check` is offline. It reads the runtime file,
  verifies and compiles the package, reads each CA bundle, and checks the
  bindings between them, and reads no secret material, file modes, extract
  freshness, signer, audit destination, or network. Run
  `evidence check --require-runtime-dependencies` on the target host for the
  full proof. Exit codes: 0 clean, 1 refused, 2 usage, 3 an input could not
  be read.
- BREAKING: `evidence check` reports every problem in the shared diagnostic
  shape with a three-segment code and a summary line, writes one JSON
  document with `--format json`, and adds `--deny-warnings` and
  `--environment`.
- BREAKING: the bundle, the runtime file, code lists, fixtures, fact schemas,
  and both verification policies are read by the shared configuration
  reader: the shared YAML subset, unknown keys refused at their line and
  column, `${...}` refused in the bundle, code lists, and policies, and every
  bundle and runtime integer bounded.
- BREAKING: `service.publicOrigin`, `publication.endpointUrl`, and each
  `baseUrl` refuse userinfo, a scheme other than `http` or `https`, or more
  than 2048 characters.
- BREAKING: a fixture opens with
  `apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1` and
  `kind: EvidenceFixture` in place of `fixture: <id>`.
- BREAKING: `--runtime` and `REGISTRY_EVIDENCE_RUNTIME` exit 2 (usage).
- `evidence check-policy` checks one verification or holder-bound
  verification policy offline, as `verify` and `verify-presentation` read it.
- The code list JSON Schema is generated from the reader types, and
  `editors/configure.py` maps deployment-project files to their schemas.

Migration steps and the diagnostic code table:
`release/notes/config-conventions/evidence.md`, section "Evidence runtime".

## v0.39.0 - 2026-10-06

- BREAKING: before 1.0, a release reads only the state its immediate
  predecessor wrote. This release reads state written by v0.38.0 and nothing
  older. If you run an older release, upgrade one release at a time and finish
  each release's upgrade steps before starting the next. The entries below
  remove what served only releases before v0.38.0.
  - `release/scripts/rehearse-upgrade.py` rehearses an Evidence upgrade only
    from a deployment v0.38.0 packaged. It no longer rewrites a runtime file
    or a governance file from an earlier grammar, and it always starts
    `evidence` with `--runtime-config`.
  - `evidencectl dev --mint-port` and `--mint-bin` are unknown arguments
    (exit status 2), where they were refused as `evidence.dev.mint-retired`.
    Retained dev state under any schema but
    `registry.evidencectl.dev-state/v6` is refused as an unsupported local
    state schema, without the Mint guidance, and left untouched. Stop it with
    the release that wrote it, or move `.evidence/dev` aside, then start a
    fresh session.
  - Dev state that lacks `namePrefix`, or that names a subject's selector with
    `selectorProfile` and `selectorField` instead of `selectors`, is refused
    as invalid. Start a fresh session.

## v0.38.0 - 2026-10-01

- `evidence-oid4vci` omits `response_types_supported` from its OAuth
  authorization-server metadata. OpenID4VCI 1.0 Final permits the omission
  for a server that supports only the Pre-Authorized Code Grant, and the
  service no longer publishes an empty array for this multi-valued member.
  The metadata still does not advertise an authorization endpoint or an
  unsupported authorization response (#1785).

- An `http-json` source may declare `evidence` to read one predefined
  assertion from another Evidence deployment. The block pins one reviewed
  audience-scoped definition that supports `signed-jws`, its independently
  accepted public keys in `trustedJwks`, optional `revokedKeyIds`,
  `maximumAssertionLifetimeSeconds`, and `clockSkewSeconds`. Rust draws a
  fresh request nonce for every acquisition, sends the request with the
  ordinary source credential, and verifies the signed answer before
  projection; the preparation script supplies only the subjects, and
  extraction sees only `{"values": {...}}` keyed by concept handle. The
  source needs a fixed `POST` path ending in `/v1/evidence`, `query:
  forbidden`, `jsonBody: required`, and no `Accept` override, and it cannot
  declare `batch`, `unresolvedProblem`, or `forwardAccessAttribution: true`.
  Every selector in the pinned definition must use `valueOrigin: request`:
  the upstream authenticates this service's own source credential, so an
  `authenticated-context` or `authenticated-grant` selector is refused at
  configuration validation (#1774).

- `evidence-oid4vci` validates the complete discovered Evidence catalog
  against the Evidence request contract, and refuses the whole catalog when
  any one definition fails, instead of advertising the valid remainder.
  `CredentialCatalog::derive` now returns a `Result`. Each offered selector
  must carry exactly the published field set with values of the published
  type and bounds, checked before an offer secret or exchange state exists,
  so an unusable request is refused before a wallet spends its single-use
  code (#1773).

- `registry-evidence-client` publishes its offline request contract for an
  integrator that owns its HTTP transport:
  `EvidenceDefinitionsDocument::validate_for_request`,
  `DefinitionSelector::accepts_request_values`,
  `PreparedEvidenceRequest::prepare`,
  `PreparedEvidenceRequest::claim_request_json`, which claims the single
  send, and `RetainedEvidenceVerification::from_prepared`. None of them
  performs I/O.

- An `http-json` source may set `forwardAccessAttribution: true` to send the
  verified requester and authorized purpose, base64url encoded, in the
  reserved `Registry-Access-Requester` and `Registry-Access-Purpose` headers.
  The headers grant no source authority; the source must trust this service
  as an intermediary on its own terms.

- An inline proof `jwk` in `evidence-oid4vci` accepts only the `kty`, `crv`,
  `x`, `y`, `alg`, `kid`, and `use` members, with `use` only as `sig`, the
  same closed set a `did:jwk` proof already had. A key carrying any other
  member is refused instead of having the member dropped.
  `registry-evidence-client` refuses a holder-bound batch answer whose
  credential count differs from the number of presented holder keys.

- BREAKING: a requirement's `subjectRoles[].role` is limited to 64 bytes
  instead of 128, in the bundle schema and at startup, to match the Evidence
  request contract. A bundle with a longer role now fails startup; shorten
  the role and every grant, request, and derivation input that names it.

- Publish an `evidence-oid4vci` Docker image from v0.38.0 alongside the
  existing release binary (#1760).

## v0.36.0 - 2026-09-29

- `evidencectl audit show --last-operation` reads a retained history that
  holds request-batch entries instead of refusing it, and refuses with
  `evidence.audit.request-batch` when the last operation is a batch. An
  operation that ended in a denial or a transient failure after its access
  prints `DISCLOSURE DENIED` or `TRANSIENT FAILURE` with its reason instead of
  failing, and earlier operations left without an outcome are counted on an
  `EARLIER OPERATIONS WITHOUT AN OUTCOME` line. Refusals name a running writer,
  a malformed entry, or an unrecognized outcome with their own codes. The
  internal core view moves to `registry.evidence.local-audit-operation/v2`,
  which adds `unmatchedEarlierOperations`, so `evidence` and `evidencectl` must
  be the same version.

- `evidence serve` writes its operational records to standard error instead of
  standard output, so a `stdout` audit destination carries audit entries alone.
  A collector that read Evidence logs from standard output reads standard error
  instead.

- BREAKING: `evidencectl` follows the shared ctl report and exit contract.
  - Under `--format json` every command writes one object on standard output
    and nothing on standard error. It opens with `ok`, `command`, and
    `status`, then the command's own members, and every member name is
    camelCase; a map keyed by authored identifiers, such as
    `selectorProfiles`, keeps those identifiers as its keys.
    The former `operation` member is replaced by `command`. Refusals use the
    same object with `ok: false` and diagnostics that name the next command.
    A command-line error reports `command: "usage"` and `status:
    "usage-error"`.
  - `fixtures run` and `test` reports rename `evaluated_cases`,
    `failing_case`, `expected_class`, and `observed_class` to
    `evaluatedCases`, `failingCase`, `expectedClass`, and `observedClass`.
    A run that evaluated no case carries the diagnostic
    `evidencectl.fixtures.no-case`.
  - `source suggest` notes move from standard error into the report's
    `notes` member, and its equivalent command names the project
    positionally.
  - Exit classes are `0` success, `1` domain refusal or failing fixture, `2`
    usage, and `3` operational failure. A file that cannot be read or a
    missing local dev session now exits `3` instead of `1`.
  - Every command that reads one project takes it as a positional
    `<project>`. The former `--project` flag stays accepted but hidden on
    those commands; `source import`, `source diff`, `source update`, and
    `target new` still document it. `doctor` keeps its visible `--project`,
    and `access` and `audit show` still act on the current directory; none
    of these takes a positional project.
  - `test` and `fixtures run` accept `--format junit`: one JUnit XML document
    on standard output, one test case per traced case, and the human summary
    on standard error. Other commands refuse it as a usage error.
  - `dev start --name-prefix <prefix>` sets the local issuer container name
    prefix, `evidence-dev` by default, so parallel jobs on one host keep
    their containers apart. A restart without the flag reuses the session's
    prefix, and a different prefix is refused until `dev clean`.
  - To migrate, read `command` instead of `operation`, read the camelCase
    fixture keys, parse JSON reports from standard output alone, treat exit
    `3` as an unavailable dependency, and replace `--project <dir>` with
    `<dir>` in scripts for the commands that now take a positional project.

- Fix: `evidencectl access policy add` and `access client add` set their
  directories to the intended modes after creating them, so they no longer
  refuse the directory they just created when the operator's shell runs under
  a strict umask such as `077`.
- Fix: a request batch with more items than `burstPerPrincipal`, or a
  holder-bound release presenting more holder keys than the burst, is refused
  as `evidence.invalid_request` (400) without `Retry-After` and charges
  nothing. It previously returned `evidence.rate_limited` with a retry hint,
  although the bucket never refills past the burst and the retry could never
  be admitted. `evidence check` and `evidencectl doctor` now warn when
  `rateLimits.burstPerPrincipal` is below the largest request cost the bundle
  admits (sixteen items for a request batch against any audience-scoped
  requirement, or `holderBoundBatchMaxSize` for a holder-bound release with
  `sd-jwt-vc-batch`), naming both numbers and the key. The shipped reference
  deployment targets, reference deployment projects, BReg Evidence starters,
  and the `evidencectl` local bundle now set `burstPerPrincipal: 16`.
- Add: an HTTP source response whose shape drifted from the declared
  projection (a selected container missing or of another JSON type, or a
  selected leaf missing beside a member the projection does not select, which
  is what a rename leaves) increments the new
  `evidence_source_shape_drift_total{source}` counter and writes a
  rate-limited `WARN` naming the source and the declared JSON pointers. A 404
  that is not the source's declared `unresolvedProblem` still answers
  `source.unavailable`, and now writes a rate-limited `WARN` saying the source
  answered 404 with an undeclared shape. Neither record carries a response
  value, an undeclared member name, a selector, or a subject.

## v0.35.0 - 2026-09-28

- BREAKING: write audit through the shared platform audit writer instead of
  the keyed hash chain. Every entry is one JSON line with the members
  `schema`, `eventId`, `time`, `phase`, `correlation`, and `record`: an access
  attempt is a `request` entry, every terminal record a `response` entry, and
  `correlation` is the record's `operation`. Entries are not chained; ship
  them to append-only storage for tamper evidence.
  - The entry schemas are `registry.evidence.audit/v2`,
    `registry.evidence.audit.request-batch/v2`, and
    `registry.evidence.audit.authorization-refusal/v2`. The record no longer
    carries a `schema` member, and readers written for the chained `/v1`
    records do not read `/v2` entries.
  - The bundle `audit` section is now `hashKeyRef` and `hashKeyVersion`, both
    required. `format`, `hashSecretRef`, and `failClosed` are refused; every
    audit gate stays fail closed. Pseudonyms keep their
    `hmac-sha256:v<hashKeyVersion>:` prefix and are byte-identical for the same
    master and version.
  - The runtime `auditStorage` block is replaced by `audit`: `destination`
    (`file` by default, or `stdout`), `path` (required for `file`),
    `rotateBytes` (at least 1 MiB, 100 MiB by default), and `retainDays` (1 to
    36,500, 90 by default). Sealed files older than `retainDays` are deleted
    when the writer opens or rotates. `maximumFileBytes` is refused.
    `evidence check --require-audit-under` refuses a `stdout` destination.
  - `evidence verify-audit` is removed, and startup no longer verifies a chain.
    The runtime can no longer detect an audit master replaced without a
    `hashKeyVersion` change; the documented key rotation procedure owns that.
  - The `evidence_audit_segments` and `evidence_audit_bytes` metrics are
    removed.
  - `evidencectl doctor` checks a file audit destination with the audit
    writer's own rule and skips a `stdout` destination. `evidencectl target
    new` and the local bundles and runtime files `evidencectl` renders write
    the new `audit` blocks.
  - To migrate, rewrite the bundle `audit` section to `hashKeyRef` and
    `hashKeyVersion` and the runtime `auditStorage` block to `audit`, archive
    the old chained audit files to append-only storage, and point
    `audit.path` at a fresh file in a directory that holds no old sealed
    segments: retention deletes sealed files under the same name older than
    `retainDays`. Update audit readers to the `/v2` envelope
    before routing traffic to the new runtime.
