# Registry Evidence changelog

## Unreleased

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
- BREAKING: the Evidence client reads its profile and reviewed contracts
  through the shared configuration reader. Their schemas are generated and
  published under `id.registrystack.org`, replacing the hand-written
  `client-profile.schema.yaml` and `client-contracts.schema.yaml`; `null`
  members, contracts over 1 MiB, and control characters in `clientId` are
  refused. The added `read_client_profile` and `read_reviewed_contracts`
  return positioned, coded diagnostics. Migration steps and codes are in the
  same release-note section.

### Evidence authoring tools

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

- BREAKING: every authored YAML document except a source and a selector
  opens with `apiVersion` and `kind`, and is read by the shared configuration
  reader: `${...}`, anchors, aliases, tags, unknown, duplicate, and null keys
  are refused at their line and column. `evidencectl check --deny-findings`
  is now `--deny-warnings`, its report lists `diagnostics` with
  `severity: warning`, its codes follow `evidence.<area>.<condition>`, and
  `--production` requires `--target`. `release/notes/config-conventions/evidence.md`
  ("Evidence authoring tools") gives each migration and the full code table.

### Evidence runtime

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
