# Registry Evidence: configuration conventions

## Evidence clients and OID4VCI

Every change the configuration conventions make to the `evidence-oid4vci`
runtime file and to the Evidence relying-party client's profile files, with
the step that migrates a file or a script.

### BREAKING: the `evidence-oid4vci` runtime file has an envelope and a schema
<!-- upgrade: evidence-oid4vci-envelope -->

`evidence-oid4vci check`, `inspect`, and `serve` read the runtime file through
the configuration reader every Registry Stack product shares. The file starts
with an `apiVersion` and a `kind`, and `version` is retired.

- Old: `version: 1`. New:

  ```yaml
  # yaml-language-server: $schema=https://id.registrystack.org/schemas/evidence/oid4vci-runtime/oid4vci-runtime.v1alpha1.schema.json
  apiVersion: id.registrystack.org/formats/evidence/oid4vci-runtime/v1alpha1
  kind: EvidenceOid4vciRuntimeConfig
  ```

  Migration: delete the `version: 1` line and write the two envelope lines
  (and, optionally, the editor modeline) at the top of the file. A file
  without them is refused as `config.missing-envelope`, whose fix names both
  lines; a file that keeps `version` is refused as `config.removed-key` at
  `/version`.
- The schema is published at
  `https://id.registrystack.org/schemas/evidence/oid4vci-runtime/oid4vci-runtime.v1alpha1.schema.json`
  and committed at
  `products/evidence/generated/oid4vci-runtime/oid4vci-runtime.schema.json`.
  `python3 editors/configure.py` maps it for editors.
- A minimal valid file is committed at
  `products/evidence/examples/oid4vci-runtime/runtime.yaml`.

### BREAKING: listeners are written as `bind`
<!-- upgrade: evidence-oid4vci-listeners -->

- Old: `listener: {address: 127.0.0.1, port: 8090}`. New:
  `listener: {bind: 127.0.0.1:8090}`. Migration: replace `address` and `port`
  with one `bind: <address>:<port>` member; an IPv6 address is written in
  brackets, `[::1]:8090`. `maximumRequestBytes` and
  `requestTimeoutMilliseconds` stay in `listener` unchanged.
- Old: `metricsListener: {address: 127.0.0.1, port: 9090}`. New:
  `metricsListener: {bind: 127.0.0.1:9090}`. Migration: the same edit.
- `listener.address`, `listener.port`, `metricsListener.address`, and
  `metricsListener.port` are refused as `config.removed-key`, each with that
  fix.

### BREAKING: the delivery client key is a secret reference
<!-- upgrade: evidence-oid4vci-key-ref -->

Security-relevant. `tokenClient.privateKeyFile` named a file path, relative
paths resolved beside the runtime file. The key is now named by a secret
reference and resolved by the shared secret providers when `serve` or
`inspect` starts.

- Old:

  ```yaml
  tokenClient:
    privateKeyFile: delivery-client.jwk.json
  ```

  New, with the key file in a directory the runtime user owns:

  ```yaml
  secretProviders:
    file:
      root: /run/secrets/evidence-oid4vci
  tokenClient:
    privateKeyRef: secret:file/delivery-client.jwk.json
  ```

  Migration: move the key file into one directory, write that directory's
  absolute path as `secretProviders.file.root`, and replace `privateKeyFile`
  with `privateKeyRef: secret:file/<file name>`. The file name is one path
  segment that starts with a lowercase letter and holds only lowercase
  letters, digits, `.`, `_`, and `-` (at most 128 bytes); rename the file if
  it does not.
- Or, to pass the key through the environment (the route for a Kubernetes
  Secret, whose volume files are symbolic links owned by root, which the file
  provider refuses):

  ```yaml
  secretProviders:
    environment: {}
  tokenClient:
    privateKeyRef: secret:env/EVIDENCE_OID4VCI_CLIENT_JWK
  ```

  Migration: set `EVIDENCE_OID4VCI_CLIENT_JWK` (any uppercase name) to the
  JWK text in the process environment, for example from
  `valueFrom.secretKeyRef`.
- The file provider is stricter than the old reader about the key file: it
  must be a regular file (not a symbolic link) owned by the runtime user,
  with mode exactly `0400` or `0600`, and one hard link. The old reader also
  accepted any mode without group or other bits, such as `0700` or `0500`.
  Migration: `chmod 0400 <key file>`. The key file is no longer trimmed of
  surrounding whitespace before it is parsed as JSON, which JSON already
  ignores.
- `tokenClient.privateKeyFile` is refused as `config.removed-key` with the
  fix above. A reference that is not `secret:file/<name>` or
  `secret:env/<NAME>` is refused as `config.invalid-value`; a reference whose
  provider `secretProviders` does not enable is
  `evidence.oid4vci.secret-provider-disabled`; a `secretProviders` with
  neither provider is `evidence.oid4vci.secret-providers`; a relative
  `secretProviders.file.root` is `evidence.oid4vci.secret-file-root`.
- `evidence-oid4vci check` no longer reads the key. It resolves no secret
  and opens no socket. `serve` and `inspect` resolve the key at startup and
  log `the secret reference <reference> could not be resolved: <reason>`
  when it fails, naming the reference and never the key. Migration: a
  deployment step that relied on `check` to prove the key file was readable
  runs `evidence-oid4vci inspect --config <file>` instead, which resolves the
  key and reads the Evidence metadata.

### BREAKING: offer restrictions are stated, not defaulted
<!-- upgrade: evidence-oid4vci-offer-restrictions -->

`offers.authorizedClients` and `offers.requiredScopes` are required, and each
is either the word `unrestricted` or a nonempty list.

- Old: `authorizedClients` absent or `[]` accepted any client the offer-token
  issuer vouched for. New: `authorizedClients: unrestricted` does that, and
  `authorizedClients: [<client>, ...]` admits only the listed clients.
  Migration: write `authorizedClients: unrestricted` where the member was
  absent or `[]`; leave a nonempty list as it is. An empty list is refused as
  `config.invalid-value`.
- Old: `requiredScopes` absent kept no scope gate. New:
  `requiredScopes: unrestricted` keeps no scope gate, and
  `requiredScopes: [oid4vci:offer]` requires the scope. Migration: write
  `requiredScopes: unrestricted` where the member was absent; leave a
  nonempty list as it is. (`requiredScopes: []` was already refused.)
- A missing member is `config.missing-key`. An item `"*"` or
  `"unrestricted"` inside either list is a warning,
  `evidence.oid4vci.sentinel-item`: it matches only a client or scope with
  that literal name. Write `unrestricted` in place of the list instead.

### BREAKING: values the reader now refuses
<!-- upgrade: already-wrong -->

Each of these files was read before. The reader refuses them at their
position.

- `tokenClient.resource` is at most 512 bytes, where it was at most 2048
  (`config.invalid-value`). Migration: use the shorter resource identifier
  the Evidence deployment registers.
- A repeated item in `offers.audiences`, `offers.authorizedClients`,
  `offers.requiredScopes`, `offers.algorithms`, or `tokenClient.scopes` is
  `config.duplicate-item` at the repeated item. Migration: delete the repeat.
- `null`, `~`, or an empty value after a key is refused as
  `config.null-value`, where it read as absent. Migration: remove the key to
  take its default, or write a value.
- Anchors and aliases (`yaml.anchor`, `yaml.alias`) and explicit tags such as
  `!!str` (`yaml.tag`) are refused. Migration: write the value in full,
  quoted where it is text.
- A file larger than 1 MiB is refused as `platform.runtime-config.size`.
- `${NAME}` in a text value is substituted from the process environment when
  `serve` or `inspect` starts, where it was read literally. In
  `apiVersion`, `kind`, `tokenClient.privateKeyRef`, and under
  `secretProviders` it is refused as `config.substitution-not-allowed`.
  Migration: a text value that must hold `${NAME}` literally is written as
  `${VARIABLE}`, with the literal text as that variable's value.
- The runtime file's path, once resolved against the working directory, must
  not pass through a symbolic link. Migration: pass the file's real path. A
  Kubernetes ConfigMap volume presents its files through symbolic links; mount
  the runtime file with `subPath`, which bind-mounts the file itself. A path
  that cannot be resolved against the working directory is
  `evidence.oid4vci.config-path`.
- These were refused before and still are, now with a code and a position:
  an unknown member (`config.unknown-key`), `mint`
  (`config.removed-key`, fix: write `tokenClient` with the same members), a
  number outside its bound (`config.out-of-range`), and a value of the wrong
  type or shape (`config.invalid-value`).

### BREAKING: `evidence-oid4vci check` reports in the shared diagnostic shape
<!-- upgrade: no-file -->

- `check --config <file>` prints every problem, each on standard error as
  `error[CODE] FILE:LINE:COLUMN /json/pointer` followed by the message and a
  `next:` line, then a count of errors and warnings. The old command logged
  one JSON tracing line naming the first problem. Migration: a script that
  parsed the log line runs `check --format json` and reads the
  `diagnostics` list (`code`, `severity`, `path`, `message`,
  `suggestedAction`, `source.file`, `source.line`, `source.column`). A
  passing file prints `0 errors, 0 warnings in 1 file` on standard error,
  where the old command logged `configuration is valid`.
- Exit status: 0 when the file passes (warnings included), 1 when it breaks a
  rule (or reports a warning under `--deny-warnings`), 2 when the command line
  is invalid, and 3 when the file cannot be read. The old command exited 1
  for every failure. Migration: a script that tested for a nonzero status
  needs no change; one that tested for exactly 1 also accepts 3 for an
  unreadable file.
- `--environment` substitutes `${...}` expressions from the process
  environment, as startup does, and checks the values they fill. Without it
  an expression is checked by its syntax and position only.
- When `serve` or `inspect` refuses the file, it prints the same lines on
  standard error before it logs the startup failure. A warning is printed the
  same way and does not stop startup.

### `evidence-oid4vci` diagnostic codes

The old messages carried no code. Each maps to the code that reports the same
problem now.

| Old message | New code |
|---|---|
| `the configuration file is unavailable` | `platform.runtime-config.unavailable` (exit 3) |
| `the configuration document is invalid: <parser text>` | The reader's own code at the position: `config.unknown-key`, `config.missing-key`, `config.invalid-value`, `config.out-of-range`, `config.duplicate-item`, or a `yaml.` syntax code |
| `only configuration version 1 is supported` | `config.missing-envelope`, `config.unsupported-api-version`, or `config.removed-key` at `/version` |
| `the mint configuration key is retired; use tokenClient` | `config.removed-key` at `/mint` |
| `configuration path has no parent` | Retired: nothing is resolved beside the file. An unresolvable path is `evidence.oid4vci.config-path` |
| `listener address is not an IP address` | `config.invalid-value` at `/listener/bind` |
| `the listener port must be non-zero, because the published origin names it` | `evidence.oid4vci.listener-port` |
| `listener maximumRequestBytes must be 1024..=1048576` | `config.out-of-range` |
| `listener requestTimeoutMilliseconds must be 1..=30000` | `config.out-of-range` |
| `metrics listener address is not a private IP address` | `config.invalid-value` (not an address) or `evidence.oid4vci.metrics-address` |
| `the metrics listener must bind a loopback or private address` | `evidence.oid4vci.metrics-address` |
| `the metrics listener port must be non-zero` | `evidence.oid4vci.metrics-port` |
| `the metrics listener must not share the delivery listener binding` | `evidence.oid4vci.metrics-shared-binding` |
| `the token client identifier must be 1..=128 bytes` | `evidence.oid4vci.client-id` |
| `a token client key file is required` | `config.missing-key` for `tokenClient.privateKeyRef` |
| `tokenClient.resource must be an absolute URI without fragment or userinfo, at most 2048 bytes` | `evidence.oid4vci.token-resource`; over 512 bytes, `config.invalid-value` |
| `tokenClient.scopes must contain 1..=32 scope tokens` | `evidence.oid4vci.token-scope-count` |
| `tokenClient.scopes must be distinct bounded RFC 6749 scope tokens` | `config.duplicate-item` (a repeat), `evidence.oid4vci.token-scope` (not a scope token), or `evidence.oid4vci.token-scope-parameter` (joined scopes over 4096 bytes) |
| `offer contextual claim names must be valid and distinct` | `evidence.oid4vci.claim-names` |
| `the offer endpoint must state at least one audience` | `evidence.oid4vci.audience-count` |
| `every offer audience must be 1..=256 bytes` | `evidence.oid4vci.audience` |
| `the offer endpoint must accept at least one signature algorithm` | `evidence.oid4vci.algorithm-count` |
| `the offer endpoint must accept exactly one signature algorithm family` | `evidence.oid4vci.algorithm-count` |
| `every authorized offer client must be 1..=128 bytes` | `evidence.oid4vci.authorized-client` |
| `offer requiredScopes, when stated, must list at least one scope` | `config.invalid-value` |
| `every required offer scope must be 1..=256 bytes` | `evidence.oid4vci.required-scope` |
| `offer requiredScopes must be RFC 6749 scope-tokens` | `evidence.oid4vci.required-scope` |
| `offer requiredScopes must not repeat a scope` | `config.duplicate-item` |
| `the offer token lifetime ceiling must be 60..=3600 seconds` | `config.out-of-range` |
| `the store must hold 256..=1048576 offers` | `config.out-of-range` |
| `the offer lifetime must be 60..=900 seconds` | `config.out-of-range` |
| `the access token lifetime must be 60..=900 seconds` | `config.out-of-range` |
| `the nonce lifetime must be 30..=900 seconds` | `config.out-of-range` |
| `the nonce lifetime must not exceed the access token lifetime` | `evidence.oid4vci.nonce-lifetime` |
| `the transaction code attempt ceiling must be 1..=10` | `config.out-of-range` |
| `the credential issuer must be an absolute URL`, and the same message for the Evidence base URL, the token endpoint, the offer token issuer, the offer key set, and the client assertion audience | `config.invalid-value` |
| `every published and called origin must use https` | `evidence.oid4vci.https-required` |
| `every published and called origin must have a host` | `config.invalid-value` |
| `no published or called origin may carry credentials` | `config.invalid-value` |
| `no published or called origin may carry a query or fragment` | `evidence.oid4vci.url-query-or-fragment` |
| `the credential issuer must be a bare origin with no path` | `evidence.oid4vci.issuer-path` |
| `the supervised local development listener must exactly match its canonical credential issuer origin` | `evidence.oid4vci.supervised-listener` |
| `a supervised local development endpoint must be an absolute URL` | `config.invalid-value` |
| `a supervised local development endpoint must be a canonical 127.0.0.1 HTTP origin with an explicit port and no query or fragment` | `evidence.oid4vci.supervised-endpoint` |
| `a supervised local development credential issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port` | `evidence.oid4vci.supervised-issuer` |
| `the client key file is unavailable`, `... is not a regular, single-link, owner-only file`, `... is too large`, `... could not be read`, `... is not valid UTF-8` (at `check`, `serve`, or `inspect`) | No longer reported by `check`. At `serve` and `inspect` startup: `the secret reference <reference> could not be resolved: <reason>` |

New codes with no old message: `evidence.oid4vci.sentinel-item` (warning),
`evidence.oid4vci.secret-providers`,
`evidence.oid4vci.secret-provider-disabled`,
`evidence.oid4vci.secret-file-root`, `evidence.oid4vci.config-path`,
`config.missing-envelope`, `config.unsupported-api-version`,
`config.substitution`, and `config.substitution-not-allowed`.

### BREAKING: the client profile and reviewed contracts have generated schemas
<!-- upgrade: no-file -->

The relying-party client (`registry-evidence-client`, its Node.js and Python
bindings, and `evidencectl` commands that load a client profile) reads the
client profile and the reviewed contracts snapshot through the configuration
reader every Registry Stack product shares. Both files keep their `schema`
member (`registry.evidence-client-profile/v1`,
`registry.evidence-client-contracts/v1`) and every member they had.

- The hand-written schemas
  `products/evidence/contracts/client-profile.schema.yaml`
  (`https://registrystack.org/schemas/evidence/client-profile-v1.json`) and
  `products/evidence/contracts/client-contracts.schema.yaml`
  (`https://registrystack.org/schemas/evidence/client-contracts-v1.json`) are
  deleted. They are generated from the readers and committed at
  `products/evidence/generated/client-profile/client-profile.schema.json`
  (`https://id.registrystack.org/schemas/evidence/client-profile/client-profile.v1.schema.json`)
  and
  `products/evidence/generated/client-contracts/client-contracts.schema.json`
  (`https://id.registrystack.org/schemas/evidence/client-contracts/client-contracts.v1.schema.json`).
  Migration: point any `$schema` member, editor mapping, or validator that
  named an old path or identifier at the new one. The contracts schema refers
  each definition to `evidence-definitions-v1.schema.json`, so a validator
  loads that document beside it.
- Minimal valid files are committed at
  `products/evidence/examples/client-profile/client-profile.json` and
  `products/evidence/examples/client-contracts/evidence.contracts.json`.

### BREAKING: client profile and contracts values the reader now refuses
<!-- upgrade: already-wrong -->

- `null` as the value of an optional member is refused as
  `config.null-value`, where it read as absent. Migration: remove the member
  to take its default.
- A reviewed contracts file larger than 1 MiB is refused, where the limit
  was 4 MiB. Migration: review a snapshot scoped to the definitions the
  application requests; a requester-scoped snapshot is far below the limit.
- A `\uD800`-`\uDFFF` surrogate-pair escape in a string is refused as
  `yaml.unclosed-quote`. Migration: write the character itself in UTF-8.
- A `clientId` holding a control character is refused. This refuses only a
  file that was already wrong: no authorization server issues such an
  identifier.
- A repeated member was refused before and still is, now as
  `yaml.duplicate-key` at its position.

The client now also reads what it refused before: a profile up to 1 MiB
(the limit was 256 KiB), a byte-order mark, and either file written in YAML
syntax.

### Client diagnostic codes

The public Rust error and the binding errors stay opaque: `from_slice`,
`from_file`, and the reviewed contracts loader still fail with `the client
profile is invalid or unavailable`. The added `read_client_profile` and
`read_reviewed_contracts` functions return the positioned diagnostics, each
with one of these codes or a shared `config.` or `yaml.` code.

| Old message | New code |
|---|---|
| `the client profile is invalid or unavailable` (profile syntax, shape, or type) | The reader's own code at the position: `config.unknown-key`, `config.missing-key`, `config.invalid-value`, `config.out-of-range`, `config.null-value`, or a `yaml.` syntax code |
| `the client profile is invalid or unavailable` (`baseUrl`) | `evidence.client.base-url-not-origin`, `evidence.client.base-url-not-https`, `evidence.client.base-url-literal-address`, or `evidence.client.base-url-not-loopback` |
| `the client profile is invalid or unavailable` (another profile rule) | `evidence.client.profile-invalid` |
| `the client profile is invalid or unavailable` (contracts shape) | `evidence.client.definition-shape` |
| `the client profile is invalid or unavailable` (contracts with a repeated definition) | `evidence.client.duplicate-definition` |
| `the client profile is invalid or unavailable` (a definition that breaks a contract rule) | `evidence.client.definition-invalid` |
| `the client profile is invalid or unavailable` (contracts rules) | `evidence.client.contracts-invalid` |

## Evidence authoring tools

Track: Evidence authoring tools (`evidencectl`, `registry-evidence-authoring`,
`registry-language-server`).

### BREAKING changes
<!-- upgrade: 1=evidence-project-envelope, evidence-question-envelope, evidence-access-policy-envelope, evidence-access-client-envelope, evidence-target-governance-envelope, evidence-target-settings-envelope, evidence-mock-plan-envelope; 2=no-file; 3=no-file; 4=evidence-authoring-reader-refusals; 5=evidence-authoring-reader-refusals; 6=no-file; 7=evidence-authoring-reader-refusals; 8=no-file; 9=no-file; 10=no-file -->

1. **Every authored YAML document except a source and a selector opens with
   `apiVersion` and `kind`.** A document without them is refused with
   `config.missing-envelope`, and a version key the format no longer takes is
   refused with `config.removed-key` at its line. Migration, file by file:

   | File | Delete | Add at the top |
   |---|---|---|
   | `evidence-project.yaml` | `version: 1` and `project: evidence-authoring` | `apiVersion: id.registrystack.org/formats/evidence/authoring-project/v1alpha1`, `kind: EvidenceAuthoringProject` |
   | `questions/<id>.yaml` | (nothing) | `apiVersion: id.registrystack.org/formats/evidence/question/v1alpha1`, `kind: EvidenceQuestion` |
   | `access/policies/<id>.yaml` | `version: 1` | `apiVersion: id.registrystack.org/formats/evidence/access-policy/v1alpha1`, `kind: EvidenceAccessPolicy` |
   | `access/clients/<id>.yaml` | `version: 1` | `apiVersion: id.registrystack.org/formats/evidence/access-client/v1alpha1`, `kind: EvidenceAccessClient` |
   | a target's `governance.yaml` | `version: 1` | `apiVersion: id.registrystack.org/formats/evidence/target-governance/v1alpha1`, `kind: EvidenceTargetGovernance` |
   | the `settings.yaml` that `evidencectl target new --settings` reads | `formatVersion: 1` and `governance.version: 1` | `apiVersion: id.registrystack.org/formats/evidence/target-settings/v1alpha1`, `kind: EvidenceTargetSettings` |
   | `mocks/source.yaml` | `version: 1` | `apiVersion: id.registrystack.org/formats/evidence/mock-plan/v1alpha1`, `kind: EvidenceMockPlan` |

   Edit each file by hand; `evidencectl check <project>` names every file and
   line still to change. `evidencectl init`, `access`, `target new`, and
   `source mock generate` write the new lines in the files they create.
2. **`--deny-findings` is now `--deny-warnings`.** `evidencectl check
   --deny-findings` is a usage error (exit 2, `evidence.usage.flag-renamed`)
   that names the new flag. Migration: replace the flag in scripts and CI.
3. **`evidencectl check` and `explain` report diagnostics, not findings.** The
   JSON report lists every diagnostic under `diagnostics`; the `findings` array
   is gone, and so is the `evidencectl.check.refused` or
   `evidencectl.explain.refused` wrapper a denied run added. A non-fatal
   diagnostic has `severity: warning` (was `finding`), and every diagnostic
   carries the `source` file, line, and column it names. Human output prints
   the shared shape (`error[code] file:line:col /pointer`, the message, then
   the next step) and a summary line. `check` exits 0 when it passes, 1 when
   it refuses the project (or finds a warning under `--deny-warnings`), 2 for
   a usage error, and 3 when it could not finish. Migration: read
   `diagnostics` in place of `findings`, match `severity: warning` in place of
   `finding`, and match codes by the table below.
4. **`${...}` is refused in every authored document** with
   `config.substitution-not-allowed`. Nothing in an authoring project was ever
   substituted; the expression was read as literal text. Migration: write the
   value itself.
5. **Every authored document is read by the shared configuration reader.**
   Anchors, aliases, tags, merge keys, more than one document, duplicate keys,
   unknown keys, and null values are refused at their line and column
   (`yaml.anchor`, `yaml.alias`, `yaml.tag`, `yaml.merge-key`,
   `yaml.multiple-documents`, `yaml.duplicate-key`, `config.unknown-key`,
   `config.null-value`), with the closest declared key when there is one.
   Each document holds at most 1 MiB (`yaml.too-large`); this also applies to
   a target's `governance.yaml` and to `mocks/source.yaml`. Migration: expand
   each anchor or alias in place, remove the tag or the unknown key, or
   correct its spelling as the diagnostic names.
6. **`evidencectl check --production` requires `--target`.** Without it the
   command is a usage error (exit 2). Migration: name the target, for example
   `evidencectl check <project> --production --target targets/production`.
7. **`evidencectl check` reads every YAML file in the project root,
   `targets/`, and `mocks/`.** A file is checked as the format its `kind`
   names. Under `targets/`, a file that names no format the target holds and
   is not named `settings.yaml`, `governance.yaml`, or `runtime.yaml` is
   refused (`evidence.project.unidentified-file`); under `mocks/`, every file
   that names no other format is checked as a mock plan; at the project root,
   a file that is neither a known format nor an OpenAPI description is a
   warning (`evidence.project.unidentified-file`). A known format in the wrong
   directory is refused (`evidence.project.misplaced-file`). Migration: move
   or delete a stray YAML file, or add its envelope.
8. **`evidencectl source mock check` reports the reader's diagnostics.** Its
   JSON report carries `diagnostics`, and `--deny-warnings` refuses the plan
   when any warning is present. An invalid plan is refused as
   `evidence.mock-plan.invalid` or with the reader's own code. Migration: none
   beyond item 1 for an existing plan.
9. **Diagnostic codes follow `evidence.<area>.<condition>`.** See the table
   below. Migration: update any script or CI rule that matches a code.
10. **The authoring JSON Schema identifiers moved to id.registrystack.org.**
    The schema files keep their paths under
    `crates/registry-evidencectl/schemas/authoring/`, so
    `editors/configure.py` needs no change. `evidencectl init` writes a
    `# yaml-language-server: $schema=...` line naming the new identifier.
    Migration: an editor configuration that names a schema by `$id` uses the
    new value.

    | Schema | Previous `$id` | `$id` now |
    |---|---|---|
    | project marker | `https://registrystack.example/schemas/evidence-authoring/project-marker.v1.json` | `https://id.registrystack.org/schemas/evidence/authoring-project/authoring-project.v1alpha1.schema.json` |
    | question | `https://registrystack.example/schemas/evidence-authoring/question.v1.json` | `https://id.registrystack.org/schemas/evidence/question/question.v1alpha1.schema.json` |

### Other changes

- Size bounds follow the shared reader: the project marker may hold 1 MiB (was
  4 KiB), and a question or access policy 1 MiB (was 64 KiB).
- The language server reports the same codes, sentences, and positions as
  `evidencectl check` for the files it covers.
- `products/evidence/reference/authoring-projects/example/` is a complete
  reference project. The format registry names it as the example for every
  authoring format, and `evidencectl check` and `evidencectl source mock
  check --project` pass on it with no diagnostic.

### Diagnostic codes, old to new

`evidencectl check`, `explain`, and the authoring commands:

| Before | Code now |
|---|---|
| `evidence.authoring.<code>` for a finding in a question, access policy, or derivation file | `evidence.<area>.<condition>`, where the area is `question`, `access-policy`, or `derivation` and a code that began with the area drops it: `evidence.authoring.question-text` is `evidence.question.text`, `evidence.authoring.answer-concept-unique` is `evidence.question.answer-concept-unique`, `evidence.authoring.access-policy-grant-kind` is `evidence.access-policy.grant-kind`, `evidence.authoring.derivation-compile` is `evidence.derivation.compile` |
| `evidence.authoring.derivation-fact-undeclared` | `evidence.derivation.fact-undeclared` |
| `evidence.authoring.disclosure-allow` | `evidence.derivation.disclosure-allow` against a derivation file, `evidence.question.disclosure-allow` against a question |
| `evidence.authoring.bundle-shape` | `evidence.bundle.shape` |
| `evidence.question.parse`, `evidence.access-policy.parse`, `evidence.authoring.project-marker-parse`, `evidence.target.governance-shape` | the reader's code at the line and column: `yaml.*` (for example `yaml.syntax`, `yaml.duplicate-key`, `yaml.anchor`, `yaml.too-large`) or `config.*` (for example `config.unknown-key`, `config.missing-key`, `config.invalid-type`, `config.null-value`) |
| `evidence.authoring.project-marker-version`, `evidence.target.governance-version` | `config.missing-envelope`, or `config.removed-key` at `/version` |
| `evidence.project-marker.missing` | `evidence.project.marker-missing` (warning) |
| `evidence.project-marker.file-type` | `evidence.project.not-plain-file` |
| `evidence.authoring.unreadable` | the condition itself: `evidence.project.not-directory`, `evidence.project.not-plain-file`, `evidence.project.file-too-large`, `evidence.project.changed`, `evidence.project.unexpected-file`, or a reader code |
| `evidence.question.id-duplicate` | not raised: a question's `id` must equal its file name (`evidence.question.id-filename-mismatch`), so two files cannot share one |
| `evidence.finding` (human output for a finding without a code) | removed: every diagnostic carries its own code |
| `evidencectl.check.refused`, `evidencectl.explain.refused` | removed: the refusing diagnostics are the report |

The language server (`registry-language-server`, hosted by `evidencectl`):

| Before | Code now |
|---|---|
| `evidence/question-shape`, `evidence/access-policy-shape` | the reader's `yaml.*` or `config.*` code |
| `evidence/<code>` for an authoring finding | the code `evidencectl check` reports, by the rule in the first table |
| `evidence/question-file-name` | `evidence.question.file-name` |
| `evidence/access-policy-file-name` | `evidence.access-policy.file-name` |
| `evidence/operation-identifier` | `evidence.question.operation-identifier` |
| `evidence/subject-selector` | `evidence.question.subject-selector` |
| `evidence/undeclared-collection` | `evidence.question.undeclared-collection` |
| `evidence/unselectable-fact-path` | `evidence.question.unselectable-fact-path` |
| `evidence/unknown-question` | `evidence.project.unknown-question` |
| `evidence/project-ceiling` | `evidence.project.ceiling` |
| `evidence/directory-ceiling` | `evidence.project.directory-ceiling` |
| `evidence/document-ceiling` | `evidence.project.document-ceiling` |
| `evidence/openapi-prerequisite` | `evidence.openapi.prerequisite` |

Codes with no predecessor (the condition was an uncoded refusal or was not
checked): `evidence.usage.flag-renamed`, `evidence.project.misplaced-file`,
`evidence.project.unidentified-file`, `evidence.question.derivation-shared`,
`evidence.derivation.encoding`, `evidence.access-policy.id-filename-mismatch`,
`evidence.mock-plan.invalid`, `evidence.target-settings.invalid`, and
`evidence.target.runtime-structure`.

Unchanged: `evidence.answer-schema.*`, `evidence.offline-check.refused`,
`evidence.access.questions-missing`, `evidence.access-policy.question-missing`,
`evidence.answer.stable-id-missing`, `evidence.question.{missing,
source-missing, selector-missing, governance-missing, id-filename-mismatch,
validity-exceeds-signing-maximum}`, `evidence.question.derivation-*` and
`evidence.question.fixture-*`, `evidence.source.*`, `evidence.package.*`, and
`evidence.target.{required, incomplete, production-profile-required,
source-connection-required, assurance-profile, authority-profiles,
publication-invalid, signing-key-missing}`.

## Evidence runtime

Track: the `evidence` runtime binary and the files it reads (the deployment
bundle, the runtime file, code lists, fixtures, fact schemas, and the two
verification policies).

### BREAKING changes
<!-- upgrade: 1=no-file; 2=no-file; 3=evidence-bundle-reader-refusals; 4=evidence-bundle-reader-refusals; 5=evidence-fixture-envelope; 6=evidence-bundle-reader-refusals; 7=evidence-bundle-reader-refusals; 8=evidence-check-policy; 9=no-file -->

Promised spellings are unchanged in this release; the section "Respellings
held for the stable release" lists them.

1. **Plain `evidence check` is offline.** It reads the runtime file, verifies
   the package `package.root` names, loads and compiles the bundle, reads
   each CA bundle a trust profile names, and checks every binding between the
   runtime file and the bundle. It no longer reads secret material, checks
   file modes or immutability, checks extract freshness, runs the signer
   self-test, opens the audit destination, or contacts the network. Exit
   codes: 0 clean, 1 refused (or a warning with `--deny-warnings`), 2 usage,
   3 an input could not be read. Migration: on the target host, run
   `evidence check --require-runtime-dependencies --runtime-config <path>`
   (with `--require-audit-under <directory>` where you used it) for the proof
   the previous `evidence check` gave. `evidencectl doctor` treats exit 3 as
   a dependency failure. `evidence evaluate` and `evidence serve` still
   refuse a writable runtime file, bundle, or CA bundle.
2. **`evidence check` output.** One run reports every problem it finds
   instead of stopping at the first. The human output on standard error
   prints each diagnostic in the shared shape
   (`error[code] file:line:col /pointer`, the message, then `next:` with the
   fix) and ends with a summary line (`0 errors, 0 warnings in N files`); a
   passing check still prints
   `Evidence package <digest> passed check (<n> requirements)` on standard
   output. `--format json` writes one JSON document on standard output with
   `ok`, `command`, `status` (`complete`, `domain-refusal`,
   `operational-failure`), `filesChecked`, and `diagnostics`.
   `--deny-warnings` turns a warning into exit 1. `--environment` fills
   `${NAME}` expressions from the process environment and checks the values
   they fill; without it an expression is checked by its syntax and position
   only, and a warning (`evidence.runtime.not-checked`,
   `evidence.package.not-checked`) says what was skipped. Substitution fills
   text only, so an expression in an integer or boolean member is refused
   (`config.expected-integer`, `config.expected-boolean`) with or without
   `--environment`. Every diagnostic
   carries a three-segment code. Migration: a script that matched message
   text should match the code instead; the table in "Diagnostic codes, old
   to new" maps each previous message to its code.
3. **The bundle (`evidence.yaml`) and the runtime file are read by the shared
   configuration reader.** They accept only the shared YAML subset (no
   anchors, aliases, tags, merge keys, duplicate keys, or more than one
   document) and refuse an unknown key at its line and column with the
   closest declared key. A null or a quoted value where an integer belongs is
   refused. A key an earlier grammar accepted is refused as
   `config.removed-key` with its replacement. A `${...}` expression in the
   bundle is refused as `config.substitution-not-allowed`. Every integer in
   both files is bounded, and a value outside its range is refused as
   `config.out-of-range` with the allowed range. `audit.hashKeyVersion` and
   `subjectBinding.keyVersion` accept 1 to 2147483647, the range the bundle
   contract states; a larger value was accepted before. The warning for a burst
   below the largest request cost names that cost and the key to raise, not
   the configured values. Migration: remove anchors, aliases, tags, merge
   keys, duplicate keys, and unknown keys; write each integer unquoted and
   within its range; move a removed key to the replacement the diagnostic
   names.
4. **URL members are typed.** `service.publicOrigin`,
   `publication.endpointUrl`, and each source's and source connection's
   `baseUrl` refuse userinfo, a scheme other than `http` or `https`, or more
   than 2048 characters, as `config.invalid-value`. Migration: write a plain
   `https` URL without credentials.
5. **The fixture header is an envelope.** A fixture opens with
   `apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1` and
   `kind: EvidenceFixture` in place of `fixture: <id>`. A file with only the
   old header is refused as `config.missing-envelope`; `fixture:` beside the
   envelope is refused as `config.removed-key`. Migration: replace the
   `fixture: <id>` line with the two envelope lines, then rebuild the package
   with `evidencectl package`.
6. **Code lists are read by the shared reader.** An unknown key, a
   `${...}` expression, or a repeated code is refused (`config.unknown-key`,
   `config.substitution-not-allowed`, `config.duplicate-item`). A code list
   declares `codes`, or `entries` with `allowed_outputs`, and not both
   (`evidence.codelist.invalid-form`); each list or mapping holds from 1 to
   4096 items (`evidence.codelist.invalid-size`); a mapping names only
   outputs `allowed_outputs` lists (`evidence.codelist.output-not-allowed`).
   Migration: remove empty lists and repeated codes, and correct the file as
   the diagnostic names.
7. **Fact schemas are read by the shared reader** and accept only the shared
   YAML subset. Migration: remove anchors, aliases, tags, merge keys, and
   duplicate keys.
8. **Verification and holder-bound verification policies are read by the
   shared reader.** An unknown member, a `${...}` expression, a duplicate
   item, or a count outside its bounds is refused. `evidence verify` and
   `evidence verify-presentation` still report a refused policy as
   `stored response verification failed (malformed)`. Migration: run the new
   `evidence check-policy --verification-policy <file>` (or
   `--holder-bound-policy <file>`) and correct the policy as it reports.
9. **`--runtime` and `REGISTRY_EVIDENCE_RUNTIME` are usage errors.** Both
   were already refused; the exit status is now 2 (usage), where it was 1.
   Migration: pass `--runtime-config <file>` and unset the variable.

### Other changes

- `evidence check-policy --verification-policy FILE` or
  `--holder-bound-policy FILE` checks one policy offline exactly as `verify`
  or `verify-presentation` reads it, reports every problem with the shared
  diagnostics, and exits 0 clean, 1 refused, 2 usage, 3 the file could not
  be read. `--format json` writes the same document shape as
  `evidence check`, and `--deny-warnings` exits 1 on a warning. A file over
  the 1 MiB cap is refused as `yaml.too-large` (exit 1).
- The code list JSON Schema is generated from the reader types and held
  byte-identical by `products/evidence/scripts/check-contracts.sh`.
- `editors/configure.py` maps the deployment-project files (`evidence.yaml`,
  `runtime.yaml`, and `codelists/*.yaml`) to their schemas for editors.

### Diagnostic codes, old to new

Before this release no `evidence check` diagnostic carried a code: the
command printed one sentence on standard error and stopped. Codes now follow
CFG-DIAG-3 (`evidence.<area>.<condition>`) beside the shared reader's
`yaml.*` and `config.*` codes. The runtime's HTTP problem codes are
unchanged.

| Before (message, no code) | Code now |
|---|---|
| `configuration YAML does not match the Evidence Version 1 schema: ...` | the reader's `yaml.*` and `config.*` codes, for example `yaml.duplicate-key`, `yaml.anchor`, `yaml.tag`, `config.unknown-key`, `config.missing-key`, `config.null-value`, `config.expected-integer`, `config.invalid-type`, `config.unknown-variant`, `config.wrong-kind`, `config.missing-envelope` |
| `... key is no longer accepted` | `config.removed-key` |
| `configuration exceeds the Evidence Version 1 size limit` | `yaml.too-large` (runtime file); `evidence.bundle.invalid-configuration` (bundle) |
| `configuration violates the Evidence Version 1 contract: ...` (bundle) | `config.out-of-range`, `config.invalid-value`, or the section's code: `evidence.bundle.invalid-service`, `evidence.bundle.invalid-issuer`, `evidence.bundle.invalid-publication`, `evidence.bundle.invalid-authentication`, `evidence.bundle.invalid-subject-binding`, `evidence.bundle.invalid-signing`, `evidence.bundle.invalid-response-formats`, `evidence.bundle.invalid-selector-profile`, `evidence.bundle.invalid-source`, `evidence.bundle.invalid-source-connection`, `evidence.bundle.invalid-authority-profile`, `evidence.bundle.invalid-acquisition-capabilities`, `evidence.bundle.invalid-requirement`, `evidence.bundle.invalid-configuration` |
| `configuration violates the Evidence Version 1 contract: ...` (runtime file) | `config.out-of-range`, `config.invalid-value`, or the block's code: `evidence.runtime.invalid-package`, `evidence.runtime.invalid-listener`, `evidence.runtime.invalid-metrics-listener`, `evidence.runtime.invalid-secret-providers`, `evidence.runtime.invalid-signer`, `evidence.runtime.invalid-audit`, `evidence.runtime.invalid-outbound-tls`, `evidence.runtime.invalid-source-extract`, `evidence.runtime.invalid-acquisition-capabilities`, `evidence.runtime.invalid` |
| `deployment input is unavailable` | `evidence.runtime.unavailable` (runtime file), `evidence.bundle.unavailable` (package file), `evidence.runtime.ca-bundle-unavailable` (CA bundle); `evidence.deployment.unavailable` (with `--require-runtime-dependencies`) |
| `deployment input is not immutable: ...` | `evidence.deployment.not-immutable` (with `--require-runtime-dependencies`); `evidence.bundle.not-immutable` (package file) |
| another deployment input refusal while proving runtime dependencies | `evidence.deployment.invalid-input` |
| `deployment contains an unsupported entry` | `evidence.bundle.unsupported-entry` |
| `deployment contains an invalid path binding` | `evidence.bundle.invalid-path` |
| `deployment artifact closure is invalid: ...` | `evidence.bundle.unknown-file` |
| `deployment exceeds a Version 1 size bound` | `evidence.bundle.too-large` |
| `deployment configuration is invalid: ...` | `evidence.bundle.invalid-configuration` |
| `deployment artifact is invalid: ...` | `evidence.bundle.invalid-artifact`; for a code list `evidence.codelist.invalid-form`, `evidence.codelist.invalid-size`, `evidence.codelist.output-not-allowed`; for a fixture `evidence.fixture.not-synthetic`, `evidence.fixture.missing-cases`, `evidence.fixture.invalid-case-count`, `evidence.fixture.invalid-case`, `evidence.fixture.invalid-case-id`, `evidence.fixture.unresolved-not-declared`, `evidence.fixture.invalid-unresolved-marker`, `evidence.fixture.incomplete-coverage`; for a CA bundle `evidence.runtime.invalid-ca-bundle` |
| `deployment artifact is invalid: runtime signer kind does not match the bundle assurance profile` | `evidence.runtime.signer-assurance-mismatch` |
| `deployment artifact is invalid: a bundle secret reference names a provider ...` | `evidence.runtime.secret-provider-not-enabled` |
| `deployment artifact is invalid: the local signing key reference must be distinct ...` | `evidence.runtime.signing-key-shared` |
| `deployment artifact is invalid: the audit file path must not resolve to configured secret material` | `evidence.runtime.audit-path-is-secret` |
| `deployment artifact is invalid: the runtime configuration does not bind a TLS trust profile the bundle names` | `evidence.runtime.trust-profile-unbound` |
| `deployment artifact is invalid: the runtime configuration binds a TLS trust profile the bundle does not name` | `evidence.runtime.trust-profile-unused` |
| `deployment artifact is invalid: the runtime configuration binds no file for a source extract profile ...` | `evidence.runtime.source-extract-unbound` |
| `deployment artifact is invalid: the runtime configuration binds a source extract profile no bundle source names` | `evidence.runtime.source-extract-unused` |
| `deployment artifact is invalid: the runtime configuration does not enable an acquisition capability ...` | `evidence.runtime.acquisition-capability-missing` |
| `deployment script is invalid: ...` | `evidence.bundle.invalid-script` |
| a package refusal (`the package at <root> ...`) | `evidence.package.invalid-root`, `evidence.package.sum-file-missing`, `evidence.package.invalid-sum-file`, `evidence.package.mismatch`, `evidence.package.unsafe-entry`, `evidence.package.too-large`, `evidence.package.unavailable`, `evidence.package.empty`, `evidence.package.digest-mismatch`, `evidence.package.invalid`; `evidence.deployment.package-refused` (with `--require-runtime-dependencies`) |
| `bundle compilation failed: ...` | `evidence.bundle.compile-refused` |
| `source plan compilation failed` | `evidence.source.plan-refused` |
| `bound extract is stale for source ...` | `evidence.deployment.stale-extract` |
| `runtime bundle initialization failed` | `evidence.deployment.refused` |
| `runtime secret initialization failed` | `evidence.deployment.secret-unavailable` |
| `runtime audit initialization failed: ...` | `evidence.deployment.audit-refused` (the audit block), `evidence.deployment.audit-unavailable` (key, file, or storage) |
| `runtime signing initialization failed: ...` | `evidence.deployment.signing-unavailable` (key or provider not available), `evidence.deployment.signing-refused` (a key that is not the governed one) |
| `runtime source initialization failed` | `evidence.deployment.source-unavailable` |
| `runtime rate-limit initialization failed` | `evidence.deployment.rate-limit-unavailable` |
| `runtime authentication initialization failed: ...` | `evidence.deployment.refused` |
| `a required runtime dependency is unavailable` | `evidence.deployment.dependency-unavailable` |
| `audit destination check failed: ...` | `evidence.deployment.audit-outside-root` |
| `--require-audit-under needs a file audit destination; ...` | `evidence.deployment.audit-not-a-file` |
| `evidence: warning: rateLimits.burstPerPrincipal is <n>, below <m>, ...` | `evidence.bundle.burst-below-largest-request` (warning) |
| (offline check skipped a substituted value, new) | `evidence.runtime.not-checked`, `evidence.package.not-checked` (warnings) |
| (verification policy refusals, new with `check-policy`) | the reader's `yaml.*` and `config.*` codes, `evidence.policy.invalid-count`, `evidence.policy.unpaired-list-form`, `evidence.policy.not-verifiable`, `evidence.policy.unavailable` |

### Respellings held for the stable release (WP11)

These promised spellings stay as they are now; the stable release moves them
and refuses the old spelling with a diagnostic naming the new one.

| Format | Now | Stable release |
|---|---|---|
| bundle (`evidence.yaml`) | `version: 1`, no `apiVersion` or `kind` | `apiVersion: id.registrystack.org/formats/evidence/bundle/v1`, `kind: EvidenceBundle` |
| bundle | `concurrencyLimit` (fixed requests, statement requests, source connections) | `maximumConcurrency` |
| bundle | `timeoutMilliseconds` (fixed requests, statement requests) | `attemptTimeoutMilliseconds` |
| bundle | untagged variants (acquisitions, fixed requests, path bindings, sources, source authentication, statement parameter bindings, concept forms) | a `type` member, or single-key mappings |
| bundle | untyped identifier keys and members (sources, source connections, selector profiles, authority profiles, requirement and concept ids, issuer id, parameter maps) | typed as `LocalId` or `ExternalId` |
| bundle | `...Ref` secret members (audit hash key, source authentication, subject binding) | typed as `SecretReference` |
| runtime file | `apiVersion: registry.registrystack.org/evidence-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1` (the old value refused as `config.retired-api-version`) |
| runtime file | `audit.retainDays` | `audit.retentionDays` |
| runtime file | `signer.timeoutMilliseconds` | `signer.attemptTimeoutMilliseconds` |
| runtime file | `signer` tagged by `kind` | tagged by `type` |
| runtime file | `outboundTls.trustProfiles` and `sourceExtracts` keys | typed as `LocalId` |
| runtime file | `signer.privateKeyRef` | typed as `SecretReference` |
| code list | no `apiVersion` or `kind` | `apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1`, `kind: EvidenceCodelist` |
| code list | `allowed_outputs` | `allowedOutputs` |
| code list | `id` (a URI) | an `ExternalId` member |
| code list | code list and mapping forms told apart by their members | a `type` member |
| verification policy | no `apiVersion` or `kind` | `apiVersion: id.registrystack.org/formats/evidence/verification-policy/v1`, `kind: EvidenceVerificationPolicy` |
| holder-bound verification policy | no `apiVersion` or `kind` | `apiVersion: id.registrystack.org/formats/evidence/holder-bound-verification-policy/v1`, `kind: EvidenceHolderBoundVerificationPolicy` |
| both policies | untagged expected forms | a `type` member |

## Evidence tooling files

### BREAKING: every `evidencectl --format json` report has an envelope

Every report opens with `ok`, `command`, and `status`, then `apiVersion`
(`id.registrystack.org/formats/evidence/ctl-report/v1alpha1`) and `kind`
(`EvidenceCtlReport`), then the command's own members. The format is
unpromised. Migration: a script that compared a whole report for equality, or
refused unknown members, accepts `apiVersion` and `kind`; a script that read
members by name needs no change.
