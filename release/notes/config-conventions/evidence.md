# Registry Evidence: configuration conventions

## Evidence clients and OID4VCI

Every change the configuration conventions make to the `evidence-oid4vci`
runtime file and to the Evidence relying-party client's profile files, with
the step that migrates a file or a script.

### BREAKING: the `evidence-oid4vci` runtime file has an envelope and a schema

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
