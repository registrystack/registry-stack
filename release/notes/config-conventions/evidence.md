# Registry Evidence: configuration conventions

This fragment describes the final v0.40.0 interface. An `Old` or `Before`
example is an earlier file, request, response, or value to replace; every
current example and diagnostic below uses the final v0.40.0 spelling.

## BREAKING: wallet delivery names its runtime file with `--runtime-config`

In v0.39.0, `evidence-oid4vci check`, `inspect`, and `serve` took `--config`
or `EVIDENCE_OID4VCI_CONFIG`. In v0.40.0 they take `--runtime-config FILE`
or `EVIDENCE_OID4VCI_RUNTIME_CONFIG`, with no alias for either old name.
Replace the flag and variable in scripts, service definitions, and deployment
configuration. Relative paths remain accepted.

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
  log `the secret reference configured at <member path> could not be resolved: <reason>`
  when it fails, naming the member and never the reference or the key. Migration: a
  deployment step that relied on `check` to prove the key file was readable
  runs `evidence-oid4vci inspect --runtime-config <file>` instead, which resolves the
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
  `evidence.oid4vci.wildcard-spelled-item`: it matches only a client or scope with
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
- A file larger than 1 MiB is refused as `yaml.too-large`.
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

- `check --runtime-config FILE` prints every problem it finds in a pass, each on standard error as
  `error[CODE] FILE:LINE:COLUMN /json/pointer` followed by the message and a
  `next:` line, then a count of errors and warnings. The old command logged
  one JSON tracing line naming the first problem. Migration: a script that
  parsed the log line runs `check --format json` and reads the
  `diagnostics` list (`code`, `severity`, `path`, `message`,
  `suggestedAction`, `source.file`, `source.line`, `source.column`). A
  passing file prints `0 errors, 0 warnings in 1 file` on standard error,
  where the old command logged `configuration is valid`.
- The JSON report carries the Evidence report envelope, `apiVersion`
  `id.registrystack.org/formats/evidence/ctl-report/v1alpha1` and `kind`
  `EvidenceCtlReport`, as the `evidence` and `evidencectl` reports do.
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
| `the client key file is unavailable`, `... is not a regular, single-link, owner-only file`, `... is too large`, `... could not be read`, `... is not valid UTF-8` (at `check`, `serve`, or `inspect`) | No longer reported by `check`. At `serve` and `inspect` startup: `the secret reference configured at <member path> could not be resolved: <reason>` |

New codes with no old message: `evidence.oid4vci.wildcard-spelled-item` (warning),
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
   --deny-findings` is a usage error (exit 2), as any unknown flag is.
   Migration: replace the flag in scripts and CI.
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
   correct its spelling as the diagnostic names. A mock plan's
   `generation.seed` is an integer from 0 to 9007199254740991 inclusive; a
   value outside that range is refused as `config.out-of-range` at
   `/generation/seed`. Migration: choose a seed in range; regenerating a mock
   with a different seed changes its output.
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
11. **A question answer's concept URI is `uri`.** The member `answers[].id`
    holds an identifier another system issues (a URN), so it was never a
    local identifier and no longer shares the name `id` with the question's
    own identifier. The question's own top-level `id` does not change.
    Migration: in every `questions/*.yaml`, rename `id:` to `uri:` under each
    entry of `answers`. A file that keeps `answers[].id` is refused as
    `config.removed-key` at `/answers/<n>/id`, naming `answers[].uri`. The
    value is held to 1 to 512 characters with no control characters. The
    diagnostic code `evidence.answer.stable-id-missing` is unchanged and now
    points at `/answers/<n>/uri`.

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
checked): `evidence.project.misplaced-file`,
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

The promised spellings these items leave alone are respelled by the "Stable
move" section below; the section "Respellings made by the stable move" lists
them.

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
2. **`evidence check` output.** One run reports every problem it finds in a pass
   instead of stopping at the first; fix them and run it again, because a later pass
   can report more (see the "Read a diagnostic" section of the Configuration files reference). The human output on standard error
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
   `kind: EvidenceFixture` in place of `fixture: <id>`. A file with the
   old header is refused twice: `config.missing-envelope` for the absent
   envelope and `config.removed-key` for `fixture:`; both are reported for the
   one cause, and `fixture:` beside the envelope is refused as
   `config.removed-key` alone. Until the package is rebuilt with
   `evidencectl package`, `evidence check` reports `evidence.package.mismatch`
   first (the edited file no longer matches its `SHA256SUMS`) and hides these
   content errors. Migration: replace the `fixture: <id>` line with the two
   envelope lines, then rebuild the package with `evidencectl package`.
6. **Code lists are read by the shared reader.** A code list opens with the
   `EvidenceCodelist` envelope and declares `uri`, `version`, and `type`. A
   `type: code-list` file declares `codes`; a `type: mapping` file declares
   `entries` and `allowedOutputs`. An unknown key, a `${...}` expression, or
   a repeated code is refused (`config.unknown-key`,
   `config.substitution-not-allowed`, `config.duplicate-item`). Each list or
   mapping holds from 1 to 4096 items (`evidence.codelist.invalid-size`), and
   a mapping names only outputs listed under `allowedOutputs`
   (`evidence.codelist.output-not-allowed`). The old `id` and
   `allowed_outputs` members are `config.removed-key`; the tagged form makes
   `evidence.codelist.invalid-form` obsolete. Migration: add the envelope and
   `type`, rename the two removed members, remove empty lists and repeated
   codes, and correct the file as the diagnostics name.
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
  or `verify-presentation` reads it, reports every problem it finds in a pass with the shared
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
| `deployment artifact is invalid: ...` | `evidence.bundle.invalid-artifact`; for a code list `evidence.codelist.invalid-size`, `evidence.codelist.output-not-allowed`; for a fixture `evidence.fixture.not-synthetic`, `evidence.fixture.missing-cases`, `evidence.fixture.invalid-case-count`, `evidence.fixture.invalid-case`, `evidence.fixture.invalid-case-id`, `evidence.fixture.unresolved-not-declared`, `evidence.fixture.invalid-unresolved-marker`, `evidence.fixture.incomplete-coverage`; for a CA bundle `evidence.runtime.invalid-ca-bundle` |
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
| (verification policy refusals, new with `check-policy`) | the reader's `yaml.*` and `config.*` codes, `evidence.policy.invalid-count`, `evidence.policy.unpaired-list-form`, `evidence.policy.list-not-unique`, `evidence.policy.list-bounds-inverted`, `evidence.policy.not-verifiable`, `evidence.policy.unavailable` |

### Respellings made by the stable move

The items above leave these promised spellings alone. This release moves them
with no alias, and the "Stable move" section below states each change and its
migration step under the heading the last column names.

| Format | Was | Is | Stable move item |
|---|---|---|---|
| bundle | a fixed request told apart by `path` or `pathTemplate` | one `path`, a literal or a template | "a request states one `path`, a literal or a template" |
| bundle | the OAuth client authentication of a source, told apart by which members were present | `type: oauth2-client-credentials` or `type: oauth2-private-key-jwt` | "a client assertion key is its own authentication type" |
| bundle | a requirement's concept names its value form in `form`; a fact contract writes `form` as a bare name or a `list` mapping | the concept names it in `type`; a contract's `form` is a mapping named by `type` | "a concept states its value form as `type`", "a concept's `form` is a mapping named by `type`" |
| bundle | untyped keys of the id-keyed maps (sources, source connections, selector profiles, authority profiles, parameter maps) | typed as `LocalId` | "the key of an id-keyed map is a local identifier" |
| bundle | the issuer, concept, and requirement URIs under `id` | under `uri` | "the issuer and each concept name their URI as `uri`", "a requirement names its URI as `uri`" |
| runtime file | `outboundTls.trustProfiles` and `sourceExtracts` keys | typed as `LocalId` | "the key of an id-keyed map is a local identifier" |
| both policies | untagged expected forms | a `form` mapping named by `type` | "a concept's `form` is a mapping named by `type`" |

## Evidence tooling files

### BREAKING: every `evidencectl --format json` report has an envelope

Every report opens with `ok`, `command`, and `status`, then `apiVersion`
(`id.registrystack.org/formats/evidence/ctl-report/v1alpha1`) and `kind`
(`EvidenceCtlReport`), then the command's own members. The format is
unpromised. Migration: a script that compared a whole report for equality, or
refused unknown members, accepts `apiVersion` and `kind`; a script that read
members by name needs no change.

### BREAKING: the development session state has an envelope

`.evidence/dev/state.json` opens with `apiVersion:
id.registrystack.org/formats/evidence/dev-state/v6` and `kind:
EvidenceDevState`; the `schema` member is gone (`config.removed-key`), and a
member that is unset (`caller`, `issuerProject`, `issuerOwner`, `failure`) is
absent where it was `null`. The file is read by the shared configuration
reader. `evidencectl dev` refuses a state file in the earlier shape without
changing it. Migration: finish the session with the evidencectl that started
it (`evidencectl dev stop`, then `evidencectl dev clean`), then run
`evidencectl dev start` again.

### BREAKING: the source-import baseline and journal have an envelope

`.evidence/source-imports/state.json` opens with `apiVersion:
id.registrystack.org/formats/evidence/source-import-state/v1alpha1` and
`kind: EvidenceSourceImportState`; `.evidence/source-imports/transaction.json`
opens with `apiVersion:
id.registrystack.org/formats/evidence/source-import-journal/v1alpha1` and
`kind: EvidenceSourceImportJournal`. `formatVersion` is gone from both, and
from each recorded export manifest inside the baseline. A file in the earlier
shape is refused and left as it is. Migration for the baseline: delete
`.evidence/source-imports` and run `evidencectl source import` again; every
file that differs from the export is then reported as a conflict to resolve.
Migration for a journal left by an interrupted import: run `evidencectl source
import` with the evidencectl that started it to finish or roll back, then
rerun.

### BREAKING: the source resolution file has an envelope

A resolution file passed with `--resolutions` opens with `apiVersion:
id.registrystack.org/formats/evidence/source-resolution/v1alpha1` and `kind:
EvidenceSourceResolution`; `formatVersion` is gone and is refused with
`config.removed-key`. The file is read by the shared configuration reader, so
a `null` value, a document over 1 MiB, an unknown `type`, and a member a
`keep` or `adopt` resolution does not take (`path`) are refused with a
positioned diagnostic. The member that names the resolution is `type` (it was
`choice`), as in every other tagged union. Migration: replace `"formatVersion":
1` with the two members above, and rename each `"choice"` member to `"type"`.
The conventional names `source-resolutions.json` and `*.resolutions.json` have
a generated schema, mapped by `editors/configure.py`.

### BREAKING: a source file has an envelope and a schema

Every file under `sources/` opens with `apiVersion` and `kind`, and is read by the
shared configuration reader. A file without them is refused as
`config.missing-envelope`, whose fix names both lines, and a `null` value is
refused as `config.null-value`. `evidencectl` removes the two lines before the
body enters the bundle, so the compiled bundle is unchanged. Migration: add
these two lines at the top of every file under `sources/`:

```yaml
# yaml-language-server: $schema=https://id.registrystack.org/schemas/evidence/source/source.v1alpha1.schema.json
apiVersion: id.registrystack.org/formats/evidence/source/v1alpha1
kind: EvidenceSource
```

The first line is the optional editor modeline. The schema is generated at
`crates/registry-evidencectl/schemas/authoring/source.schema.json`, mapped by
`evidencectl tooling editor` and `editors/configure.py`; it requires the two
members and leaves the body to the bundle grammar that `evidencectl check`
applies after the compile. A BReg source export writes the
two lines itself, so a source imported from an export needs no edit.

### BREAKING: a selector file has an envelope and a schema

Every file under `selectors/` opens with `apiVersion` and `kind`, and is read by the
shared configuration reader. A file without them is refused as
`config.missing-envelope`, whose fix names both lines, and a `null` value is
refused as `config.null-value`. `evidencectl` removes the two lines before the
body enters the bundle, so the compiled bundle is unchanged. Migration: add
these two lines at the top of every file under `selectors/`:

```yaml
# yaml-language-server: $schema=https://id.registrystack.org/schemas/evidence/selector/selector.v1alpha1.schema.json
apiVersion: id.registrystack.org/formats/evidence/selector/v1alpha1
kind: EvidenceSelector
```

The first line is the optional editor modeline. The schema is generated at
`crates/registry-evidencectl/schemas/authoring/selector.schema.json`, mapped by
`evidencectl tooling editor` and `editors/configure.py`; it requires the two
members and leaves the body to the bundle grammar that `evidencectl check`
applies after the compile. A BReg source export writes the
two lines itself, so a source imported from an export needs no edit.

### BREAKING: retired `evidencectl` argument spellings are refused

`evidencectl source mock serve`, `generate`, and `check` no longer accept
`--project <dir>`; `evidencectl client profile create` and `evidencectl client
contracts fetch` no longer accept `--out`. Clap refuses each as an unexpected
argument (`evidencectl.usage`, exit 2). Migration: pass the project directory
as the positional argument (`evidencectl source mock check <dir>`), and write
`--output` where a script wrote `--out` for those two commands.

The same refusal applies to the second spellings of other arguments.
`--project <dir>` is refused on `evidencectl target explain`, `dev stop`,
`dev clean`, `source add`, `source suggest`, `source detach`, `fixtures run`,
and `tooling editor`; `evidencectl keygen` refuses `--out-dir`, `--public-out`,
and `--out`, and `evidencectl jwks` refuses `--out`. Migration: pass the
project directory as the positional argument (`evidencectl fixtures run
<dir>`), and write `--output-dir`, `--public-output`, and `--output` for the
`keygen` and `jwks` flags.

### BREAKING: a fixture file the reader refuses stops `evidencectl test`

`evidencectl test` and `evidencectl fixtures run` read every
`fixtures/*.yaml` of an editable project, and every fixture a deployment
project's bundle references, through the configuration reader before they
compile the project or run an `evidence` step. A file the reader refuses is
reported with the reader's own code, pointer, line, column, and fix, as
report diagnostics that repeat no value from the file, and the run ends with
exit 1 before any delegated step. The generic `evidencectl.fixtures.failed`
remains for a run whose cases fail.

Before, a refused fixture surfaced as `evidencectl.fixtures.failed` with the
reader's refusal only as text in `check.stderr`, and an editable project's
`fixtures/*.yaml` that no question referenced was never read. Migration: a
`fixtures/*.yaml` file that is not an `EvidenceFixture` document (a stray
notes or draft file) is now refused as `config.missing-envelope` or
`config.wrong-kind`; move it out of `fixtures/`, or give it the fixture
`apiVersion` and `kind`.

`evidencectl test` and `evidencectl fixtures run` take `--deny-warnings`
(additive): a warning the reader reports for a fixture file then exits 1.

## Stable move

Track: the promised Evidence formats move to the spellings the configuration
conventions fix for the stable release. Every old spelling is refused with a
diagnostic naming the new one; none is read as an alias.

Every change in this section that rewrites a bundle moves the
`configurationRevision` of every requirement the bundle serves, because the
revision digests the bundle as read and every artifact a requirement reaches.
The member and its `sha256:` form are unchanged. A verification policy or a
relying party that pins a revision re-pins it after the rewritten bundle is
deployed.

### BREAKING: the four frozen contract schemas use resolver identifiers

The committed schema files stay at the same paths. Their `$id` values move to
the Registry Stack identifier resolver:

| Contract | Old `$id` | New `$id` |
|---|---|---|
| bundle | `https://registrystack.org/schemas/evidence/bundle-v1.json` | `https://id.registrystack.org/schemas/evidence/bundle/bundle.v1.schema.json` |
| runtime | `https://registrystack.org/schemas/evidence/runtime-v1.json` | `https://id.registrystack.org/schemas/evidence/runtime/runtime.v1alpha1.schema.json` |
| verification policy | `https://registrystack.org/schemas/evidence/verification-policy-v1.json` | `https://id.registrystack.org/schemas/evidence/verification-policy/verification-policy.v1.schema.json` |
| holder-bound verification policy | `https://registrystack.org/schemas/evidence/holder-bound-verification-policy-v1.json` | `https://id.registrystack.org/schemas/evidence/holder-bound-verification-policy/holder-bound-verification-policy.v1.schema.json` |

Migration: replace an old `$id` in schema registries, validator allowlists,
cached schema metadata, and editor mappings with the corresponding new value.
For a Registry Stack deployment project, rerun `python3 editors/configure.py
evidence-deployment PROJECT` so the editor mapping reads the current schemas.

### BREAKING: the bundle has an envelope

`evidence.yaml` opens with `apiVersion:
id.registrystack.org/formats/evidence/bundle/v1` and `kind: EvidenceBundle`.
The `version` member is gone and is refused as `config.removed-key`, whose fix
names the two lines; a bundle with neither is refused as
`config.missing-envelope`, and another `kind` as `config.wrong-kind`. The
frozen `bundle.schema.yaml` requires the two members as constants.
`evidencectl` writes them in every bundle it compiles. Migration: in a
hand-written bundle, replace the first line

```yaml
version: 1
```

with

```yaml
apiVersion: id.registrystack.org/formats/evidence/bundle/v1
kind: EvidenceBundle
```

then regenerate the package `SHA256SUMS`, update `package.expectedDigest`
where the runtime file pins it, and re-pin `configurationRevision`. A bundle
`evidencectl` compiles needs only `evidencectl build` with this release.

### BREAKING: the runtime file names its format under id.registrystack.org

The runtime file declares `apiVersion:
id.registrystack.org/formats/evidence/runtime/v1alpha1`. The earlier value
`registry.registrystack.org/evidence-runtime/v1alpha1` is refused as
`config.retired-api-version` at `/apiVersion`, whose fix names the new value;
`kind: EvidenceRuntimeConfig` is unchanged. `evidencectl target new` applies
the same rule to the `runtime` member of a target settings file and writes the
new value in every runtime file it renders. Migration: replace the
`apiVersion` line of `runtime.yaml`, and of the `runtime` member of each
`targets/<name>/settings.yaml` an authoring project keeps. No other member
moves, and the bundle and `configurationRevision` are untouched by this
change.

### The secret members are typed as `SecretReference`

Not breaking. The bundle and runtime schemas name the definition every
`...Ref` member references `SecretReference`, the name every other Registry
Stack schema uses, in place of `secret-ref`. The grammar is the same
(`secret:file/name` or `secret:env/NAME`), the reader already decoded these
members with the shared type, and no file changes. A tool that referenced
`#/$defs/secret-ref` in `bundle.schema.yaml` or `runtime.schema.yaml`
references `#/$defs/SecretReference` instead.

### BREAKING: a code list has an envelope, a type, and camelCase members

A file under `codelists/` opens with `apiVersion:
id.registrystack.org/formats/evidence/codelist/v1alpha1` and `kind:
EvidenceCodelist`, names its identifier `uri` where it wrote `id`, states its
form with `type: code-list` or `type: mapping`, and spells the outputs of a
mapping `allowedOutputs`. A file without the envelope is refused as
`config.missing-envelope`, whose fix names the two lines; `id` and
`allowed_outputs` are refused as `config.removed-key`, each naming its
replacement; a missing or unknown `type` is refused by the shared reader, and
a member of the other form as `config.unknown-key`.
`evidence.codelist.invalid-form` is no longer reported: the `type` member
decides the form. The code list schema describes the two forms under `oneOf`.
`evidencectl` writes the new form in every code list it compiles. Migration,
for each hand-written code list:

```yaml
id: urn:example:codelist:regions
version: "1"
entries: {SOURCE-A: REGION-NORTH}
allowed_outputs: [REGION-NORTH]
```

becomes

```yaml
apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1
kind: EvidenceCodelist
uri: urn:example:codelist:regions
version: "1"
type: mapping
entries: {SOURCE-A: REGION-NORTH}
allowedOutputs: [REGION-NORTH]
```

and a file that lists `codes` takes `type: code-list`. Then regenerate the
package `SHA256SUMS`, update `package.expectedDigest` where the runtime file
pins it, and re-pin `configurationRevision`. The identifier and version a
bundle names a code list by, and the values a derivation reads from it, are
unchanged.

### BREAKING: a code list identifier holds no whitespace and no control character

A code list keeps its `uri` as written, and the URI parser that checks it
reads past a space or control character at either end and a tab or line break
anywhere. The identifier a file declared and the URI that was checked could
therefore differ. An identifier holding a whitespace or control character is
now refused with `config.invalid-value` at `/uri`, and the code list schema
refuses the same characters. A `bucketScheme` never accepted such a
character, so no member that cites a code list changes.

The limit of 512 is counted in characters, as the schema states it with
`maxLength`. It was counted in bytes, so an identifier written outside ASCII
was refused before it reached 512 characters. A `bucketScheme` that cites a
code list by its identifier is held to the same 512-character bound.

Migration: remove the character from the identifier, then regenerate the
package `SHA256SUMS`, update `package.expectedDigest` where the runtime file
pins it, and re-pin `configurationRevision`.

### BREAKING: URI and code list version bounds count characters

Bundle URI validation and client profile URI identities now count Unicode
characters, matching the frozen Version 1 `uri` schema's `maxLength: 512`.
A URI of at most 512 characters that takes more than 512 bytes is accepted;
513 characters are refused. Code list versions likewise count 1 through 128
characters and now refuse control characters. Their authoring schema states
that refusal. The frozen Version 1 schemas are unchanged.

Migration: remove control characters from code list versions, then regenerate
package `SHA256SUMS`, update `package.expectedDigest` where pinned, and re-pin
`configurationRevision`. No spelling change is needed for a valid multibyte
URI or version. Request preparation retains its existing identifier bounds.

### BREAKING: the two verification policy files have an envelope

The policy file `evidence verify --policy` reads opens with `apiVersion:
id.registrystack.org/formats/evidence/verification-policy/v1` and `kind:
EvidenceVerificationPolicy`; the one `evidence verify-presentation --policy`
reads opens with `apiVersion:
id.registrystack.org/formats/evidence/holder-bound-verification-policy/v1`
and `kind: EvidenceHolderBoundVerificationPolicy`. Both contracts require the
two members as constants. `evidence check-policy` refuses a file without them
as `config.missing-envelope`, whose fix names the two lines, and a file of
the other kind as `config.wrong-kind`; the two verify commands report their
closed `malformed` class, as before. Migration: add the two lines at the top
of every retained policy file. No other member moves.

The Rust, Node.js, and Python clients return the same complete document in a
prepared request's `policyDocument` (`policy_document` in Python), in each
prepared batch policy, and under `verificationPolicy` in a retained context.
Each document writes `apiVersion` and `kind` first. A retained context keeps
its `registry.evidence-client.retained-verification/v1` schema marker and
refuses a policy without the envelope. Prepare a fresh context with the
updated client. With independently pinned subject expectations, write its
`verificationPolicy` directly to a standalone CLI policy file. A first-use
draft retains its existing empty `expectedSubjects` and is not a standalone
CLI policy. Applications supply prepare options as before, and verification
decisions do not change.

Rust callers constructing `EvidenceVerificationPolicyDocument` or
`HolderBoundPresentationPolicyDocument` with a struct literal must supply the
required typed `api_version` and `kind` fields. `Default::default()` selects
each field's only supported value.

### BREAKING: a request's bounds are `attemptTimeoutMilliseconds` and `maximumConcurrency`

In the bundle, a source's `request.timeoutMilliseconds` is
`request.attemptTimeoutMilliseconds`, and `request.concurrencyLimit` and a
source connection's `concurrencyLimit` are `maximumConcurrency`, on both the
fixed HTTP request and the SQLite statement request. The values, their bounds
(1 to 30,000 milliseconds, 1 to 256), and what they bound are unchanged. The
old keys are refused as `config.removed-key` at the member, with the
replacement named. Migration: rename the keys and keep the values, in
`evidence.yaml`, in every authored `sources/*.yaml`, and under
`sourceConnections` in every target `settings.yaml`; then regenerate the
package `SHA256SUMS`, update `package.expectedDigest` where the runtime file
pins it, and re-pin `configurationRevision`.

| Old key | New key |
|---|---|
| `sources.<id>.request.timeoutMilliseconds` | `sources.<id>.request.attemptTimeoutMilliseconds` |
| `sources.<id>.request.concurrencyLimit` | `sources.<id>.request.maximumConcurrency` |
| `sourceConnections.<id>.concurrencyLimit` | `sourceConnections.<id>.maximumConcurrency` |

### BREAKING: the runtime file spells `audit.retentionDays` and `signer.attemptTimeoutMilliseconds`

In the runtime file, `audit.retainDays` is `audit.retentionDays` and the
Transit signer's `timeoutMilliseconds` is `attemptTimeoutMilliseconds`. The
values, bounds, and defaults are unchanged (1 to 36,500 days, 90 by default;
1 to 30,000 milliseconds). The old keys are refused as `config.removed-key`
with the replacement named, and a retention period written beside
`destination: stdout` is refused as `evidence.runtime.invalid-audit` at
`/audit/retentionDays`. Migration: rename the two keys in `runtime.yaml` and
under the `runtime` member of every target `settings.yaml`; keep the values.

| Old key | New key |
|---|---|
| `audit.retainDays` | `audit.retentionDays` |
| `signer.timeoutMilliseconds` | `signer.attemptTimeoutMilliseconds` |

### BREAKING: the bundle unions are tagged by `type`

Each bundle union that carried a tag names it `type`, the tag CFG-ID-7
gives every Registry Stack union. A source's `transport`, an
authentication's `kind`, a path binding's `from`, a statement parameter
binding's `kind`, and an acquisition's `kind` are each `type`; the values and
the members beside them are unchanged. The old tags are refused as
`config.removed-key` at the member, with `type` named. The conditions the
grammar hangs on a tag move with it: a production bundle still refuses
`authentication.type: none` on a source and on a source connection.
Migration: rename the five tags and keep the values, in `evidence.yaml`, in
every authored `sources/*.yaml`, and under `sourceConnections` in every
target `settings.yaml`; then regenerate the package `SHA256SUMS`, update
`package.expectedDigest` where the runtime file pins it, and re-pin
`configurationRevision`. An authored source file keeps its envelope `kind:
EvidenceSource` and states the source's variant in `type` beside it.

| Old key | New key |
|---|---|
| `sources.<id>.transport` | `sources.<id>.type` |
| `sources.<id>.authentication.kind` | `sources.<id>.authentication.type` |
| `sourceConnections.<id>.authentication.kind` | `sourceConnections.<id>.authentication.type` |
| `sources.<id>.request.pathBindings.<name>.from` | `sources.<id>.request.pathBindings.<name>.type` |
| `sources.<id>.request.parameterBindings.<name>.kind` | `sources.<id>.request.parameterBindings.<name>.type` |
| `requirements[].acquisition.kind` | `requirements[].acquisition.type` |

### BREAKING: the access-token key source is tagged by `type`

`authentication.oidc.jwksSource` names its variant in `type`, the tag the
shared key source block carries in every Registry Stack product. Evidence
still reads access-token keys from one variant only, `uri`, and the `uri`
member beside the tag is unchanged. The old tag is refused as
`config.removed-key` at `/authentication/oidc/jwksSource/kind`, with `type`
named. Migration: rename the key and keep the value, in `evidence.yaml`, in
every target `governance.yaml`, and in the governance part of every authored
target `settings.yaml`; then regenerate the package `SHA256SUMS`, update
`package.expectedDigest` where the runtime file pins it, and re-pin
`configurationRevision`. A local target that leaves the key source to
`evidencectl` has nothing to rename.

| Old key | New key |
|---|---|
| `authentication.oidc.jwksSource.kind` | `authentication.oidc.jwksSource.type` |

`jwksSource: {kind: uri, uri: https://issuer.example/jwks}` becomes
`jwksSource: {type: uri, uri: https://issuer.example/jwks}`.

### BREAKING: the runtime signer is tagged by `type`

In the runtime file, `signer.kind` is `signer.type`; the values `local-jwk`
and `transit` and the members beside them are unchanged. The old tag is
refused as `config.removed-key` at `/signer/kind` with `signer.type` named,
and a signer that does not match the bundle's assurance profile is reported
at `/signer/type`. Migration: rename the key in `runtime.yaml` and under the
`runtime` member of every target `settings.yaml`; keep the value.

| Old key | New key |
|---|---|
| `signer.kind` | `signer.type` |

### BREAKING: the bundle states its two admission gates

`authentication.oidc.allowedClients` and `authentication.oidc.requiredScopes`
are required in every bundle. Each takes the keyword `unrestricted` or a list
of at least one value. An omitted member used to mean "no gate": every
issuer-vouched client was admitted, or no scope was required. That choice is
now written. An omitted member is refused as `config.missing-key`, and an
empty list or any other scalar as `config.invalid-value` at the member, with
the keyword named and no written value repeated. A bundle with a task-grant
authority profile must list its clients: `unrestricted` is refused there, as
an omitted list was before.

`authentication.oidc.assertionIssuers` is unchanged: it only narrows tokens
that carry an exchanged authority, it takes no keyword, and the format
registry records its omission as open.

Migration: under `authentication.oidc` of `evidence.yaml`, of each target
`governance.yaml`, and of the governance part of each authored target
`settings.yaml`, add the member that is absent. Write `unrestricted` to keep
today's behavior, or list the admitted values. A list already written stays as
it is; an empty list becomes `unrestricted` or a real list. Then regenerate
`SHA256SUMS`, update `package.expectedDigest` where the runtime file pins it,
and re-pin `configurationRevision`. `evidencectl build` and `evidencectl dev`
write both members.

| Member | Before | After |
|---|---|---|
| `authentication.oidc.allowedClients` | optional; omitted admits every issuer-vouched client | required; `unrestricted` or a list of 1 to 32 client identifiers |
| `authentication.oidc.requiredScopes` | optional; omitted requires no scope | required; `unrestricted` or a list of 1 to 32 scope tokens |

Security review note. Threat: a bundle that omits a gate, or whose gate was
emptied by a bad edit or a template, admits every client the issuer vouches
for or drops the scope gate, and nothing in the file shows it. Enforcement
point: the bundle reader, when the file is decoded, before `evidence check`
passes and before the runtime starts. Refusal: `config.missing-key` for the
omission, `config.invalid-value` for an empty list or another scalar, at
`/authentication/oidc/<member>`. Negative test:
`the_admission_gates_are_required_and_unrestricted_is_explicit` in
`crates/registry-evidence/src/config.rs`.

### BREAKING: the client profile and the reviewed contracts file have an envelope

A client profile opens with `apiVersion:
id.registrystack.org/formats/evidence/client-profile/v1` and `kind:
EvidenceClientProfile`, and a reviewed contracts file with `apiVersion:
id.registrystack.org/formats/evidence/client-contracts/v1` and `kind:
EvidenceClientContracts`, each in place of its `schema` header. The private
key reference of a profile is tagged by `type`, as the `trust` and
`contracts` members beside it already are; the values `file` and
`environment` and the members beside the tag are unchanged.

| File | Old | New |
|---|---|---|
| client profile | `schema: registry.evidence-client-profile/v1` | `apiVersion: id.registrystack.org/formats/evidence/client-profile/v1` and `kind: EvidenceClientProfile` |
| client profile | `privateKey.source` | `privateKey.type` |
| reviewed contracts | `schema: registry.evidence-client-contracts/v1` | `apiVersion: id.registrystack.org/formats/evidence/client-contracts/v1` and `kind: EvidenceClientContracts` |

The old header is refused as `config.removed-key` at `/schema` with the two
members named, and the old tag as `config.removed-key` at
`/privateKey/source` with `privateKey.type` named. A file with neither
member is refused as `config.missing-envelope`, one whose `kind` names
another format as `config.wrong-kind` at `/kind`, and one whose `apiVersion`
is another's as `config.unsupported-api-version` at `/apiVersion`. `evidencectl check
--file` names both formats by `kind`; a file that still opens with the old
header is handed to its own reader, so it gets the same refusal and not
`evidence.check.unknown-format`.

`evidencectl client init` writes the new profile, and `evidencectl client
contracts fetch` and the SDK contract candidate write the new contracts
form. In the Rust SDK, `EvidenceClientProfile`, `ReviewedContracts`, and
`EvidenceClientContracts` carry `api_version` and `kind` in place of
`schema`, serialized as `apiVersion` and `kind`; the constants
`EVIDENCE_CLIENT_PROFILE_SCHEMA_V1` and `EVIDENCE_CLIENT_CONTRACTS_SCHEMA_V1`
are replaced by `EVIDENCE_CLIENT_PROFILE_API_VERSION` and
`EVIDENCE_CLIENT_CONTRACTS_API_VERSION`, and the two `..._KIND` constants are
exported from the profile module. The Node.js and Python bindings take the
same JSON, so a profile object an application builds in code changes the same
way. The generated schemas state the envelope and the `type` tag.

Migration: in every client profile, replace the `schema` line with the two
envelope members and rename `privateKey.source` to `privateKey.type`; in
every reviewed contracts file, replace the `schema` line with the two
envelope members, or write the file again with `evidencectl client contracts
fetch` and review it. A Base Registry Engine project that keeps a reviewed
contracts file as `evidence/contracts.json` changes that file the same way
and rebuilds its package. No signed, HTTP, or stored form changes: the
definitions document the service publishes keeps its
`registry.evidence-definitions/v1` header.

### BREAKING: the key of an id-keyed map is a local identifier

The bundle and the runtime file held the names an operator chooses to two
grammars of their own: up to 128 characters with dots for the key of a named
map, and up to 64 with dots for a field name. Every Registry Stack format
writes a local identifier one way (CFG-ID-1): a lowercase letter, then up to
63 lowercase letters, digits, `_`, or `-`. The key of each id-keyed map now
follows it, and the two frozen schemas say so with `propertyNames` naming
`$defs/LocalId`:

| File | Map |
|---|---|
| `evidence.yaml` | `selectorProfiles`, `sourceConnections`, `sources`, `authorityProfiles` |
| `evidence.yaml` | `selectorProfiles.<id>.fields` |
| `evidence.yaml` | `sources.<id>.request.pathBindings`, with the placeholders the request path names |
| `evidence.yaml` | `authorityProfiles.<id>.grants[].subjects[].valueClaims` |
| `evidence.yaml` | `requirements[].derivation.parameters` |
| `runtime.yaml` | `outboundTls.trustProfiles`, `sourceExtracts` |

A key with a dot, or one longer than 64 characters, is refused at the key and
is never repeated in the refusal: in the bundle as the area's rule code
(`evidence.bundle.invalid-source`, `evidence.bundle.invalid-source-connection`,
`evidence.bundle.invalid-selector-profile`,
`evidence.bundle.invalid-authority-profile`, or
`evidence.bundle.invalid-requirement`), in the runtime file as
`evidence.runtime.invalid-outbound-tls` or
`evidence.runtime.invalid-source-extract`. No old spelling is read.

Two kinds of key are another party's spelling and keep it, typed as
`$defs/ExternalId`. The names in `adapterParameters` and in a statement's
`parameterBindings` are what the adapter script or the SQL statement reads,
and keep the parameter grammar: a letter or `_`, then up to 127 letters,
digits, `.`, `_`, or `-`. A key of `authentication.oidc.assertionIssuers` is a
client identifier as its issuer writes it, 1 through 128 bytes; one with a
control character is now refused as `evidence.bundle.invalid-authentication`.

The places that name one of these keys keep their own, wider grammar and are
not part of this change: a requirement `handle`, a subject role, a requester
tag, a statement column name, and every reference to a map key, such as
`acquisition.source`, `selectorProfile`, `tlsTrustProfile`, and
`extractProfile`. A reference to a renamed key changes with it. The public
request, the signed response, and the audit record still accept the wider
spelling; what narrows is only which names a bundle may define.

Migration: rename every key of the maps above that has a dot or more than 64
characters, and every reference to it. A selector profile name and a field
name are also what a relying party writes in its request, and a source name is
what the audit record carries, so a rename is coordinated with the callers and
with any verification policy that pins the profile. Then regenerate
`SHA256SUMS`, update `package.expectedDigest`, and re-pin
`configurationRevision`. In `runtime.yaml`, rename the same way and keep each
name equal to the bundle's `tlsTrustProfile` or `extractProfile` reference. An
authored project compiles `local-subject-<question>-v1`,
`local-subject-<question>-<role>-v1`, and `local-source-<question>`: the
authoring form refuses the names that would not fit, as "BREAKING: a question
refuses the names its bundle would refuse" below states.

### BREAKING: the issuer and each concept name their URI as `uri`

In a Registry Stack file a member named `id` is a local identifier
(CFG-ID-1). The bundle's `issuer.id` and each `requirements[].concepts[].id`
hold a URI, so both are now `uri`, the name the question format and the code
list already give a URI. The values, their rules, and the members beside
them are unchanged: the issuer URI is still what an assertion carries as
`issuedBy`, and a concept URI what it names as `providesValueFor`. The old
keys are refused as `config.removed-key` at the member, with `uri` named. A
rule that refuses the value now reports it at the new key
(`evidence.bundle.invalid-issuer` at `/issuer/uri`, a repeated concept URI
at the concept's `uri`). A requirement's own URI is renamed by the next
item. Migration: rename
the two keys and keep the values, in `evidence.yaml`, in every target
`governance.yaml`, and in the governance part of every authored target
`settings.yaml`; then regenerate the package `SHA256SUMS`, update
`package.expectedDigest` where the runtime file pins it, and re-pin
`configurationRevision`. `evidencectl build` writes the new keys for a
compiled bundle.

| Old key | New key |
|---|---|
| `issuer.id` | `issuer.uri` |
| `requirements[].concepts[].id` | `requirements[].concepts[].uri` |

### BREAKING: a requirement names its URI as `uri`

Each `requirements[].id` holds the requirement URI a request names, not a
local identifier (CFG-ID-1), so it is now `requirements[].uri`, as the issuer
and the concepts already are. The value and its rules are unchanged. What a
relying party sends and receives is unchanged too: a request still names the
requirement in its `requirement` member, the definitions document still
lists each definition under `id`, and an assertion still carries the URI as
`supportsRequirement`. The old key is refused as `config.removed-key` at the
member, with `uri` named, and a requirement without the member as
`config.missing-key`. Two requirements with the same URI are refused as
`config.duplicate-id` at the second one's `uri`, with the first one's `uri`
as a related position. Migration: rename the key and keep the value in every
entry of `requirements` in `evidence.yaml`; then regenerate the package
`SHA256SUMS`, update `package.expectedDigest` where the runtime file pins
it, and re-pin `configurationRevision` wherever a relying party or a
verification policy pins it, because the revision covers the bundle's own
spelling. `evidencectl build` writes the new key for a compiled bundle.

| Old key | New key |
|---|---|
| `requirements[].id` | `requirements[].uri` |

### BREAKING: a concept states its value form as `type`

A concept's value form selects which `constraints` keys it must declare, so
it is the tag of a union, and every union in a Registry Stack file is tagged
by `type` (CFG-ID-7). Each `requirements[].concepts[].form` is now
`requirements[].concepts[].type`. The twelve values, the constraints each
one fixes, and the members beside it are unchanged, and so is every
published form: the definitions document, a relying party's expected
outputs, a verification policy, and a fact contract a source declares under
`sources.<id>.evidence.contract` keep `form`. The old key is refused as
`config.removed-key` at the member, with `type` named. Migration: in
`evidence.yaml`, rename `form` to `type` under every entry of every
requirement's `concepts` and keep the value; then regenerate the package
`SHA256SUMS`, update `package.expectedDigest` where the runtime file pins
it, and re-pin `configurationRevision`. `evidencectl build` writes the new
key for a compiled bundle, and an authored question already writes
`answers[].type`.

| Old key | New key |
|---|---|
| `requirements[].concepts[].form` | `requirements[].concepts[].type` |

### BREAKING: a client assertion key is its own authentication type

`type: oauth2-client-credentials` held two forms told apart only by which
members were present: a shared client secret, or a signed client assertion.
A union is told apart by its `type` (CFG-ID-7), so each form is now its own
type. `oauth2-client-credentials` is the shared-secret form and requires
`clientSecretRef` and `credentialPlacement`. `oauth2-private-key-jwt` is the
RFC 7523 section 2.2 form and requires `clientAssertionKeyRef`, with the
optional `clientAssertionAudience`. `tokenEndpoint`, `clientIdRef`, `scope`,
`audience`, `resource`, `maximumCacheSeconds`, and `assumedLifetimeSeconds`
are the same under both, and the token request the runtime sends is
unchanged. `clientAssertionKeyRef` or `clientAssertionAudience` under any
other type is refused as `config.unknown-key` at the key, and the fix names
`oauth2-private-key-jwt`. Migration: wherever an `authentication` mapping
carries `clientAssertionKeyRef`, change its `type` from
`oauth2-client-credentials` to `oauth2-private-key-jwt` and keep every other
member: under `sources.<id>` and `sourceConnections.<id>` of `evidence.yaml`,
in an authored `sources/*.yaml`, and in the `sourceConnections` of an
authored target `settings.yaml`. A source with a client secret changes
nothing. Then regenerate the package `SHA256SUMS`, update
`package.expectedDigest` where the runtime file pins it, and re-pin
`configurationRevision`. `evidencectl source add` writes the new type.

| Written | Old | New |
|---|---|---|
| `authentication.type` beside `clientAssertionKeyRef` | `oauth2-client-credentials` | `oauth2-private-key-jwt` |
| `authentication.type` beside `clientSecretRef` | `oauth2-client-credentials` | `oauth2-client-credentials` |

### BREAKING: a request states one `path`, a literal or a template

A source request named its path in one of two members, `path` for a literal
and `pathTemplate` for a path with placeholders, and nothing but which
member was present told the two forms apart. The request now has one
required `path`. A path that names a placeholder, `{name}` as a complete
segment, is a template and requires `pathBindings` with one binding for each
placeholder; a path without one is a literal and takes no `pathBindings`. A
literal path never admitted `{` or `}`, so no path that loaded before changes
its meaning. The placeholder grammar, the bindings, the expansion, and the
request the runtime sends are unchanged. `path` is 2 to 2048 bytes in both
forms, the bound the template already had. `pathTemplate` is refused as
`config.removed-key` at the member, with `path` named. Migration: in
`evidence.yaml`, rename `request.pathTemplate` to `request.path` under every
entry of `sources` and keep the value and the `pathBindings`; do the same in
every authored `sources/*.yaml`; then regenerate the package `SHA256SUMS`,
update `package.expectedDigest` where the runtime file pins it, and re-pin
`configurationRevision`. `evidencectl build` writes `path` for a compiled
bundle, and `evidencectl suggest` drafts a templated operation as `path`.

| Old key | New key |
|---|---|
| `sources.<id>.request.pathTemplate` | `sources.<id>.request.path` |

### BREAKING: the batch ceiling is `maximumHolderBoundBatchSize` in the bundle

A bound is written `maximum<Noun>` (CFG-NAME-3), so the ceiling on how many
assertions one holder-bound release may carry is now
`maximumHolderBoundBatchSize`. The value, its range of 1 through 16, and
the meaning of omission (one) are unchanged. An Evidence source pins a
definitions document under `sources.<id>.evidence.contract`, which names the
ceiling the same way. The old key is refused as `config.removed-key` at the
member, in both places, with the new name. Migration: rename the key and
keep the value in `evidence.yaml`; a bundle that declares no ceiling has
nothing to rename. Then regenerate the package `SHA256SUMS`, update
`package.expectedDigest` where the runtime file pins it, and re-pin
`configurationRevision` wherever a relying party or a verification policy
pins it, because the revision covers the bundle's own spelling.

| Old key | New key |
|---|---|
| `holderBoundBatchMaxSize` | `maximumHolderBoundBatchSize` |
| `sources.<id>.evidence.contract.holderBoundBatchMaxSize` | `sources.<id>.evidence.contract.maximumHolderBoundBatchSize` |

Security review note: this changes how a bundle is read.

- Threat: a bundle written for the earlier grammar is loaded with its
  ceiling silently read as one, or a wider ceiling is taken from a member
  the operator did not review.
- Enforcement point: `EvidenceConfig::parse_yaml`, through the shared
  reader's removed-key table and the closed bundle mapping.
- Refusal: `config.removed-key` at `/holderBoundBatchMaxSize` and at
  `/sources/<id>/evidence/contract/holderBoundBatchMaxSize`. No diagnostic
  repeats the value.
- Negative test: `the_batch_ceiling_is_a_maximum_and_the_old_name_is_refused`.

### BREAKING: the definitions document publishes `maximumHolderBoundBatchSize`

The `registry.evidence-definitions/v1` document an Evidence deployment
serves at `GET /v1/evidence/definitions` publishes the same ceiling, under
the same new name. This is a change to what a relying party reads over
HTTP, not to a file: the schema identity is kept, the member is renamed,
and nothing reads both spellings.

| Old member | New member |
|---|---|
| `holderBoundBatchMaxSize` (definitions document, OpenAPI `EvidenceDefinitions`) | `maximumHolderBoundBatchSize` |
| `holder_bound_batch_max_size` (Rust `EvidenceDefinitionsDocument`, `EvidenceDefinitions`) | `maximum_holder_bound_batch_size` |

- `registry-evidence-client`, its Node.js and Python bindings, the unified
  client packages, `evidence-oid4vci`, and `evidencectl doctor` read the new
  member. A document that carries the old member is refused, the way any
  unknown member of that document is refused: the client reports its
  protocol failure and prepares no request. A document that carries neither
  is still read as a ceiling of one.
- A client built before this release refuses the new member for the same
  reason, so there is no interoperation window. Migration: upgrade Evidence
  Gateway and every client, binding, and protocol adapter that reads its
  definitions response in one step. Code of your own that reads the
  document renames the member. The Node.js and Python bindings hand the
  document to their caller as parsed JSON and declare no typed member for
  the ceiling, so a caller that reads it from that object renames it there.
- A signed assertion, an SD-JWT VC, and an audit record never carried the
  member and are unchanged. The OID4VCI metadata `evidence-oid4vci`
  publishes keeps the specification's `batch_credential_issuance.batch_size`.

### BREAKING: a concept's `form` is a mapping named by `type`

A union names its variant in one shape (CFG-ID-7). The `form` of a concept
was a bare name for seven of its variants and a single-key mapping for the
eighth, which is neither accepted shape. It is now a mapping tagged by `type`
for every variant, with the list's members beside the tag, in each file that
carries it: the fact contract a bundle pins under
`sources.<id>.evidence.contract`, a verification policy file, a holder-bound
verification policy file, and a reviewed client contracts file. The names of
the forms, the list's members, and their bounds are unchanged.

| Old form | New form |
|---|---|
| `form: boolean` | `form: {type: boolean}` |
| `form: integer` | `form: {type: integer}` |
| `form: string` | `form: {type: string}` |
| `form: date-bucket` | `form: {type: date-bucket}` |
| `form: time-bucket` | `form: {type: time-bucket}` |
| `form: entity-reference` | `form: {type: entity-reference}` |
| `form: structured` | `form: {type: structured}` |
| `form: {list: {items: string, minimumItems: 1, maximumItems: 8, unique: true}}` | `form: {type: list, items: string, minimumItems: 1, maximumItems: 8, unique: true}` |

Nothing reads both shapes. In a bundle and in either policy file:

| Written | Refusal |
|---|---|
| a bare name, `form: boolean` | `config.invalid-type` at the `form` |
| the list's members under `list` | `config.missing-key` at the `form`, naming `type`, and `config.removed-key` at `form/list`, naming the shape to write |
| a mapping without `type` | `config.missing-key` at the `form` |
| a `type` that names no form | `config.unknown-variant` at `form/type`, naming the eight forms |
| a member its `type` does not carry, such as `unique` beside `type: boolean` | `config.unknown-key` at the member |

A requirement's own concept keeps `type` directly beside its `constraints`:
there the concept is the mapping the tag selects the members of, and in a
contract or a policy the tag sits one level down, inside `form`. `type` is the
tag in both places.

Migration:

- `evidence.yaml`: rewrite each form under `sources.<id>.evidence.contract`
  as the table shows. The seven memberless forms gain the mapping and the
  tag; in a list form the members also move up one level. Then regenerate
  the package `SHA256SUMS`, update `package.expectedDigest` where the runtime
  file pins it, and re-pin `configurationRevision` wherever a relying party or
  a verification policy pins it. A bundle that pins no Evidence source has
  nothing to rewrite.
- A verification policy or holder-bound verification policy file: rewrite the
  `form` of each `expectedOutputs` entry by hand, as in the table. A list form
  that omits both `items` and `unique` keeps omitting both.
- A reviewed contracts file (`evidence.contracts.json`, and
  `evidence/contracts.json` of a Base Registry Engine project): write it again
  with `evidencectl client contracts fetch` against the upgraded deployment
  and review it, or rewrite each concept's `form` as in the table.

Security review note: this changes how a bundle and a verification policy are
read.

- Threat: a form written for the earlier grammar is read as another form, or
  a member beside it is ignored, so a verifier accepts a value shape the
  reviewer did not expect or a source's pinned contract differs from the one
  reviewed.
- Enforcement point: `EvidenceConfig::parse_yaml` for the bundle and the
  policy readers of `crates/registry-evidence/src/verification_policy.rs`,
  through the shared reader's tagged union and removed-key table;
  `ExpectedFormDocument` in `registry-evidence-verifier` and
  `DefinitionConceptForm` in `registry-evidence-client` for a document or an
  object that reaches them as JSON. Every variant refuses a member it does
  not declare.
- Refusal: the codes in the table above for a file; a JSON document or policy
  object in the old shape fails to parse and nothing is verified or
  requested. No diagnostic repeats a value from the file.
- Negative tests: `a_pinned_concept_form_is_named_by_type_and_the_old_shapes_are_refused`
  (bundle); `the_holder_bound_policy_refuses_the_untagged_form`,
  `a_list_form_under_the_removed_list_member_names_the_shape_to_write`, and
  `an_unknown_form_names_the_accepted_forms` (policy files);
  `an_untagged_expected_form_is_refused` and
  `an_expected_form_refuses_what_its_variant_does_not_declare` (verifier);
  `an_untagged_concept_form_is_refused` and
  `a_concept_form_refuses_what_its_variant_does_not_declare` (client).

### BREAKING: the definitions document and the policy object carry the tagged `form`

The same union travels in two places that are not files, and both take the
shape of the table above:

- The `registry.evidence-definitions/v1` document served at
  `GET /v1/evidence/definitions` publishes each concept's `form` as
  `{"type": "boolean"}` or
  `{"type": "list", "items": "string", "minimumItems": 1, "maximumItems": 8, "unique": true}`.
  The schema identity is kept. `registry-evidence-client`, its Node.js and
  Python bindings, the unified client packages, `evidence-oid4vci`, and
  `evidencectl` read the new shape and refuse the old one as a protocol
  failure; a client built before this release refuses the new shape. There is
  no interoperation window, the same as for `maximumHolderBoundBatchSize`
  above: upgrade Evidence Gateway and every client, binding, and protocol
  adapter that reads its definitions response in one step.
- The verification policy object an application hands to a client library
  states each expected output's `form` the same way: `expectedOutputs` in
  Node.js, `expected_outputs` in Python, `ExpectedFormDocument` in Rust. The
  bindings type the entry as an open record, so no typing changes, and an
  entry in the old shape is refused when the policy is prepared. Code that
  builds the object, or derives it from a definitions document, writes
  `{type: 'boolean'}` where it wrote `'boolean'`.

The Rust types keep their variants (`DefinitionConceptForm::Scalar` and
`List`, `ExpectedFormDocument::Scalar` and `List`), so code that matches on
them compiles unchanged; only the written form moved.

A signed assertion, an SD-JWT VC, and an audit record never carried this
union and are unchanged, so a verifier keeps accepting what a running issuer
signs. The `form` member of a signed public value, such as
`{"form": "date-bucket", "scheme": ..., "bucket": ...}`, is a different
member and keeps its shape.

### BREAKING: a question refuses the names its bundle would refuse

The key of an id-keyed map in the bundle is a local identifier, so an authored
question could pass `evidencectl check` and then compile to a bundle the
reader refused, with a refusal that named a key of the compiled bundle and not
the member the author wrote. The authoring check now refuses each such name at
its own member, with the file, line, and column, and the language server
reports the same finding in the editor. The check runs after every other rule
of the form.

| Member of a question file | Refused | Code |
|---|---|---|
| `id`, when the question reads an `operation` and has one subject | over 47 bytes: the selector profile is named `local-subject-<id>-v1` | `evidence.question.compiled-name-length` |
| a subject `role`, when the question reads an `operation` and has several subjects | `id` and `role` over 46 bytes together: the selector profile is named `local-subject-<id>-<role>-v1` | `evidence.question.compiled-name-length` |
| a subject `role`, when the question reads an `operation` and has several subjects | a dot | `evidence.question.compiled-name-dot` |
| a subject `selector` | a dot: it is a selector field of the compiled profile | `evidence.question.compiled-name-dot` |
| a subject `profile`, and each entry of `profiles` | a dot: it is a key of `selectorProfiles` | `evidence.question.compiled-name-dot` |
| `source.ref` | a dot: it is a key of `sources` | `evidence.question.compiled-name-dot` |

The source of such a question, `local-source-<id>`, is shorter than its
selector profile, so the profile's bound covers it. A question with a
`source.ref` compiles no name from its `id`, which keeps the form's 64 bytes.
A `role` keeps the dot where it enters no compiled name: the one subject of a
question, and every subject of a question with a `source.ref`. `purpose`, a
fact `name`, and an answer `concept` keep the dot. The names of the files
under `selectors/` and `sources/`, and the names a governance file carries
into the bundle, are still checked where the bundle is checked. No finding
repeats a name from the file.

A project with one of these names already failed, at the bundle check that
follows the compile, so no project that built before stops building; the
refusal moves earlier and to the authored member. Migration: shorten the
question `id` or the `role`, or replace the dot, in the question file; rename
`questions/<id>.yaml` and its derivation and fixtures with a changed `id`; and
tell the callers of a renamed selector, profile, or question.

An access policy under `access/policies/` compiles to an authority profile
that was named by the policy's whole requester tag, 74 characters, which the
bundle's 64 refuse: `evidencectl dev` and a local target with an access policy
could not start. The profile is now named `policy-v1-` or `policy-v2-` and the
first 32 hexadecimal digits of the tag's digest, 42 characters. The requester
tag a caller is matched on is unchanged and stays whole in the profile's
`requesterTags`, so no token, client, or policy file changes. A running
`evidencectl dev` session rebuilds its bundle at the next start.

Security review note. Threat: a name that reaches the compiled bundle under a
grammar the reader refuses stops the build after the author's files were
accepted, and an authority profile named by a key the reader refuses leaves a
local runtime with access policies unable to start. The profile name carries
no authority: the runtime matches a caller on `requesterTags`, which is
unchanged, and the compiler refuses two policies whose profile names agree
instead of letting one replace the other.
Enforcement point: `validate_question` in
`crates/registry-evidence-authoring/src/validate.rs`, before the compile, and
the bundle reader after it. Refusal: `evidence.question.compiled-name-length`
and `evidence.question.compiled-name-dot` at the authored member. Negative
tests: `crates/registry-evidence-authoring/tests/compiled_names.rs`, one per
refused shape; `an_access_policy_names_its_authority_profile_with_a_local_identifier`
in `crates/registry-evidencectl/src/authoring.rs`.

### Diagnostic codes changed by the stable move

These refusals were already made; the code, or where stated only the
position, moved to the shared reader's. A script that matches on the old code matches
on the new one. No file changes.

| Condition | Old code | New code |
|---|---|---|
| a bundle requirement repeats the `uri` of an earlier requirement | `evidence.bundle.invalid-requirement` at the copy's `id` | `config.duplicate-id` at the copy's `uri`, with the first requirement's `uri` as a related position |
| the bundle, a code list, or a fixture file in the package is larger than 1 MiB | `evidence.package.too-large` at the package directory | `yaml.too-large` at the file; another package file over a package bound keeps `evidence.package.too-large` |
| a package entry the bundle names is a symbolic link or another entry that is no regular file | `evidence.package.unsafe-entry` at the package directory | the same code at each bundle member that names the entry, with the line and column of the value; an entry no bundle member names stays at the package directory |
| a requirement's derivation parameter is an integer outside the safe integers, or a list concept's `minimumItems` or `maximumItems` is outside 1 to 64 | `evidence.bundle.invalid-requirement` at the requirement | `config.out-of-range` at the value |
| an OAuth source authentication declares both credential forms, neither, a client secret without `credentialPlacement`, or `clientAssertionAudience` beside a client secret | `evidence.bundle.invalid-source` or `evidence.bundle.invalid-source-connection` at the source or connection | `config.missing-key` at the `authentication` mapping for a member its `type` requires, `config.unknown-key` at a member its `type` does not carry |
| a source request declares neither `path` nor `pathTemplate` | `evidence.bundle.invalid-source` at the source | `config.missing-key` at the `request` mapping, naming `path` |

## Protocol words

A protocol word is a value Evidence itself defines and writes where a caller
or an operator reads it: a problem code, a result word, an error kind, a
reason in a command report. Each one is now spelled in lowercase kebab-case,
the way every value a machine matches is spelled in configuration. Nothing in
this section changes a file: no bundle, runtime file, fixture, package sum,
or `configurationRevision` carries any of these words, so no step is run.
Nothing signed changes either: the assertion payload, an SD-JWT VC, a
holder proof, and the Rhai script interface keep every word they had. A word
an external standard defines (OAuth, OpenID Connect, JOSE, SD-JWT, OID4VCI,
RFC 9457) keeps the standard's spelling.

There is no alias and no window in which both spellings are accepted. Upgrade
Evidence Gateway and every client, binding, protocol adapter, dashboard, and
alert that matches one of these words in one step.

### BREAKING: five problem codes and their type URIs are spelled in kebab-case

The `code` member of an Evidence problem body
(`application/problem+json`, `GET` and `POST` under `/v1`) and the `type` URI
derived from it change for the five codes that carried an underscore. The
other five codes, every status, title, and detail, and the six-member body
are unchanged.

| Status | Old `code` | New `code` |
|---|---|---|
| 400 | `evidence.invalid_request` | `evidence.invalid-request` |
| 400 | `request.selector_invalid` | `request.selector-invalid` |
| 401 | `auth.invalid_credential` | `auth.invalid-credential` |
| 429 | `evidence.rate_limited` | `evidence.rate-limited` |
| 404 | `resource.not_found` | `resource.not-found` |

Each `type` URI is `https://id.registrystack.org/problems/registry-evidence/` followed by a
path, and the path is what changes:

| Old `type` path | New `type` |
|---|---|
| `evidence/invalid_request` | `https://id.registrystack.org/problems/registry-evidence/evidence/invalid-request` |
| `request/selector_invalid` | `https://id.registrystack.org/problems/registry-evidence/request/selector-invalid` |
| `auth/invalid_credential` | `https://id.registrystack.org/problems/registry-evidence/auth/invalid-credential` |
| `evidence/rate_limited` | `https://id.registrystack.org/problems/registry-evidence/evidence/rate-limited` |
| `resource/not_found` | `https://id.registrystack.org/problems/registry-evidence/resource/not-found` |

- The Version 1 problem contract,
  `products/evidence/contracts/problem-contract.yaml`, the generated
  `problem-v1.schema.json`, and the Evidence OpenAPI document state the new
  codes and type URIs.
- The `error` label of `evidence_http_requests_total` carries the
  problem code, so its value changes with it: a query or alert on
  `error="auth.invalid_credential"` matches `error="auth.invalid-credential"`.
- `registry-evidence-client`, its Node.js and Python bindings, and the
  unified client packages register the new codes. A problem body in the old
  spelling is not a registered problem: the client reports its protocol
  failure with no code, never a denial, so a caller cannot mistake an
  unrecognized body for an authorization decision.
- Migration: code of your own that matches `code` or `type` matches the new
  spelling. `EvidenceClientError::Denied` and the bindings' denial errors
  hand the code to their caller as a string, so a comparison there is
  respelled too.

### BREAKING: an unavailable request-batch item is `evidence-not-available`

The `result` member of one item of the `registry.evidence-request-batch/v1`
response (`POST /v1/evidence/batch`) names the closed unavailable outcome
in kebab-case. The envelope is unsigned: each available item still carries
its own flattened JWS, unchanged, and the `evidence` result word is
unchanged.

| Old `result` | New `result` |
|---|---|
| `evidence_not_available` | `evidence-not-available` |

- The Version 1 contract file
  `products/evidence/contracts/request-batch-response.schema.yaml`, the
  generated `evidence-request-batch-response-v1.schema.json`, and the
  Evidence OpenAPI document state the new word. The schema identity
  `registry.evidence-request-batch/v1` is kept.
- `registry-evidence-verifier` owns the item type, so the runtime, the
  client, and both bindings change together. A response whose item carries
  the old word is refused whole, the way any item outside the closed union
  is refused: the client reports its protocol failure and releases no
  member of the batch.
- Migration: code of your own that reads the response matches the new word.
  A caller of the Rust client, the Node.js binding, or the Python binding
  reads the typed unavailable item, whose spelling in each language is
  unchanged.

### BREAKING: five verifier and client error kinds are spelled in kebab-case

`kind()` on `VerificationError`, `EvidenceClientError`, and `NonceError` is
the stable discriminant a caller branches on and a binding carries across
the language boundary: the `kind` attribute of every Node.js and Python
client error, and the `code` of a verification failure. Five of those words
carried an underscore.

| Type | Old kind | New kind |
|---|---|---|
| `registry_evidence_verifier::VerificationError` | `malformed_jws` | `malformed-jws` |
| `registry_evidence_verifier::VerificationError` | `protected_header` | `protected-header` |
| `registry_evidence_verifier::VerificationError` | `key_binding` | `key-binding` |
| `registry_evidence_client::EvidenceClientError` | `not_available` | `not-available` |
| `registry_evidence_client::NonceError` | `not_canonical` | `not-canonical` |

- The other kinds (`key`, `signature`, `payload`, `policy`, `time`,
  `disclosure`, `configuration`, `nonce`, `token`, `transport`, `denied`,
  `protocol`, `verification`, `entropy`) are unchanged.
- The Python binding raises `NotAvailableError` for the new kind, and the
  class names of both bindings are unchanged, so a caller that catches by
  class changes nothing. A caller that compares `error.kind` with
  `"not_available"`, or `error.code` with one of the three verifier words,
  compares with the new spelling.
- Not changed: the values each binding spells in its host language's own
  convention, the Python batch item `{"status": "not_available"}` and the
  Node.js `{ status: 'notAvailable' }`. The transport and token words the
  clients pass through from the shared HTTP primitives are respelled too:
  see the next section.

### BREAKING: four transport and token words the clients pass through are kebab-case

A transport failure and a failed token acquisition carry words the Evidence
clients take from the shared HTTP primitives unchanged. Four of those words
carried an underscore, and the primitives respell them in this release
(CFG-NAME-2).

| Member (Node.js, Python) | Old word | New word |
|---|---|---|
| `transportKind`, `transport_kind` | `response_too_large` | `response-too-large` |
| `tokenKind`, `token_kind` | `invalid_credential` | `invalid-credential` |
| `tokenKind`, `token_kind` | `scope_narrowed` | `scope-narrowed` |
| `code` of a refused token request | `unregistered_error_code` | `unregistered-error-code` |

- The other transport and token words are unchanged.
- The `code` of a refused token request keeps the specification's spelling
  when the authorization server answered one of the six codes RFC 6749
  section 5.2 registers (`invalid_request` among them).
- No file an adopter writes changes. A caller that compares one of these
  members with an old word compares with the new spelling.

### BREAKING: `evidencectl audit view` and target diagnostics spell their words in kebab-case

`evidencectl audit view` prints one `reason=` word on a refusal, denial, or
transient-failure line. The audit record it reads already spells its
`decision` in kebab-case; the view printed the same decision with an
underscore. It now prints the record's own word. A deployment-target refusal
that `evidencectl` reports as a diagnostic named its `artifact` with an
underscore too.

| Where | Old word | New word |
|---|---|---|
| `ACCESS REFUSED ... reason=` | `not_authorized` | `not-authorized` |
| `DISCLOSURE DENIED reason=` | `no_match` | `no-match` |
| `DISCLOSURE DENIED reason=` | `fact_missing` | `fact-missing` |
| `TRANSIENT FAILURE reason=` | `dependency_failure` | `dependency-failure` |
| `TRANSIENT FAILURE reason=` | `evaluation_failure` | `evaluation-failure` |
| `TRANSIENT FAILURE reason=` | `signing_failure` | `signing-failure` |
| diagnostic `artifact` | `deployment_target` | `deployment-target` |

- `ambiguous` and `unresolved` are unchanged.
- No audit record is rewritten and none changes spelling: the record's
  `decision` and `safeErrorCategory` words were kebab-case already.
- A script that matches the view's lines or a diagnostic's `artifact`
  matches the new word.

### BREAKING: the local source mock states its problem codes in kebab-case

The source mock that `evidencectl` serves for local development answers a
request it cannot serve with one of five fixed problems. Each `code` carried
underscores, in the prefix and in the word.

| Status | Old code | New code |
|---|---|---|
| 404 | `source_mock.not_found` | `source-mock.not-found` |
| 405 | `source_mock.method_not_allowed` | `source-mock.method-not-allowed` |
| 501 | `source_mock.unsupported_route` | `source-mock.unsupported-route` |
| 500 | `source_mock.generation_failed` | `source-mock.generation-failed` |
| 503 | `source_mock.busy` | `source-mock.busy` |

- The mock is a local development aid: no deployed gateway serves these
  codes, and Evidence itself never branches on them.
- A local script that matches a mock problem `code` matches the new word.

### BREAKING: Evidence spells its metric label values in kebab-case

A metric name and a label name follow the Prometheus naming rule and are
unchanged. A label value is a word Evidence defines and an operator's query
matches, so it follows the same rule as every other such word. The `error`
label of the gateway already carries the kebab-case problem code.

| Series | Label | Old value | New value |
|---|---|---|---|
| `evidence_http_requests_total`, `evidence_http_request_duration_seconds` | `status` | `client_error` | `client-error` |
| `evidence_http_requests_total`, `evidence_http_request_duration_seconds` | `status` | `server_error` | `server-error` |
| `evidence_oid4vci_http_requests_total`, `evidence_oid4vci_http_request_duration_seconds` | `status` | `client_error` | `client-error` |
| `evidence_oid4vci_http_requests_total`, `evidence_oid4vci_http_request_duration_seconds` | `status` | `server_error` | `server-error` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `offer_created` | `offer-created` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `offer_authorization_refused` | `offer-authorization-refused` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `store_saturated` | `store-saturated` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `store_fault` | `store-fault` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `code_redeemed` | `code-redeemed` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `code_claim_refused` | `code-claim-refused` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `token_claimed` | `token-claimed` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `token_claim_refused` | `token-claim-refused` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `nonce_minted` | `nonce-minted` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `nonce_invalid` | `nonce-invalid` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `nonce_tampered` | `nonce-tampered` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `nonce_expired` | `nonce-expired` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `proof_refused` | `proof-refused` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `credential_issued` | `credential-issued` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `evidence_refused` | `evidence-refused` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `evidence_not_available` | `evidence-not-available` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `evidence_unavailable` | `evidence-unavailable` |
| `evidence_oid4vci_outcomes_total` | `outcome` | `cleanup_expired` | `cleanup-expired` |

- The `status` field of a structured request log of either service carries
  the same class word and changes with it.
- Unchanged: every metric and label name; `success`, `unmatched`, `other`,
  and `none`; and the `error` label of the delivery front end, which passes
  through the error codes OAuth 2.0 and OID4VCI define (`invalid_request`,
  `invalid_nonce`, `server_error`, ...).
- Respell the label values in every dashboard query, recording rule, alert
  rule, and log filter that names one. A rule that still matches the old
  value matches no series after the upgrade and raises no error, so check
  each one.

### BREAKING: `evidencectl dev` reads the issuer owner's `mapping` word in kebab-case

A local Evidence project that borrows a Base Registry Engine issuer owner
checks that the owner registered each exchange client against an exchange
issuer of the matching `mapping`. The owner's `.breg/dev/clients.json`
states that word in kebab-case in this release, and `evidencectl` still
compared it with the underscore spelling.

| Member read | Old word matched | New word matched |
|---|---|---|
| `issuer.exchangeIssuers[].mapping` | `institutional_grant` | `institutional-grant` |
| `issuer.exchangeIssuers[].mapping` | `first_party` | `first-party` |

- Evidence writes no file here: the word is the Base Registry Engine's, and
  its own fragment gives the edit to `clients.json`.
- An owner entry in the old spelling registers no exchange issuer for the
  Evidence client, and `evidencectl dev` stops with "BREG issuer
  signed-context exchange registration differs from Evidence client".
