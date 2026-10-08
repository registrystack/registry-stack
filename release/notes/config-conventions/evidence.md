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

### Diagnostic codes

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
