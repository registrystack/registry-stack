# Configuration conventions: Base Registry Engine

## BReg citizen services

This section covers the runtime files of the two citizen services beside the
Base Registry Engine: `breg-mcp`, the citizen MCP gateway, and `breg-review`,
its paired review page. Both formats are experimental, so every
normalization lands in this release.

### BREAKING: both runtime files take a new `apiVersion` and renamed keys

`breg-mcp` and `breg-review` read `runtime.yaml` through the shared Registry
Stack reader. The old `apiVersion` is refused as
`config.retired-api-version`, and the refusal names the new one and the keys
to rename. Once the `apiVersion` is replaced, each old key is refused at its
position as `config.removed-key`, and the message names its replacement.
Every value keeps its meaning unless the step below says otherwise.

| Service | Old spelling | New spelling | Migration |
|---|---|---|---|
| `breg-mcp` | `apiVersion: registry.registrystack.org/breg-mcp-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/breg/mcp-runtime/v1alpha1` | Replace the value. |
| `breg-mcp` | `resourceServer.maxTokenLifetimeSeconds` | `resourceServer.maximumTokenLifetimeSeconds` | Rename the key. The value is now bounded 1 to 86400 (it was any positive number); a larger value is refused as `config.out-of-range`, so lower it to 86400 or less. Omitted, it is 3600, as before. |
| `breg-mcp` | `registry.requestTimeoutMilliseconds` | `registry.attemptTimeoutMilliseconds` | Rename the key. The value is now bounded 100 to 120000 (it was any positive number). Omitted, it is 10000, as before. |
| `breg-mcp` | `limits.maxRequestBodyBytes` | `limits.maximumRequestBytes` | Rename the key; keep the value (1 to 1048576, as before). |
| `breg-mcp` | `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value. |
| `breg-review` | `apiVersion: registry.registrystack.org/breg-review-runtime/v1alpha1` | `apiVersion: id.registrystack.org/formats/breg/review-runtime/v1alpha1` | Replace the value. |
| `breg-review` | `limits` | `rateLimits` | Rename the key; keep its `perCitizen` and `globalSignIn` members. Each `requestsPerMinute` and `burst` is now bounded 1 to 1000000 (it was any positive number). |
| `breg-review` | `audit.retainDays` | `audit.retentionDays` | Rename the key; keep the value. |

`breg-mcp` keys that predate v0.39.0, `resourceServer.jwks` and
`audit.maximumFileBytes`, stay refused as unknown keys (`config.unknown-key`)
with no named replacement, as in v0.39.0: write `resourceServer.jwksSource`
and `audit.rotateBytes`.

To find every old spelling in a file, run
`breg-mcp --runtime-config FILE check` or
`breg-review --runtime-config FILE check`. It reports a retired `apiVersion`
alone; once that is replaced, it reports each old key at its line and column
with its replacement, and the file is clean when the command exits 0.

### BREAKING: the shared reader refuses values outside the documented grammar

A file that was already outside the documented grammar is now refused when it
is read, and every refusal carries a code, a JSON Pointer path, a line, a
column, and the edit that fixes it. No refusal repeats a configured value.

| A file that writes | is refused as | Migrate by |
|---|---|---|
| `null`, `~`, or a key with no value | `config.null-value` | Deleting the key; an optional member is written by leaving it out. |
| an unquoted value that looks like a number but is not a plain decimal: a leading zero (`0123`), a bare point (`.5`, `5.`), a base prefix (`0x1F`), `.inf`, or `.nan` | `yaml.ambiguous-number` | Quoting the value when it is text, or writing the plain decimal when it is a number. |
| a number where text is expected, such as an unquoted `clientId: 12345` | `config.expected-string` | Quoting the value: `clientId: "12345"`. |
| text where a number is expected, such as `burst: "10"` | `config.expected-integer` | Writing the number unquoted. |
| a YAML anchor, alias, merge key, or tag | `yaml.anchor`, `yaml.alias`, `yaml.merge-key`, `yaml.tag` | Writing the shared value out in full at every place that used the alias. |
| an empty file | `config.missing-envelope` at line 1, column 1 (was `platform.runtime-config.size`) | Writing the `apiVersion`, `kind`, and members the format requires. |
| a file over the reader's size bound | `yaml.too-large` (was `platform.runtime-config.size`) | Shrinking the file below the bound the message names. |

### BREAKING: members are typed by the shared reader

Each member is read as the shared type its schema names, so a value outside
that type is refused at the member, as `config.invalid-value`,
`config.invalid-length`, `config.duplicate-item`, or `config.out-of-range`,
rather than after the whole file was decoded.

- **Secret references.** Every `*Ref` member is `secret:file/NAME` or
  `secret:env/NAME`, as before. An inline value is refused as
  `config.invalid-value` at the member, by path only; a `${NAME}` expression
  in a reference is refused as `config.substitution-not-allowed`. Migration:
  none for a file either service started with.
- **URLs.** `resourceServer.resource`, `resourceServer.issuer`,
  `registry.baseUrl`, `exchange.tokenEndpoint`, `service.reviewBaseUrl`,
  `publicOrigin`, `signIn.issuer`, and the review page's `registry.baseUrl`
  are the shared URL type: an absolute `http` or `https` URL with a host, no
  user information, and at most 2048 characters. Plain `http` is still
  accepted only on a loopback host under `listener.tlsTermination:
  development-loopback`, and an endpoint still carries no query or fragment.
  Migration: none for a file either service started with, unless a URL is
  longer than 2048 characters.
- **Local identifiers (narrowed).** `registry.accessProfile`,
  `service.details.entity`, `service.application.entity`, `targetField`, and
  `ownerField` in `breg-mcp`, and `registry.entity`, `targetField`, and
  `accessProfile` in `breg-review`, are local identifiers: a lowercase
  letter, then up to 63 lowercase letters, digits, `_`, or `-`, the grammar
  the Base Registry Engine itself gives them. A dot, an uppercase letter, or
  a name longer than 64 characters is now refused. Migration: write the name
  exactly as the registry project declares it; a name the registry accepts
  already fits.
- **External identifiers (loosened).** `resourceServer.allowedClients`,
  `resourceServer.scopeClaim`, `exchange.clientId`, and
  `exchange.assertionAudience` in `breg-mcp`, and `signIn.clientId` in
  `breg-review`, are external identifiers: 1 to 512 characters with no
  control character, written exactly as the issuer gives them. They were a
  whitespace-free token (`breg-mcp`) or visible ASCII up to 256 bytes
  (`breg-review`). Migration: none.
- **Service text.** `service.name`, `service.description`, and
  `service.disclosure` are 1 to 4096 characters and not blank; the bound was
  4096 bytes. Migration: none.
- **Lists.** `resourceServer.algorithms`, `resourceServer.allowedClients`,
  `resourceServer.requiredScopes`, and `registry.scopes` in `breg-mcp` hold 1
  to 128 items, and `signIn.scopes` in `breg-review` 1 to 16. An empty list
  was already refused; a repeated item is now refused as
  `config.duplicate-item` at the repeat. Migration: delete the repeated item.
- **Integers.** Every integer member states its minimum and maximum in the
  published schema and is refused outside them as `config.out-of-range`.
  Beyond the bounds in the renaming table, `breg-mcp`'s
  `rateLimits.perCitizen` and `rateLimits.perClient` rates are bounded 1 to
  1000000 (they were any positive number). The review page's session store
  sizes and lifetimes keep their previous ranges, now stated by the schema.
  Migration: lower a value above its maximum.

### BREAKING: `check` reads its file offline and reports in the shared shape

`breg-mcp --runtime-config FILE check` and `breg-review --runtime-config
FILE check` are the offline checks for their runtime files.

- **No secret, socket, or audit file.** `check` reads no secret, opens no
  network connection, and opens no audit file. It used to resolve every
  secret the file named (and `breg-review check` used to confirm the audit
  directory was writable). Those faults are now refused only by `serve`,
  before it binds its listener, as before. Migration: a deployment step that
  relied on `check` to catch a missing or unsafe secret file, or an
  unwritable audit directory, must rely on `serve` refusing to start, or
  check those files itself. A `check` run in a container needs only the
  runtime file mounted.
- **Environment expressions.** Without options, `check` checks each
  `${NAME}` expression by its syntax and position only. `--environment`
  substitutes every expression from the current environment and checks every
  value, as `check` used to. Migration: add `--environment` to a `check` run
  that should judge substituted values.
- **Output.** The human report is the shared one: `error[CODE]
  FILE:LINE:COLUMN /path`, the message, a `next:` line, and a closing count
  of errors and warnings. It goes to standard output when the file is
  accepted and to standard error, after one line naming the command, when it
  is refused. `--format json` writes one report object to standard output:
  `apiVersion: id.registrystack.org/formats/breg/mcp-ctl-report/v1alpha1`
  with `kind: BRegMcpCtlReport` for the gateway, and
  `apiVersion: id.registrystack.org/formats/breg/review-ctl-report/v1alpha1`
  with `kind: BRegReviewCtlReport` for the review page. The previous `check`
  wrote its verdict as a JSON log line on standard output, and `breg-review`
  wrote a refusal as a `breg-review:` line on standard error. Migration: a
  script that parsed either reads `--format json` instead.
- **Exit status.** 0 accepted, 1 refused (or a warning under
  `--deny-warnings`), 2 a usage error, and 3 when the file cannot be read.
  `check` used to exit 1 for a refused file and an unreadable one alike.
  Migration: a script that treated any non-zero status as a refused file
  keeps working; one that needs to tell an unreadable file apart matches 3.
- **Every finding at once.** `check` reports every finding in the file, each
  at its own member, where each service's own rules stopped at the first
  refusal.
- **`serve`.** `serve` prints a refused runtime file's diagnostics on
  standard error, after a line naming the service, and exits 1. `breg-mcp`
  used to write that refusal as an `ERROR` JSON line on standard output.
  Other startup failures keep their previous channel. Migration: collect
  standard error for both services.
- **Rust API.** `registry_breg_mcp::runtime::check` and
  `registry_breg_review::check` are removed; `check::run` in each crate is
  the offline check. Each crate's `RuntimeConfigError` is a struct carrying
  the shared `diagnostics`, where it was an enum of refusals.

### Runtime file diagnostic codes

The previous refusals carried no code of their own: each was a sentence that
named a dotted member. The new code and JSON Pointer path for each, with
`breg.mcp-runtime.` and `breg.review-runtime.` abbreviated as `mcp.` and
`review.` in the first column of each table below.

`breg-mcp`:

| Previous refusal | New code | New path |
|---|---|---|
| the listener must bind a loopback or private address for its tlsTermination and networkExposure | `mcp.public-bind` | `/listener/bind` |
| FIELD must be an https URL without credentials, query, or fragment | `mcp.plain-http-endpoint` (plain `http` off loopback or outside `development-loopback`), `mcp.endpoint-query-or-fragment`, or `config.invalid-value` (not a URL, or with user information) | the member |
| resourceServer.resource must name the /mcp endpoint | `mcp.resource-not-mcp-endpoint` | `/resourceServer/resource` |
| FIELD must not be empty | `config.invalid-length` (a list) or `config.invalid-value` (text) | the member |
| FIELD is longer than this gateway accepts | `config.invalid-length` (a list) or `config.invalid-value` (text) | the member, or the item |
| FIELD holds a value that is not a single token | `config.invalid-value` | the member, or the item |
| FIELD holds a value that is not an RFC 6749 scope token | `config.invalid-value` | the item, such as `/registry/scopes/0` |
| FIELD must be an absolute URI without a fragment or credentials | `config.invalid-value` | `/registry/audience` |
| FIELD must be greater than zero | `config.out-of-range` | the member |
| the gateway's own exchange client may not be an accepted inbound client | `mcp.exchange-client-admitted-inbound` | `/exchange/clientId` |
| the registry audience must differ from the gateway's own resource | `mcp.audience-reused` | `/registry/audience` |
| service.reviewBaseUrl must be the review page's publicOrigin, with no path | `mcp.review-base-url-not-origin` | `/service/reviewBaseUrl` |
| service.application.ownerField must name a different field than targetField | `mcp.owner-field-is-target` | `/service/application/ownerField` |
| FIELD must be an absolute path | `mcp.relative-path` | the member |
| an audit destination refusal | `mcp.missing-audit-path` (`/audit`), `mcp.file-only-audit-member` (`/audit/path`, `/audit/rotateBytes`, or `/audit/retentionDays` under `destination: stdout`), `mcp.invalid-audit-path` (`/audit/path`), or `mcp.invalid-audit` | the member named |
| a secret provider or reference refusal | `mcp.no-secret-provider`, `mcp.invalid-secret-reference`, or `mcp.undeclared-secret-provider` | the member |
| a `resourceServer.jwksSource` URI refusal | `mcp.invalid-jwks-uri` | the member |
| any other shared block refusal | `mcp.invalid-block` | the member |
| the runtime configuration is not UTF-8 text | `yaml.not-utf8` | the file |
| the runtime file path could not be made absolute (`check` only) | `breg.mcp-check.runtime-unreadable`, exit 3 | the file |

`breg-review`:

| Previous refusal | New code | New path |
|---|---|---|
| secretProviders must explicitly enable file, environment, or both | `review.no-secret-provider` | `/secretProviders` |
| listener is not valid for its declared TLS termination and network exposure | `review.public-bind` | `/listener/bind` |
| publicOrigin must be an https origin with no path, query, or userinfo | `review.public-origin-not-origin` (a path), `review.plain-http-endpoint`, `review.endpoint-query-or-fragment`, or `config.invalid-value` (not a URL, or with user information) | `/publicOrigin` |
| signIn is invalid | `review.plain-http-endpoint` or `review.endpoint-query-or-fragment` (`/signIn/issuer`), `config.invalid-value` (`/signIn/clientId`, or a scope), `config.invalid-length` (`/signIn/scopes`), `config.duplicate-item` (the repeated scope), or `review.openid-scope` (the `openid` item) | the member or item under `/signIn` |
| registry is invalid | `review.plain-http-endpoint` or `review.endpoint-query-or-fragment` (`/registry/baseUrl`), or `config.invalid-value` (`/registry/resource`, `/registry/entity`, `/registry/targetField`, `/registry/accessProfile`) | the member under `/registry` |
| limits must admit at least one request per minute and a burst of at least one | `config.out-of-range` | `/rateLimits/perCitizen/requestsPerMinute` and the other rate members |
| session bounds are outside their accepted ranges | `config.out-of-range` | the member under `/session` |
| session.maximumPendingSignIns must hold every sign-in limits.globalSignIn admits | `review.pending-sign-ins-fillable`; the message names the formula, not the computed number | `/session/maximumPendingSignIns` |
| an audit destination refusal | `review.missing-audit-path`, `review.file-only-audit-member`, `review.invalid-audit-path`, or `review.invalid-audit` | the member named |
| a secret reference or shared block refusal | `review.invalid-secret-reference`, `review.undeclared-secret-provider`, `review.relative-path`, or `review.invalid-block` | the member |
| the runtime file path could not be made absolute (`check` only) | `breg.review-check.runtime-unreadable`, exit 3 | the file |

For both services, an unknown, removed, null, mistyped, or out-of-range
member, a refused envelope, and a refused `${NAME}` expression carry the
shared `config.*` and `yaml.*` codes at the member, and a runtime file that
cannot be read carries the shared `platform.runtime-config.*` code with exit
status 3.

### The runtime files have published schemas

Each runtime file has a JSON Schema generated from the types the service
reads, embedding the shared platform blocks unchanged:

- `breg-mcp`:
  `https://id.registrystack.org/schemas/breg/mcp-runtime/mcp-runtime.v1alpha1.schema.json`,
  committed as `products/breg/generated/mcp-runtime/mcp-runtime.schema.json`.
- `breg-review`:
  `https://id.registrystack.org/schemas/breg/review-runtime/review-runtime.v1alpha1.schema.json`,
  committed as `products/breg/generated/review-runtime/review-runtime.schema.json`.

A minimal example of each is under `products/breg/examples/mcp-runtime/` and
`products/breg/examples/review-runtime/`.
`python3 editors/configure.py breg-mcp DIRECTORY` and
`python3 editors/configure.py breg-review DIRECTORY` map the directory's
`runtime.yaml` to its schema and add an editor task that runs `check`.
