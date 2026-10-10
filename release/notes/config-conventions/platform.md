# Registry Stack platform files: configuration conventions

Track: small products (Discovery, Render, Manifest, platform tooling files).

Two files the development commands share move to the configuration
conventions: the task connection file that `evidencectl dev grant`,
`bregctl dev grant`, and `caseworkctl dev grant` read, and the ThunderID
development session state file, `session.json`, that a development session
writes and reads back. Both are read by the shared Registry Stack reader and
open with `apiVersion` and `kind`.

Shared webhook delivery installation creates the current dead-letter reason
column and constraint directly. v0.40.0 does not upgrade v0.39.0 state in
place; apply to a new database. No installation step repairs an earlier table.

## BREAKING changes

1. **A task connection file opens with `apiVersion` and `kind`.** It begins
   with
   `apiVersion: id.registrystack.org/formats/platform/task-connection/v1alpha1`
   and `kind: PlatformTaskConnection`, where it began with `version: 1`.
   `version` is refused with a fix that says to delete it. Migration: replace
   `version: 1` with the two envelope lines.
2. **A client's assertion key is a secret reference.**
   `clients.<id>.assertionKeyFile` is refused; write
   `assertionKeyRef: secret:file/<name>` (a name of 1 to 128 lowercase
   letters, digits, `.`, `_`, or `-`, starting with a letter) or
   `assertionKeyRef: secret:env/NAME`, and enable its provider under a
   top-level `secretProviders` block (`file: {root: <absolute directory>}`,
   `environment: {}`, or both) (CFG-SEC-1). The key is resolved only when a
   grant is acquired, and the key file keeps its rule: a regular file you
   own, mode 0400 or 0600, with a single link. Migration: for each client,
   move `assertionKeyFile: <directory>/<name>` to
   `secretProviders.file.root: <directory>` and
   `assertionKeyRef: secret:file/<name>`. Clients whose keys live in
   different directories need one directory that holds every key file, or
   the environment provider.
3. **The connection file's mode rule changes.** The file names no secret, so
   others may read it; it must be a regular file you own with a single link
   that neither group nor others may write (mode 0644 is accepted). It had
   to be owner-only (0600). Migration: none for a file that passed; a
   group-writable file is refused with `platform.task-connection.unsafe-file`.
4. **Every finding is reported, with its place and fix, and no value.** A
   refused connection file reports every finding as
   `error[code] file:line:col /pointer`, the message, and `next:` with the
   fix, where it reported one generic sentence. No finding repeats a value
   from the file (CFG-SEC-3). An unknown, duplicate, or null key, an anchor
   or alias, and `${...}` are refused (`config.unknown-key`,
   `yaml.duplicate-key`, `config.null-value`, `yaml.anchor`, `yaml.alias`,
   `config.substitution-not-allowed`). Migration: match the diagnostic code
   (table below) instead of the message text.
5. **`evidencectl dev grant` exit codes and JSON follow the shared check
   contract.** A refused connection file exits 1, and an unopenable one
   exits 3; with `--format json` the failure report carries the
   diagnostics. Migration: treat exit 3 as a missing or unreadable file.
6. **Bounds follow the shared reader.** The file holds at most 1 MiB (was
   64 KiB), and `clientAssertionAudience`, `bootstrapResource`, and each
   client's `resource` at most 512 characters. Migration: none for a file
   that passed, unless a URI was longer than 512 characters.
7. **`session.json` opens with `apiVersion` and `kind`, and its members are
   camelCase.** It holds
   `apiVersion: id.registrystack.org/formats/platform/thunderid-session/v1alpha1`,
   `kind: PlatformThunderidSession`, `setupComplete`, and `containerName`.
   The unused `schema_applied` member is gone. A file written by an earlier
   release is refused, and the refusal says how to start afresh. Migration:
   stop the development session, delete the directory that holds
   `session.json`, and start the session again; the local issuer is set up
   afresh.
8. **A substituted value holds no control character.** A `${VAR}` value
   with a control character other than tab, line feed, or carriage return
   (ESC, DEL, U+0085, and the like) is refused with `config.substitution`
   naming the variable, as the same character written in the file is refused
   with `yaml.control-character`. Migration: remove the control character
   from the variable.
9. **A mapping key holds no control character.** A key with a control
   character other than tab, line feed, or carriage return is refused with
   `yaml.control-character` at the key, and the diagnostic's path is the
   enclosing mapping, so it does not repeat the key. Migration: remove the
   control character from the key.
10. **A URL holds no backslash, whitespace, or control character and preserves its host.**
    In every product's files, a member typed as the shared URL refuses those
    characters anywhere with `config.invalid-value` at the member. The schema
    pattern continues to exclude whitespace and control characters; raw-backslash
    schema tightening is deferred to preserve frozen Version 1 contracts. The
    reader also refuses a host the URL parser rewrites, including Unicode host
    names and percent-encoded host text.
    Ordinary ASCII DNS names, case differences, punycode, and IPv6 literals
    remain allowed. The URL stays as written; issuer equality stays textual.
    `OidcIssuerConfig.issuer` and `JwksSource::Uri.uri` now use the checked
    `Url` type, matching their schemas, before existing HTTPS and loopback
    policy checks run. Rust struct-literal callers must construct those fields
    with `registry_platform_yaml::Url::new`.
    Migration: remove forbidden characters, write an internationalized host
    in punycode, use a canonical IPv4 address, and write a space or backslash
    inside a path or query as `%20` or `%5C`.

## Other changes

- **The check.** `evidencectl dev check <file>` is the offline check for a
  task connection file and a session state file; the file's envelope says
  which (CFG-CHECK-1). It resolves no secret reference and judges no file
  mode, so it runs on a file whose keys are not present. It prints every
  finding the reader and the connection rules report, takes
  `--format json` and `--deny-warnings`, and exits 0 when nothing is
  refused, 1 when something is (or a warning is reported under
  `--deny-warnings`), and 3 when the file cannot be read
  (`platform.check.unreadable`). `editors/configure.py platform <directory>`
  maps the schema to `task-connection.yaml` in that directory and adds an
  editor task that runs this check.
- A JSON Schema for the task connection file is generated from the type
  `dev grant` reads and published as
  `products/platform/schemas/task-connection.schema.json`
  (CFG-SCHEMA-2). Regenerate it with
  `cargo run -p registry-thunderid-tooling --features schema --example task-connection-schema -- --output products/platform/schemas`.
  A test holds it to the reader on the example and on each endpoint,
  resource, scope, and client rule, and CI reproduces it.
- `products/platform/examples/task-connection.yaml` and
  `products/platform/examples/thunderid/session.json` are the reference
  files, and both are read by tests.
- The identifier catalog lists the task connection schema under the
  `platform` owner.
- The shared `SecretProvidersConfig` block's `file` and `environment`
  members no longer admit `null` in any published schema. The reader
  already refused it (`config.null-value`, CFG-EMPTY-1); leave a provider
  out to disable it. Every runtime schema embedding the block was
  regenerated, so BReg's, which already dropped the `null`, embeds it
  unchanged again (CFG-SCHEMA-5).

## Diagnostic codes, old to new

The task connection file had no diagnostic codes: each refusal was one
sentence after "the approved task grant could not be acquired".

| Before | Now |
|---|---|
| "the connection file must match the closed task connection v1 format" | a reader code, such as `config.unknown-key`, `config.missing-key`, `config.removed-key`, or `yaml.syntax` |
| "task connection v1 requires 1..32 bounded registered clients" | `config.removed-key` at `/version`, or `platform.task-connection.no-clients`, `too-many-clients`, or `invalid-client-id` |
| "configured endpoints require HTTPS or explicit loopback HTTP" | `platform.task-connection.invalid-endpoint` |
| "the retained resource, assertion audience or scope ceiling is invalid" | `platform.task-connection.invalid-resource`, `no-scopes`, `too-many-scopes`, `invalid-scope`, or `config.duplicate-item` |
| "the connection or credential file cannot be opened" or "cannot be read" | `platform.task-connection.unreadable` (exit 3) |
| "connection and credential files must be ordinary owner-only single-link files" | `platform.task-connection.unsafe-file` for the connection file, `platform.task-connection.unresolved-secret` for the key file |
| "the connection or credential file exceeds its bound" | `yaml.too-large` |
| "the registered assertion key file must be absolute" | `platform.task-connection.relative-path` at `/secretProviders/file/root` |
| "the registered assertion key is invalid" | `platform.task-connection.invalid-assertion-key` |
| (new) | `platform.task-connection.no-secret-provider`, `platform.task-connection.undeclared-secret-provider`, `platform.task-connection.unresolved-secret` |

## Stable move

The changes below move promised spellings to the form the configuration
conventions give them. Each old spelling is refused with a diagnostic that
names its replacement; no release reads both.

### BREAKING: the shared `JwksSource` block is tagged by `type`

`JwksSource` in `registry-platform-config`, the block every Registry Stack
runtime reads for its OIDC issuer's signing keys, is a union tagged by `type`
(CFG-ID-7), where it was tagged by `kind`. The values `discovery`, `uri`, and
`static` and their members are unchanged, the default is still
`type: discovery`, and the type serializes with `type`.

| Old spelling | New spelling | Migration |
|---|---|---|
| `jwksSource: {kind: discovery}` | `jwksSource: {type: discovery}` | Rename the key; keep the value. |
| `jwksSource: {kind: uri, uri: <URL>}` | `jwksSource: {type: uri, uri: <URL>}` | Rename the key; keep the value. |
| `jwksSource: {kind: static, documentRef: <reference>}` | `jwksSource: {type: static, documentRef: <reference>}` | Rename the key; keep the value. |

A runtime whose issuer block sits at `authentication.oidc` adds
`REMOVED_OIDC_JWKS_SOURCE_KIND` to its removed-key table, and its loader then
refuses the old tag as `config.removed-key` at
`/authentication/oidc/jwksSource/kind` with the message naming `type`.
Casework, Scheduling, and Messaging do. A runtime that keeps the block
elsewhere declares its own entry at that path. The canonical schema
`products/platform/generated/runtime-config-blocks.schema.json` and every
runtime schema that embeds the block carry the `type` tag.

### BREAKING: the shared hook handler declaration is tagged by `type`

`HookHandlerSource` in `registry-platform-hooks`, the declaration a product
reads for the handler of a hook, is a union tagged by `type` (CFG-ID-7), where
it was tagged by `kind`. The values `rhai`, `wasm`, and `url`, the source
reference each requires, and `abi` are unchanged, and the type serializes with
`type`.

| Old spelling | New spelling | Migration |
|---|---|---|
| `handler: {kind: url, destinationId: <id>}` | `handler: {type: url, destinationId: <id>}` | Rename the key; keep the value. |
| `handler: {kind: rhai, script: <path>, abi: <abi>}` | `handler: {type: rhai, script: <path>, abi: <abi>}` | Rename the key; keep the value. |
| `handler: {kind: wasm, module: <path>, abi: <abi>}` | `handler: {type: wasm, module: <path>, abi: <abi>}` | Rename the key; keep the value. |

The declaration reads no alias: a handler written with `kind` does not
deserialize. A product that reads the declaration from an authored file adds
the old member to its removed-key table, so its reader refuses it as
`config.removed-key` with a message naming `type`; the Base Registry Engine
does, for entity hooks and governed actions. `HookHandlerKind`, its spellings,
and the stored `handler_kind` column of the delivery tables are unchanged.
Registry Scheduling keeps its own observer handler declaration, which is
already tagged by `type`.

### BREAKING: a client listed under `assertionIssuers` names at least one issuer

`OidcClientsConfig` in `registry-platform-config`, the block the Casework,
Scheduling, and Messaging runtimes read under `authentication.oidc`, refuses
a client that `assertionIssuers` lists with an empty issuer list
(CFG-EMPTY-2). The reader reports `config.invalid-value` at
`/authentication/oidc/assertionIssuers/<client>`, and the block schema
declares `minItems: 1` on the list.

| Old spelling | New spelling | Migration |
|---|---|---|
| `assertionIssuers: {portal: [https://a.example], kiosk: []}` | `assertionIssuers: {portal: [https://a.example]}` | Remove the client that lists no issuer, or list its issuers. |

A client that is not listed may exchange from no authority, so removing the
client keeps what the empty list meant while another client stays listed. Do
not delete the whole member to get there unless no assertion-issuer rule is
wanted: with the member omitted, the block applies no rule.

### BREAKING: `DatabaseIdCheck` is written in kebab-case

`registry_platform_activation::DatabaseIdCheck` serializes `NotRecorded` as
`not-recorded`, where it wrote `notRecorded` (CFG-NAME-2). `matches` and
`differs` are unchanged, and so is the Rust type. The value appears in the
plan reports of Casework (`databaseIdCheck`) and Messaging (`databaseId`);
nothing reads it back and nothing stores it.

Migration: a script that compares `notRecorded` compares `not-recorded`.

### BREAKING: the shared `OidcClientsConfig` block requires `allowedClients`

`OidcClientsConfig` in `registry-platform-config`, the block the Casework,
Scheduling, and Messaging runtimes read under `authentication.oidc`, requires
`allowedClients` (CFG-EMPTY-2). The member takes the keyword `unrestricted`,
to admit a token from every client the issuer verifies, or a list of at least
one client, none repeated (CFG-ID-6).

| Written | Before | Now |
|---|---|---|
| member omitted | read as every client | refused, `config.missing-key` at `/authentication/oidc` |
| `allowedClients: []` | read as every client | refused, `config.invalid-value` at `/authentication/oidc/allowedClients` |
| `allowedClients: unrestricted` | refused | read as every client |
| `allowedClients: [a, b]` | only `a` and `b` | unchanged |
| `allowedClients: [a, b, a]` | only `a` and `b` | refused, `config.duplicate-item` at `/authentication/oidc/allowedClients/2` |

The diagnostic names the fix and never repeats what was written. The block
schema states the same shape: `allowedClients` is required, has no default,
and is `$defs/OidcAllowedClients`, the constant `unrestricted` or a list with
`minItems: 1` and `uniqueItems: true`.

Each runtime keeps its own rule on top of the block. Casework accepts
`unrestricted` only on development loopback, and Scheduling and Messaging
accept it nowhere.

Rust API: `OidcClientsConfig::allowed_clients` is still a `Vec<String>` in
which an empty list admits every client, the form the token verifier takes.
Deserializing the block requires the member, and serializing an empty list
writes `unrestricted`.

Migration: in each runtime file that reads the block, write
`allowedClients` as the list of clients the deployment admits, written once
each, or as `unrestricted` where the runtime accepts it.

### BREAKING: four shared HTTP client error words are written in kebab-case

`registry-platform-httputil` names a failed exchange and a failed token
acquisition with fixed words: a caller branches on them, and every client
binding carries them across its language boundary. Four of them carried an
underscore (CFG-NAME-2).

| Where | Old word | New word |
|---|---|---|
| `TransportKind::kind()` | `response_too_large` | `response-too-large` |
| `TokenError::kind()` | `invalid_credential` | `invalid-credential` |
| `TokenError::kind()` | `scope_narrowed` | `scope-narrowed` |
| `OAuthErrorCode::as_str()`, a code outside RFC 6749 section 5.2 | `unregistered_error_code` | `unregistered-error-code` |

The other words of the three functions are unchanged. The six codes RFC 6749
section 5.2 registers (`invalid_request`, `invalid_client`, `invalid_grant`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`) are the
specification's and keep its spelling: `OAuthErrorCode::as_str()` still
returns them as an authorization server writes them.

The Node.js and Python clients carry these words as `transportKind` or
`transport_kind`, `tokenKind` or `token_kind`, and the `code` of a refused
token request. Each product fragment names the members its own client sets.

No file an adopter writes changes. To migrate, change what a consumer of one
of these words compares it with.
