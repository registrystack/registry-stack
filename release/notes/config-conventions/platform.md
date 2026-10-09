# Registry Stack platform files: configuration conventions

Track: small products (Discovery, Render, Manifest, platform tooling files).

Two files the development commands share move to the configuration
conventions: the task connection file that `evidencectl dev grant`,
`bregctl dev grant`, and `caseworkctl dev grant` read, and the ThunderID
development session state file, `session.json`, that a development session
writes and reads back. Both are read by the shared Registry Stack reader and
open with `apiVersion` and `kind`.

## BREAKING changes
<!-- upgrade: 1=platform-task-connection-envelope; 2=platform-assertion-key-ref; 3=no-file; 4=platform-task-connection-reader-refusals; 5=no-file; 6=platform-task-connection-bounds; 7=platform-session-state -->

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
