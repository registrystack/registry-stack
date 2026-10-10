# registry-platform-config

Shared runtime configuration for maintained Registry Stack runtimes: one
loader for the operator `runtime.yaml`, the configuration blocks every runtime
spells the same way, and the `secret:` reference resolver. Each product still
owns and validates the rest of its configuration contract.

## Loader

`RuntimeConfigLoader` reads one runtime configuration file named by an
absolute path, through the shared configuration reader in
`registry-platform-yaml`. It refuses:

- a relative path, or one with `.` or `..` components;
- a symbolic link in any path component;
- anything but a regular file, or one over the size bound (1 MiB,
  `yaml.too-large`; the reader refuses a larger document whatever the
  bound);
- an empty file, or one that holds only comments, as a missing envelope
  (`config.missing-envelope` at line 1, column 1);
- text that is not UTF-8, and YAML outside the reader's subset: more than one
  document, a root that is not a mapping, a non-string key, a duplicate key,
  a YAML tag, or an anchor or alias;
- an `apiVersion` or `kind` other than the product's literal envelope, before
  anything else in the document is looked at;
- a key the product removed, naming the key that replaced it;
- a key the product's configuration type does not declare;
- a null member (`null`, `~`, or a key with nothing after it): leave the key
  out instead.

A product may also require trusted ownership: every ancestor directory and
the file owned by root or the runtime user and not writable by group or
others, except a root-owned sticky directory.

Every refusal names the file, the field, and the fix, and never repeats a
configured value. A `RuntimeConfigError` carries the reader's diagnostics
(`diagnostics()`), each with a two-segment code, a JSON pointer, a line and
column, a message, and a suggested action; its `Display` renders every one of
them in the human form `error[code] file:line:col /pointer`. A consumer
classifies a refusal by a diagnostic's `code`; `deciding_diagnostic()` is the
one it words the refusal from, and `UNAVAILABLE_CODE` is the code of a file
that cannot be read. A refusal found before the reader ran carries one
`platform.runtime-config.*` diagnostic.

## Environment substitution

While reading, the loader substitutes environment expressions inside string
values of `runtime.yaml`, in place, so a diagnostic about a substituted value
points at the expression in the file:

- `${VAR}` requires `VAR` to be set and non-empty;
- `${VAR:-default}` uses `default` when `VAR` is unset or empty;
- `${VAR:?message}` refuses when `VAR` is unset or empty. The refusal names
  `VAR` and withholds `message`, because the message is configured text.

Comments are never substituted, a substituted value stays a string, so it
never fills a number or a boolean, and substitution runs once, so a value that
itself looks like an expression is kept as written. A `${` followed by
anything but a name character or `}` is text; an expression without its
closing brace, or with a name that is not letters, digits, and underscores
starting with a letter or underscore, is refused. There is no escape syntax:
a literal `${...}` reaches the configuration as the value of a variable. An expression is refused in a key, in `apiVersion` or `kind`, inside
a field whose name ends in `Ref` or `Refs` or anywhere beneath one (a secret
reference names a provider, and the provider reads the value), and anywhere
under `secretProviders`, because a provider setting chooses which secret a
reference resolves to. A refusal names the variable but never its value or a
`${NAME:?message}` message.

Authored package files are not substituted.
`reject_environment_expressions_in_authored_yaml` reads an authored document
with the same reader and refuses one that carries an expression in a key or
a value, and refuses text it cannot read rather than letting it pass
unchecked. Its refusals carry the `authored_config.environment_expression` and
`authored_config.syntax` codes.

The effective digest of a loaded file is the `sha256:` label of the canonical
JSON of the substituted document, so a comment or formatting change does not
change it.

## Shared blocks

`blocks` holds the sections each runtime embeds unchanged:

- `SecretProvidersConfig`: `file.root` enables `secret:file/name`, and
  `environment: {}` enables `secret:env/NAME`. At least one must be declared,
  and a reference to an undeclared provider is refused.
- `DatabaseConfig`: `runtimeUrlRef`, `migrationUrlRef`, and an optional
  `trustedRootCertificateRef`.
- `JwksSource`: `type: discovery` (the default) with no other member,
  `type: uri` with `uri`, or `type: static` with `documentRef`.
- `PackageConfig`: an absolute `root` and an optional `expectedDigest` pin.
- `ListenerConfig` and `PrivateListenerConfig`: `bind` as `host:port` with an
  IP address host, and for private listeners the declared TLS termination and
  network exposure.

## Package

`package` is the one package format every runtime serves from
`package.root`. A product's `package` command either writes its files from
memory with `write_package`, or populates a new directory itself and calls
`write_sum_file`; `plan_package` reports the digest a package would have
without writing it. The package carries `SHA256SUMS` at the root: one line per
file in the `sha256sum` text format, sorted by path, LF line endings, listing
every file but itself. An optional `REVISION` file holds one free-text line
(at most 256 bytes) and is listed and hashed like every other file. The
package digest is the `sha256:` label of the `SHA256SUMS` bytes, and is what
`package.expectedDigest` pins. The same files and revision always give the
same digest, and `sha256sum -c SHA256SUMS` checks a package by hand.

At startup `PackageConfig::verify_package` recomputes every digest and
refuses, in one message naming each file and the command that rebuilds the
package:

- a changed, missing, or extra file, including a hidden file and an empty
  directory;
- a missing or malformed `SHA256SUMS`, by line;
- a symbolic link or special file anywhere in the package, or a `package.root`
  that is a link;
- a path with a backslash or control character, or two paths that differ only
  in letter case;
- a package over its file count, per-file, total, depth, or path-length bound;
- a package whose digest is not `package.expectedDigest`, showing both
  digests in the `PackageDigestMismatch` shape every runtime shares.

Only file bytes are hashed. Modes, owners, and timestamps are not, because
copies, source control, and image layers do not preserve them the same way on
every platform, and hashing them would give one package several digests.
Line endings are not normalized. `is_envelope_file` names `SHA256SUMS` and
`REVISION` so a product loader that enumerates its package can skip them.

With the `schema` feature, the `shared-blocks-schema` example writes the
canonical JSON Schema of these blocks to
`products/platform/generated/runtime-config-blocks.schema.json`:

```bash
cargo run -p registry-platform-config --features schema \
  --example shared-blocks-schema -- --output products/platform/generated
```

`products/platform/scripts/check-config-conformance.py` holds each runtime that
reads `runtime.yaml` through `RuntimeConfigLoader` to this surface: its
generated runtime schema embeds the shared blocks it uses unchanged, it does
not call a text-level `expand_config_env_vars` expansion, and named tests prove a `*Ref` field and
an authored project file both refuse `${VAR}`. `--check-generated` also
regenerates the canonical schema and fails when the committed copy differs. A
product that adopts the loader adds a row to the gate.
