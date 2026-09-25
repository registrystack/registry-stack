# registry-platform-config

Shared runtime configuration for maintained Registry Stack runtimes: one
loader for the operator `runtime.yaml`, the configuration blocks every runtime
spells the same way, and the `secret:` reference resolver. Each product still
owns and validates the rest of its configuration contract.

## Loader

`RuntimeConfigLoader` reads one runtime configuration file named by an
absolute path. It refuses:

- a relative path, or one with `.` or `..` components;
- a symbolic link in any path component;
- anything but a regular file, an empty file, or one over the size bound
  (1 MiB unless the product sets another);
- text that is not UTF-8, more than one YAML document, a root that is not a
  mapping, a non-string key, a duplicate key, or a YAML tag;
- a key the product removed, naming the key that replaced it;
- an `apiVersion` or `kind` other than the product's literal envelope.

A product may also require trusted ownership: every ancestor directory and
the file owned by root or the runtime user and not writable by group or
others, except a root-owned sticky directory.

Every refusal names the file, the field, and the fix, and never repeats a
configured value.

## Environment substitution

After parsing, the loader substitutes environment expressions inside string
values of `runtime.yaml`:

- `${VAR}` requires `VAR` to be set and non-empty;
- `${VAR:-default}` uses `default` when `VAR` is unset or empty;
- `${VAR:?message}` refuses when `VAR` is unset or empty. The refusal names
  `VAR` and withholds `message`, because the message is configured text.

Keys and comments are never substituted, a substituted value stays a string,
and substitution runs once, so a value that itself looks like an expression is
kept as written. There is no escape syntax: a literal `${` reaches the
configuration as the value of a variable. An expression inside a field whose
name ends in `Ref` or `Refs`, or anywhere beneath one, is refused: a secret
reference names a provider, and the provider reads the value. An expression
anywhere under `secretProviders` is refused too, because a provider setting
chooses which secret a reference resolves to. Authored package files are not
substituted; `reject_environment_expressions_in_authored_yaml` refuses an
authored document that carries an expression, and refuses text it cannot read
as YAML rather than letting it pass unchecked. Its refusals carry the
`authored_config.environment_expression` and `authored_config.syntax` codes.

The effective digest of a loaded file is the `sha256:` label of the canonical
JSON of the substituted document, so a comment or formatting change does not
change it.

`expand_config_env_vars` is the earlier text-level expansion, kept for the
runtimes that do not read their configuration through the loader yet.

## Shared blocks

`blocks` holds the sections each runtime embeds unchanged:

- `SecretProvidersConfig`: `file.root` enables `secret:file/name`, and
  `environment: {}` enables `secret:env/NAME`. At least one must be declared,
  and a reference to an undeclared provider is refused.
- `DatabaseConfig`: `runtimeUrlRef`, `migrationUrlRef`, and an optional
  `trustedRootCertificateRef`.
- `JwksSource`: `kind: discovery` (the default) with no other member,
  `kind: uri` with `uri`, or `kind: static` with `documentRef`.
- `PackageConfig`: an absolute `root` and an optional `expectedDigest` pin.
- `ListenerConfig` and `PrivateListenerConfig`: `bind` as `host:port` with an
  IP address host, and for private listeners the declared TLS termination and
  network exposure.

With the `schema` feature, the `shared-blocks-schema` example writes the
canonical JSON Schema of these blocks to
`products/platform/generated/runtime-config-blocks.schema.json`:

```bash
cargo run -p registry-platform-config --features schema \
  --example shared-blocks-schema -- --output products/platform/generated
```

`products/platform/scripts/check-config-conformance.py` holds each runtime that
reads `runtime.yaml` through `RuntimeConfigLoader` to this surface: its
generated runtime schema embeds the shared blocks it uses unchanged, it no
longer calls `expand_config_env_vars`, and named tests prove a `*Ref` field and
an authored project file both refuse `${VAR}`. `--check-generated` also
regenerates the canonical schema and fails when the committed copy differs. A
product that adopts the loader adds a row to the gate.
