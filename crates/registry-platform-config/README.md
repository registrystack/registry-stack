# registry-platform-config

Shared configuration parsing helpers for maintained Registry Stack products.

The crate expands bounded environment references, reports deprecated field
names without exposing values, and produces canonical SHA-256 identifiers.
Each product still owns and validates its complete configuration contract.

## Environment expansion

Shared configuration loaders expand `${VAR}` expressions before YAML parsing.
`${VAR}` requires `VAR` to be set to a non-empty value. `${VAR:-fallback}`
uses `fallback` when `VAR` is unset or empty, including `${VAR:-}` for an
explicit empty result. `${VAR:?message}` fails with `message` when `VAR` is
unset or empty. Whitespace-only values are non-empty. Diagnostics name the
variable or use the supplied message; they never include the variable value.

A product that must keep some members out of expansion, such as secret
references, parses the document as written and calls
`reject_config_env_expressions_in` with a predicate over member names before
expanding. The refusal names the member's path, never its value.
