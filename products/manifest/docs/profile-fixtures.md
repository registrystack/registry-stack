# Validate against profile fixtures

Check that a manifest conforms to a named profile's requirements, or run the fixture suite against a new domain profile descriptor. Also useful for reproducing a `validate-profiles` CI failure locally.

For basic manifest validation (schema version, field format, reference integrity), use the `validate` subcommand instead. See [Validate and render a manifest](./validate-and-render.md).

## What profile fixtures are

A profile fixture is a pair of files in a `profiles/<profile-id>/` directory:

- `profile.yaml`: the profile descriptor (schema version `registry-manifest-profile/v1`). It
  declares the artifacts the profile reads, required concept IRIs, required identifiers,
  codelist expectations, cardinality expectations per entity field, the conformance checks it
  names, and a list of fixture paths to validate.
- `fixtures/metadata.yaml`: a portable manifest (schema version `registry-manifest/v1`) that
  the validator checks against the profile descriptor.

The two schema versions govern different files: `registry-manifest/v1` governs the manifest;
`registry-manifest-profile/v1` governs the descriptor. The CLI enforces both.

The five example profiles in the repository are non-normative examples.
They are not authoritative profiles for OpenCRVS, OpenSPP, OpenIMIS, or SP DCI until reviewed
against official artifacts.

## Prerequisites

- Rust toolchain installed.
- The Registry Stack monorepo cloned locally.

Run the commands on this page from the Manifest product directory:

```sh
cd /path/to/registry-stack/products/manifest
```

Build the CLI before running commands:

```sh
cargo build --locked -p registry-manifest-cli
```

The commands in this page use `cargo run --locked -p registry-manifest-cli --` as a prefix.
If you have installed the binary directly, replace that prefix with `registry-manifest`.

## Steps

### 1. Identify the profiles directory

By default the `validate-profiles` subcommand expects a `profiles/` directory path as its
argument.
Relative to the Manifest product directory, the directory is `profiles/`.

List the available profiles:

```sh
ls profiles/
```

Expected output (subdirectories that contain a `profile.yaml` are active profiles; others are
placeholders):

```text
example-benefits-sync/
example-civil-registration/
example-multi-dataset/
example-person-schema/
example-social-benefits/
opencrvs/
openimis/
openspp/
spdci/
```

Each subdirectory that contains a `profile.yaml` is a profile entry.

### 2. Run validate-profiles on the full directory

```sh
cargo run --locked -p registry-manifest-cli -- validate-profiles profiles
```

The validator scans every subdirectory for `profile.yaml`, reads each descriptor, reads every
fixture manifest the descriptor lists with the same checks as `validate`, then checks each
fixture against the descriptor's expectations. A YAML file under the directory that is neither
a descriptor nor a listed fixture is reported as a warning, since no check reads it.

On success, the command exits with code 0 and prints
`validated <n> profile descriptors and fixtures` and a summary line.

On a refusal, it prints one sentence and every finding to standard error and exits 1. It exits
3 when a descriptor, fixture, or directory cannot be read. Add `--deny-warnings` to refuse
warnings too, and `--format json` for a machine-readable report.

### 3. Run validate-profiles on a subset of profiles

`validate-profiles` takes a directory and scans its immediate subdirectories for
`profile.yaml` files. Targeting a single profile is not directly supported; the argument
must be a directory whose children are profile directories. To iterate on a single profile,
place it under a scratch directory and pass that directory:

```sh
mkdir -p /tmp/profile-check
cp -r profiles/example-civil-registration /tmp/profile-check/
cargo run --locked -p registry-manifest-cli -- validate-profiles /tmp/profile-check
```

This validates only the profiles in `/tmp/profile-check` rather than the full suite.

### 4. Understand the failure output

Each finding is printed as:

```text
error[manifest.profile.required-concept-missing] profiles/example/profile.yaml:12:11 /required_concepts/0/iri
  no field of the fixture references this concept
  next: Reference the concept from a field's concepts list in the fixture.
  note: profiles/example/fixtures/metadata.yaml the fixture checked against this expectation
```

The first line names the code, the file, line, and column, and the member's JSON Pointer. An
expectation a fixture does not meet is placed at the expectation in the descriptor, and its
`note:` line names the fixture.

Common findings:

- **`manifest.profile.claim-missing`**: the fixture does not list the profile's `id` and
  `version` under its `profiles`. Add them.
- **`manifest.profile.required-concept-missing`**: no field of the fixture references an IRI
  the profile marks as required. Add the concept to the appropriate field in the manifest.
- **`manifest.profile.identifier-missing`**: the fixture's entity does not declare the required
  identifier name and kind.
- **`manifest.profile.codelist-mismatch`**: the fixture declares no codelist with the expected
  ID, or its codelist does not hold a required code.
- **`manifest.profile.cardinality-mismatch`**: the field appears too few or too many times in
  the entity.
- **`manifest.profile.missing-fixture`** and **`manifest.profile.fixture-path-escapes`**: a
  listed fixture path does not exist, or does not stay inside the profile's directory.
- **`manifest.metadata.runtime-only-key`**: the fixture manifest contains a key that must not
  appear in a portable manifest (a manifest that carries only static metadata and no
  deployment-specific bindings). Examples: `source`, `table`, `scope`, `url_env`.
  Remove the key; it belongs in service configuration, not in a portable fixture.

The authoritative list of disallowed runtime keys is in [Registry Manifest reference](./reference.md).

### 5. Add a new profile

If you are authoring a new domain profile (for example, adapting Registry Manifest to a new
program area or official standard), follow these steps to create and validate it:

1. Create a directory under `profiles/<your-profile-id>/`.
2. Write `profile.yaml` with `schema_version: registry-manifest-profile/v1`.
3. Declare `required_concepts`, `required_identifiers`, `codelist_expectations`, and
   `cardinality_expectations` for the entities the profile governs.
4. Add a `fixtures/metadata.yaml` that satisfies all the declared requirements.
5. List the fixture path under `fixtures:` in `profile.yaml`.
6. Run `validate-profiles profiles` to confirm the fixture passes alongside all existing profiles.

See
[`profiles/example-civil-registration/profile.yaml`](../profiles/example-civil-registration/profile.yaml)
for a complete example.

## Verification

After running `validate-profiles`, confirm the exit code:

```sh
cargo run --locked -p registry-manifest-cli -- validate-profiles profiles
echo "exit code: $?"
```

Exit code 0 means every profile descriptor and every referenced fixture passed.

To confirm the profile gate also covers all five example profiles, run:

```sh
cargo run --locked -p registry-manifest-cli -- validate-profiles profiles
```

This command asserts that all five example profile descriptors and fixtures pass
manifest validation.

## Troubleshooting

### `config.unknown-variant` at `/schema_version` on profile.yaml

The profile descriptor must declare `schema_version: registry-manifest-profile/v1`.
Do not use `registry-manifest/v1` (which is the manifest schema version) in the descriptor.

### `manifest.profile.required-concept-missing` on a concept you believe is present

Check the IRI spelling exactly.
The validator matches concept IRIs as strings, so a namespace prefix mismatch
(`person:Person.identifier` versus `person:person.identifier`) causes a miss.
Prefixes are not expanded: write the IRI in the profile descriptor exactly as it appears in
the fixture manifest's `concepts` list.

### `manifest.metadata.runtime-only-key` in fixture

Remove keys such as `source`, `source_id`, `table`, `scope`, `url`, `url_env`, `file_path`,
`query`, `required_filters`, `rows_scope`, `bindings`, `capabilities`, `column`, or
`visibility` from the fixture manifest.
These keys belong in service runtime configuration, not in a portable metadata manifest.

### validate-profiles passes locally but fails in CI

Confirm you are running against the same `profiles/` directory path as CI.
The validator uses the path you pass as its argument.
Root CI enters `products/manifest` and runs
`cargo run --locked -p registry-manifest-cli -- validate-profiles profiles`.
