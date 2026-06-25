# Contributing

Registry Stack uses a maintainer-led governance model. Contributions, bug
reports, questions, and review notes are welcome. Maintainers review incoming
work according to project priorities, release risk, and available review
capacity.

## Maintainer Workflow

- Maintainers may merge their own pull requests when the change is scoped and
  the relevant checks have passed.
- Maintainers may push directly to `main` for release, documentation, CI,
  administrative, or urgent fixes.
- CI remains the reference gate for normal pull requests.
- Required human review should be enabled only when maintainer capacity can
  satisfy it reliably.

## Scope

Keep changes focused on the owning area:

- `crates/` for Rust crates and runnable binaries.
- `products/` for product-owned specs, examples, fixtures, and docs.
- `docs/site/` for the public documentation site.
- `lab/` for Registry Lab demos and source proof scripts.
- `release/` for public release manifests, schemas, notes, and tooling.

Private planning, release evidence that is not already public, credentials,
hosted deployment details, and internal review notes do not belong in this
repository.

## Before Opening A Pull Request

Run the checks that match the files you changed. The full current gate is in
`.github/workflows/ci.yml`.

Every change proposal or pull request for major new functionality MUST add
tests for the new functionality to an automated test suite. The test coverage
must exercise the behavior at the lowest practical level, such as Rust unit or
integration tests, Python unittest coverage for scripts, Node test coverage for
docs or UI scripts, or an existing product-specific automated suite. If a
maintainer determines that a change is not major new functionality, the pull
request should say so in the testing notes.

Rust workspace:

```bash
cargo metadata --locked --format-version 1
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo test --locked -p registryctl
```

Release and lab source checks:

```bash
python3 -m unittest release/scripts/test_registry_release.py
release/scripts/registry-release validate release/manifests/registry-stack-beta-6.yaml
release/scripts/registry-release audit release/manifests/import-map-2026-06-24.yaml
REGISTRY_LAB_RELEASE_SOURCE_MODE=monorepo lab/scripts/check-release-source-model.sh
python3 -m unittest lab/scripts/test_check_release_source_model.py
```

Docs checks:

```bash
cd docs/site
npm ci
npm test
npm run check
```

If you cannot run a relevant check, say which command was skipped and why.

## Repeatable Builds And Generated Outputs

Release builds and generated repository outputs MUST be repeatable from the
same source commit and lockfiles with exactly the same bit-for-bit result.
Release binaries are built from the verified release tag, the pinned Rust
builder image, and locked Cargo dependencies in `.github/workflows/release.yml`.
The workflow records SHA256 manifests for binary outputs, image input binaries,
image evidence, and release capsules, then reconciles published release assets
against the generated files.

Generated documentation data and checked-in generated snapshots must be produced
by the documented generator commands, such as `npm run generate` under
`docs/site`, and committed only when rerunning the generator from the same
source tree produces the same bytes. Do not introduce generators that depend on
wall-clock time, unordered traversal, ambient local paths, network responses, or
unlocked dependencies unless the generated output is normalized or pinned so the
same source can reproduce it exactly.

## Security Reports

Do not open public issues or pull requests for suspected credential disclosure,
auth bypass, audit redaction failure, source connector data leakage, signing key
handling bugs, or other vulnerabilities. Follow [SECURITY.md](SECURITY.md).
