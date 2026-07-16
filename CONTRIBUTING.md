# Contributing

Registry Stack uses a maintainer-led governance model. Contributions, bug
reports, questions, and review notes are welcome. Maintainers review incoming
work according to project priorities, release risk, and available review
capacity.

## Contribution License

Registry Stack uses the [Developer Certificate of Origin
1.1](https://developercertificate.org/) for inbound contributions. By
contributing, you certify that you have the right to submit the work under this
repository's license and that the contribution can be included in the project.

Add a `Signed-off-by` trailer to every commit:

```bash
git commit -s
```

The trailer must use your real name or established project identity and an
email address you are willing to associate with the contribution:

```text
Signed-off-by: Name <name@example.com>
```

Pull requests are checked automatically for this trailer.

You may use coding agents or other automation while preparing a change. The
person who commits, signs off, and submits the contribution is responsible for
reviewing the result, running the relevant checks, and making sure the DCO
certification is true.

## Maintainer Workflow

- Maintainers may merge their own pull requests when the change is scoped and
  the relevant checks have passed.
- Maintainers may push directly to `main` for release, documentation, CI,
  administrative, or urgent fixes.
- CI remains the reference gate for normal pull requests.
- Required human review should be enabled only when maintainer capacity can
  satisfy it reliably.

## Review Standards

Every pull request should make the review path clear:

- Explain the user-visible or operator-visible impact in the pull request
  summary.
- Keep changes scoped to one owning area whenever practical.
- Call out release, security, migration, compatibility, privacy, or governance
  concerns in the pull request notes.
- Run the checks that match the changed files, or state exactly which relevant
  check was skipped and why.
- Include tests for major functionality and bug fixes. If a test cannot be
  added, explain why in the pull request.
- Treat changes to authentication, authorization, credential issuance, signing,
  audit integrity, release provenance, deployment defaults, or data minimization
  as security-sensitive. These changes need explicit maintainer review notes,
  even when the maintainer is also the author.

## Dependency Changes

New or changed release dependencies must follow the
[`Dependency Vetting Policy`](release/notes/dependency-vetting-policy.md).
Document why the dependency is needed, whether it is runtime or tool-only,
license and advisory status, feature selection, transitive impact, and any
accepted risk with a review trigger.

Git dependencies require an immutable commit pin, a rationale, and a documented
review trigger. Crosswalk's current pin rationale lives in
[`external/README.md`](external/README.md).

## Scope

Keep changes focused on the owning area:

- `crates/` for Rust crates and runnable binaries.
- `products/` for product-owned specs, examples, fixtures, and docs.
- `docs/site/` for the public documentation site.
- `release/` for public release manifests, schemas, notes, and tooling.

Private planning, release evidence that is not already public, credentials,
hosted deployment details, and internal review notes do not belong in this
repository.

## Issue Labels

Public GitHub issue labels can help identify scope and priority. Start with:

- [`enhancement`](https://github.com/registrystack/registry-stack/issues?q=is%3Aissue%20is%3Aopen%20label%3Aenhancement):
  product, docs, or release improvements.
- [`criticality:p3`](https://github.com/registrystack/registry-stack/issues?q=is%3Aissue%20is%3Aopen%20label%3Acriticality%3Ap3):
  lower-risk work that is usually safer for first contributions than release or
  security-critical changes.

If an issue looks too broad, ask for a smaller slice before opening a pull
request.

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

Major bug fixes should include the smallest relevant automated test, fixture,
or docs check that proves the behavior. If a change is documentation-only, say
so in the pull request checks section. If a code change genuinely cannot be
tested, explain the reason and the manual or review evidence used instead.

Rust workspace:

```bash
cargo metadata --locked --format-version 1
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check
(cd products/notary && just openapi-check)
(cd crates/registry-relay && just openapi-contract)
```

The root gate runs the full `cargo deny check`, advisories included. Open
RUSTSEC advisories with no upstream fix are ignored in `deny.toml` with a
scoped rationale and a review trigger; a newly published advisory fails CI
until it is fixed or gets its own documented ignore.

Release source checks:

These checks require Python 3.11 or later.

```bash
python3 -m unittest release/scripts/test_registry_release.py
python3 -m unittest release/scripts/test_openid_conformance_runner.py
release/scripts/registry-release validate release/manifests/registry-stack-beta-11.yaml
release/scripts/registry-release audit release/manifests/import-map-2026-06-24.yaml
REGISTRY_RELEASE_SOURCE_MODE=monorepo release/scripts/check-release-source-model.sh
python3 -m unittest release/scripts/test_check_release_source_model.py
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
against the generated files. Public repeatable-build evidence for release
binaries is recorded in [`release/REPEATABLE-BUILDS.md`](release/REPEATABLE-BUILDS.md).

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
