# Reviewed source to Evidence journey

This executable synthetic journey connects one BReg correction, independent
Casework review, separately authorized source application, and an Evidence
consumer. A generic record starts as `retired`; a correction changes it to
`active`. Evidence returns only the Boolean `active`, first false, then true.
The consumer prepares its request and verification pins with `evidencectl`,
sends it over HTTP, and verifies the signed response offline with the maintained
Evidence client and verifier behind `evidencectl verify`.

This is a reusable composition proof. It supplies no domain model,
institutional role, legal approval rule, eligibility threshold, portal, or
production deployment. Every actor, identifier, source value and credential is
synthetic. BReg, Casework and Evidence are real executables. The token issuer is
an explicit test double: it issues prebuilt tokens for named clients and checks
request shape, without verifying client assertions. This does not establish
production OAuth operation.

## Run

Prerequisites: matching `breg`, `bregctl`, `casework`, `caseworkctl`, `evidence`
and `evidencectl` binaries; Docker; OpenSSL; `psql`; `curl`; and `uv` with a
Python version managed by the host. Run these commands from the repository root.
Build once if matching binaries are not already available:

```sh
PATH="$HOME/.cargo/bin:$PATH" \
  CARGO_TARGET_DIR=/absolute/owned/target \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo build --locked -j2 \
  -p registry-breg -p registry-bregctl -p registry-casework \
  -p registry-caseworkctl -p registry-evidence -p registry-evidencectl --bins
```

On macOS direct Cargo-built binaries need the AWS-LC FIPS library directory in
`DYLD_FALLBACK_LIBRARY_PATH`. Use the maintained
`scripts/cargo-runtime-library-path.sh` build helper when preparing those
binaries, or preserve the exact library path from the build's Cargo messages.
Released executables use their installation's runtime dependencies.

```sh
uv sync --locked --project products/breg/acceptance/reviewed-evidence-journey
uv run --locked --project products/breg/acceptance/reviewed-evidence-journey \
  python -m unittest discover \
  -s products/breg/acceptance/reviewed-evidence-journey/tests -v
uv run --locked --project products/breg/acceptance/reviewed-evidence-journey \
  python products/breg/acceptance/reviewed-evidence-journey/tests/run_live.py \
  --bin-dir /absolute/matching/bin \
  --output /absolute/owned/scratch/fresh-run
ruff check --no-cache products/breg/acceptance/reviewed-evidence-journey/tests
ruff format --no-cache --check products/breg/acceptance/reviewed-evidence-journey/tests
```

`--output` must not exist. It retains owner-only keys, tokens, configuration,
receipts and logs. Keep it private. The runner creates its own pinned
PostgreSQL 17.11 container on loopback, generates a local CA, requires TLS,
and proves plaintext refusal. It creates separate schema-test, source and
Casework databases with separate migration/runtime roles. Products never read
or write one another's tables. Cleanup stops child services and removes only
this run's databases, roles and container, then records the observed result.
Generated output is retained for inspection, including after a failed run.

## What it proves

1. BReg checks the authored project, executes the source lookup schema-test
   journey, publishes the resulting receipt-bound package, activates it and
   verifies its database before starting the real service.
2. Casework verifies and pairs the exact native context schema from that BReg
   package. It checks and packages its policy and activates its separate database.
   The administrator staffs its queue through the public Directory API.
3. The source exports only its lookup identity fields and `status`. Evidence
   imports the generated source contract into an ordinary normalized project,
   checks it, runs the maintained 11 source/derivation/privacy fixtures, packages
   it and activates the separately compiled caller authority.
4. An independent consumer verifies a signed false assertion from the retired
   source record. A human author submits a frozen correction under an explicit
   ID-only `status-review` policy selection. Casework freezes the concrete
   `{id, version, digest}` binding at acceptance. The source retains and exposes
   the exact accepted provider request ID under its service-status grant.
5. A separate synthetic human reads current-source review context, claims the
   exact task and approves it. The runner compares request, policy, subject,
   submission version, effect digest and submission digest with the immutable
   result. Review approval leaves the source unchanged until explicit application.
6. The independently authorized applier commits the exact frozen correction.
   Reviewer, producer and source lookup credentials cannot apply it. Direct
   Patch cannot bypass the source's Proposal-required mutation policy; even the
   authorized applier cannot apply before approval.
7. The consumer prepares a new request, verifies a signed true assertion from
   the corrected source, and checks the exact Boolean output and absence of
   private labels, business identifiers and raw status. An ungranted caller is
   refused and a tampered signature produces no verified output.
8. Cleanup verifies that child processes, owned databases, roles and container
   are gone. A failed cleanup fails the journey.

The unit suite tests the acceptance oracle with deliberately mismatched review
identities, policies, digests, decisions, disclosed values and cleanup receipts.
It also refuses before/after pairs whose subject, contract or issuer drifts.
`products/breg/scripts/check-contracts.sh` runs this unit suite. The live run
needs Docker and matching binaries and runs only when invoked.
The 11 Evidence fixtures are synthetic calculation and protocol checks. The
combined run is real-runtime HTTP proof. Neither establishes released artifact
installation, production issuer integration, outages, upgrades, or production
readiness.

## Authored and generated inputs

`registry/` is an authored adaptation of `products/breg/evidence/registry`.
It adds a reviewed fixed-plan status correction, manual application and narrow
reviewer/applier/status profiles. Its unrestricted rows are intentional for
this single synthetic namespace and are reported as compiler advisories.
The source Record's private label is excluded from the Evidence lookup grant.

`casework/` owns the synthetic review policy. Its vendored display schema and
contract pins come from the generated `correct-status` review-context artifacts
in the tested BReg package. After changing the source context, regenerate that
package with `bregctl test` and `bregctl package`, copy the exact schema bytes
named by `generated/review-context-schemas/index.json`, and update the three
contract members together. `caseworkctl provider pair` verifies the agreement;
it does not authorize or alter source writes.

The runner copies authored fixtures into the fresh output tree. It imports the
BReg-generated Evidence source, then reuses the maintained `record-active`
definition, Function and 11 cases from `products/breg/evidence/starter`.
Environment origins, test issuer identities, secret references and credentials
are generated separately in that output tree. The crypto helpers come from the
maintained farmer-landholding Evidence runner; its HTTP source is never used.
`inputs.json` records input hashes, binary hashes and reported binary versions.
Use `--runtime-source-revision FULL_GIT_COMMIT` when the build source is known;
that source label is operator supplied, while the binary hashes are measured.
Package reports, schema-test receipt, source export inventory, accepted review
and correlated result retain the concrete identities used. No generated
credential belongs in Git.
