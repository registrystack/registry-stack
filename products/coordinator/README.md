# Registry Coordinator

Use Registry Coordinator when your institution needs a reviewed sequence of calls to continue
across durable waits, outages, and worker restarts. One optional Rust service executes finite,
acyclic workflows. PostgreSQL stores encrypted progress and prepared commands. Receiving products
retain authority and ownership of every effect.

The [Coordinator overview](https://docs.registrystack.org/start/coordinator/) defines the
boundary; [Deploy Registry Coordinator](https://docs.registrystack.org/operate/coordinator/) covers
installation, custody, activation, and recovery.
Coordinator is one of the six products the Registry Stack 1.0 compatibility promise covers: the
workflow model, run API, and `coordinator` client namespace. Before 1.0, use one source version's
binaries, packages, configuration, and state layout together. The current protected state schema
is version 7, with no in-place migration from earlier layouts.

Build the Coordinator service, operator CLI, client, and client bindings from source using
the [deployment guide](https://docs.registrystack.org/operate/coordinator/#install-and-package) and the client crate instructions. Release packaging includes the
`coordinator` and `coordinatorctl` binaries and their installer, and the `coordinator` namespace of
the unified Node.js and Python client packages, from v0.44.0. The container image remains held.
The [archive-based tutorial](https://docs.registrystack.org/dev/tutorials/review-an-application-and-send-a-notice/)
uses those release assets.

Coordinator is optional. A direct application can prepare a BReg Proposal, obtain Casework review
of its exact version and effects, and ask BReg to apply it without running Coordinator. Every
product retains its own authorization and source mutation boundary.

## Create and check a project

From the maintained Registry Stack checkout:

```sh
cargo run --locked -p registry-coordinator --bin coordinatorctl -- init --directory ./my-follow-up
cargo run --locked -p registry-coordinator --bin coordinatorctl -- check --project ./my-follow-up --explain
coordinatorctl test --project ./my-follow-up
```

For subsequent commands, install the executable as the
[deployment guide](https://docs.registrystack.org/operate/coordinator/#install-and-package) describes, or use
that `cargo run` prefix followed by `--`. Init accepts a new or empty directory. The starter
contains `workflow.yaml`, `functions.rhai`, `runtime.yaml`, `scenarios.yaml`, and a `.gitignore`
for local `.coordinator/` state.
[Author a Coordinator workflow](https://docs.registrystack.org/configure/coordinator/) covers the
project, its mappings, waits, and checks.

## Start from a maintained project

- [Delayed follow-up](examples/delayed-follow-up/README.md) waits, reads current permission, and
  submits a separate Messaging notice.
- [Deferred appointment](examples/deferred-appointment/README.md) retains explicit deferred
  Casework task authority across a wait before a Scheduling commitment.
- [Approved record check](examples/approved-record-check/README.md) reads Base Registry Engine (BReg) under task authority.
- [Record lookup](examples/record-lookup/README.md) finds one BReg record by identifier, routes
  `unresolved` to a finish, and reads the record again with provenance.
- [Governed action follow-up](examples/governed-action-follow-up/README.md) uses an exact imported
  immediate BReg Action contract, then submits a separate notice.
- [Decision follow-up](examples/decision-follow-up/README.md) interprets a typed evaluation before
  a separately authorized BReg Action.
- [Standalone review](examples/standalone-review/README.md) submits a source-neutral Casework
  request using an explicit policy pin and waits for its result. An ID-only selector is the
  ordinary default; these examples also demonstrate the optional exact-pin form.
- [Reviewed notice](examples/reviewed-notice/README.md) combines standalone review with a fresh
  record and permission check before Messaging.
- [Product events](examples/product-events/README.md) admits committed BReg events and a
  conforming alternate-source fixture through the same signed event contract.
- [External directory](examples/external-directory/README.md) performs a configured HTTP GET.
- [External job](examples/external-job/README.md) uses a bounded completion poll and pure
  interpreter for one previously selected external job.
- [Payment collection](examples/payment-collections/README.md) requests one Adapter-owned
  collection, waits for its named completion, and records only a confirmed receipt.
- [Disbursement](examples/g2p-disbursements/README.md) submits one approved instruction,
  waits for the correlated provider observation, and reports verified provider completion.

## Package and deploy

```sh
coordinatorctl package --project ./my-follow-up --output ./my-follow-up-package
coordinatorctl types --project ./my-follow-up --language typescript --output ./follow-up.ts
coordinatorctl types --project ./my-follow-up --language python --output ./follow_up.py
```

Package refuses existing output and failing scenarios. The deployment guide covers
[the package digest, activation, and caller policies](https://docs.registrystack.org/operate/coordinator/#apply-and-start),
[run recovery](https://docs.registrystack.org/operate/coordinator/#recover-a-run), and
[backup and restore](https://docs.registrystack.org/operate/coordinator/#back-up-and-restore).
[Registry Coordinator configuration reference](https://docs.registrystack.org/reference/coordinator-configuration/)
lists the file contracts and connections.

## Verify a change

The owning Cargo tests cover authoring, deterministic scenarios, runtime config,
package integrity, OIDC policy, product adapter boundaries, Scheduling command
recovery and the authoring of review waits. The PostgreSQL feature gates protect database-dependent suites from
ordinary workspace test runs, so this command runs every suite that needs no database:

```sh
cargo test --locked -p registry-coordinator --features schema
products/coordinator/scripts/check-schemas.sh
```

The schema check generates temporary outputs and compares them with the committed schemas and
OpenAPI document. It does not rewrite tracked artifacts; regenerate changed artifacts explicitly
with their owning generators.

With three dedicated disposable PostgreSQL 17+ databases configured, use
`scripts/test-postgres.sh` for the maintained durable-state, encrypted-custody,
restart, deployment/router, review waits, standalone review, bounded external waits, and
Messaging and Scheduling integration checks. The three URLs must name distinct databases owned
by the test identity. That script first builds the independent Messaging and Scheduling services
and operator executables, then supplies `COORDINATOR_MESSAGING_BIN`,
`COORDINATOR_MESSAGINGCTL_BIN`, `COORDINATOR_SCHEDULING_BIN`, and
`COORDINATOR_SCHEDULINGCTL_BIN` to the tests. The integration fixtures compose through the
products' public HTTP contracts and refuse missing executables; Coordinator does not link their
runtimes as test dependencies.

```sh
COORDINATOR_TEST_DATABASE_URL=<owned-loopback-coordinator-database-url> \
COORDINATOR_MESSAGING_TEST_DATABASE_URL=<owned-loopback-messaging-database-url> \
COORDINATOR_SCHEDULING_TEST_DATABASE_URL=<owned-loopback-scheduling-database-url> \
  products/coordinator/scripts/test-postgres.sh
```

The native-service
fixture script runs the controlled BReg, Casework, Scheduling and Messaging
journey. It requires Python 3, OpenSSL, PostgreSQL client tools matching the test server,
Docker, and distinct disposable PostgreSQL databases. Use the explicit preparation command below
to build all ten service/operator binaries and the `reviewed-notice-input` helper with the required
features. Those contributor checks do not replace the deployment guide or imply
production credentials are needed to author a project.

Run the generated TypeScript and Python client proofs with one owned disposable PostgreSQL 17+
database. The identity must create and drop the fixtures' unique schemas and roles. The helper
prepares the current Coordinator bindings and their FIPS/module paths; it needs the Cargo native
build toolchain, Python 3, Node/npm matching the binding packages, and Pyright on `PATH`.
Use `--pyright /absolute/path/pyright` to select another local installation. Missing Node development
dependencies are installed locally with the binding's pinned `npm ci`.

```sh
COORDINATOR_TEST_DATABASE_URL=<owned-loopback-database-url> \
  python3 products/coordinator/scripts/test-generated-clients.py
```

This check runs the strict TypeScript intersection regression and the four projects' generated
TypeScript/Python admission, status, cancellation, and revision-refusal journeys. The external-job
project additionally consumes a successful typed terminal outcome in both languages. It needs no
Messaging database, product service binaries, Docker, or global package installation.

The governed-action and external-directory examples have deterministic scenarios;
adapter checks use mock HTTP services and durable-state checks use PostgreSQL.
For native BReg action and notice acceptance, run this explicit helper from the checkout:

```sh
python3 products/coordinator/scripts/test-breg-action.py --env /absolute/path/coordinator-test.env
```

Provide Python 3, the current checkout's Cargo build prerequisites, and
distinct `COORDINATOR_TEST_DATABASE_URL` and
`COORDINATOR_MESSAGING_TEST_DATABASE_URL` values in the environment or named file.
Each URL must name an owned disposable PostgreSQL 17+ database on loopback.
The Coordinator database identity needs authority to create and drop unique
fixture databases and roles; both database identities must create and drop
fixture schemas. The helper builds current `breg`, `bregctl`, `messaging` and
`messagingctl` binaries and provisions synthetic credentials and data. Successful
runs clean up UUID-owned fixture resources without resetting the named databases.
Assertion failures can retain diagnostic Coordinator and Messaging schemas.
No live service credentials are required.

Native checks distinguish adapter reconstruction, worker reconstruction, and OS-process restart.
The separate native service journey composes BReg, Casework, Scheduling, and Messaging over their
public HTTP contracts with Casework review tasks, exact policy bindings, and durable Coordinator waits.

Prepare native executables once from the checkout, using a new private output directory outside
its source roots. Preparation needs the Rust/native build toolchain but starts no service and
requires no database URLs. It honors `CARGO_TARGET_DIR`, captures source identities before and
after the build, and refuses a source change during compilation. It freezes all ten executables,
`reviewed-notice-input`, and the exact macOS FIPS library with their hashes in `build-manifest.json`.
Existing output is never overwritten.

```sh
python3 products/coordinator/scripts/test-real-services.py --prepare /absolute/private/native-build
```

Then configure the two disposable database URLs described earlier and run the composition:

```sh
python3 products/coordinator/scripts/test-real-services.py \
  --bin-dir /absolute/private/native-build/bin \
  --build-manifest /absolute/private/native-build/build-manifest.json --wait-seconds 961
```

A supplied `--bin-dir` uses existing executables without rebuilding. Without it, the helper uses
Cargo metadata's `target_directory/debug`; that directory must already contain every required
executable. Retain the preparation directory until the journey has finished.

The reservation-review example has its own compiled-service proof. It composes BReg, Casework
(a real task grant and the BReg task-grant context read), Scheduling, Messaging and Coordinator,
restarts Coordinator while reviews are pending, and recovers lost Scheduling and BReg responses
as the exact same commands. It is a manual proof that no CI job runs. Prepare the executables as
above, set the same two database URLs, and run:

```sh
python3 products/coordinator/examples/reservation-review/test-native-services.py \
  --bin-dir /absolute/private/native-build/bin \
  --build-manifest /absolute/private/native-build/build-manifest.json
```

The real 961-second deferred-appointment wait crosses the immediate approval limit; a wait below
901 seconds is a smoke check only. Exact original-receipt recovery, expiry and revocation checks,
and message acceptance are distinct from recipient delivery. Offline scenarios do not establish
these native product effects.
