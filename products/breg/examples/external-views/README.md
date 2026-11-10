# Synthetic licensing views

The [native project](registry.yaml) owns licences and licensed businesses.
The Population Registry owns Person names. The Business Registry owns the
shareholding rows. BReg stores the local facts and the references in its
ordinary Record payloads. Live and indexed external views are separate
permissions on the same local root.

| View | Root and source | Officer access |
|---|---|---|
| `licence-holder-live` | Licence → Population Registry Person | Live detail |
| `licence-holder-indexed` | Licence → Population Registry Person | Indexed detail, exact surname filter, ordering and count |
| `business-holdings-live` | Licensed business → Business Registry holdings | Live related detail |
| `business-holdings-indexed` | Licensed business → Business Registry holdings | Indexed collection, class filter, share count order, and a separately granted Person label |

Two licences and a holding reuse the same indexed Person projection.
A company shareholder has a Business key and no Person key, so the
company row remains visible without a Person lookup. The restricted
profile reads the same local licences and businesses without any external
disclosure or query permission. The refresh profile uses a dedicated
service identity, has only the approved refresh scopes, and can list local
roots only in its assigned jurisdiction.

Check the project with the candidate `bregctl`:

```sh
bregctl check products/breg/examples/external-views
```

The [dev clients and seed records](dev-clients.yaml) provide synthetic
identities and roots for an isolated deployment. This directory is an
acceptance example and is not included in the shipped starter catalog.

## Run the synthetic source

Use separate owner-only files for the two fixture credentials. The
runtime's configured file secret provider must resolve the service key
file. Only the test driver receives the control key. Start the source:

```sh
python3 products/breg/examples/external-views/synthetic_source.py \
  --service-key-file "$FIXTURE_SERVICE_KEY_FILE" \
  --control-key-file "$FIXTURE_CONTROL_KEY_FILE" \
  --runtime-fragment-file "$FIXTURE_RUNTIME_FRAGMENT"
```

The source binds only to numeric loopback, chooses a free port, and
prints its origin. The fragment pins the exact [Adapter pack](../../../adapter/examples/external-projections/pack.yaml),
binds its endpoint and scope for each projection, and names the service
key by secret reference. Merge the `externalSources` member into an
operator-owned runtime file before starting the candidate BReg. The
fragment grants an hour of synthetic source access. Indexed values keep the
authored five minute cache lifetime and are purged when it ends, so refresh
again for a continued demo, or run the fixture refresh requests below.

The fixture control identity can reset or rename the Person, replace or
empty holdings, interrupt the next page, apply `no-store` to a data
operation, or simulate denied, ambiguous and disconnected Person reads.
`hold-next` captures a response before pausing it; another request can
complete before the controller releases it. The control status reports
value-free operation counts and whether a response is held. The service
credential cannot use the control endpoints.

Test the source and its snapshot discipline independently:

```sh
python3 -B products/breg/examples/external-views/test_source.py
```

See the [operator guide](../../external-projection-storage.md) for refresh, retention,
scope changes and backup recovery.

## Run with candidate binaries

Indexed projections require separate PostgreSQL migration and runtime roles
for activation and serving. The candidate development configuration selects
those roles when the project declares an indexed projection. Use the
[candidate runner](../../loadtest/external-views/run_candidate.py) to supply the
synthetic source bindings and run the HTTP checks.

Prepare two fresh databases on the same disposable loopback PostgreSQL TLS
server. Use names such as `breg_ext_rehearsal` and `breg_ext_runtime`.
Create two non-superuser login roles and configure them in both databases.
The migration role owns `registry_internal`, `registry_data`,
`registry_source`, `registry_derived` and `registry_context`. The runtime role
has no ownership, membership in the migration role, or `BYPASSRLS`. Install
`btree_gist` in each database, revoke public access to the databases and
managed schemas, and grant both roles database `CONNECT`. BReg grants the
runtime permissions during activation. The adopter workflow has the same
role and schema setup. [Existing adopter fixture](../../scripts/test-adopter-workflow.sh)

Put the four PostgreSQL URLs in owner-only files named
`rehearsal-migration-url`, `rehearsal-runtime-url`, `migration-url`, and
`runtime-url`. Use the same respective role in each database. Each URL
needs an explicit loopback host, port, database and `?sslmode=require`.
Supply the local PostgreSQL CA PEM separately.

```sh
python3 -B products/breg/loadtest/external-views/run_candidate.py \
  --breg-bin "$BREG_BIN" \
  --bregctl-bin "$BREGCTL_BIN" \
  --database-url-dir "$FIXTURE_DATABASE_URL_DIR" \
  --postgres-ca-file "$BREG_TEST_TLS_CA_PEM_PATH" \
  --work-dir "$FIXTURE_NEW_WORK_DIR"
```

The runner rehearses ordinary Record creation and packages the tested project.
Before activation it generates and validates an owner-only
`external-source-facts.json` for all four bindings. The facts can be
imported into Studio and the check verifies that generation made no source
requests. The runner then activates, serves and seeds the package with the
supplied binaries. A local EdDSA fixture signer issues short-lived tokens
that the candidate verifies
against static JWKS. The synthetic source runs on a loopback port for the
HTTP journey. The runner stops its own processes and leaves the two
databases and owner-only evidence directory available for inspection. A
repeat run needs fresh databases and a new work directory.

To exercise an equivalent native project saved by Studio, add
`--project-dir "$FIXTURE_STUDIO_PROJECT_DIR"`. Supply the saved
`registry.yaml`, `dev-clients.yaml`, and `tests/journeys.yaml`. The runner
stages those three files unchanged and applies the same binding and HTTP
checks.

Add `--recovery` to the small candidate runner to exercise migration-role
scope maintenance with `bregctl external-projection` and the staged runtime
configuration. The runner pauses the first source response of a paged holdings
refresh, withdraws the inspected scope, and checks that the in-flight
refresh sends no later source requests or restores indexed data. It
rotates the scope under the configured synthetic binding, checks the
rotated digests against the generated source facts, restarts BReg,
and verifies that indexed coverage remains incomplete until an explicit
fresh refresh. Owner-only `scope-*.json` and `recovery-*.json` reports
record the transition and operation counts.

## Run the HTTP checks against an existing fixture

Use the same split roles and seed the supplied records under the fixture
editor. Obtain short-lived officer, restricted and refresh tokens and keep
them in owner-only files. The refresh token must carry the verified service
actor and requester client `licensing-refresh`. Pass the local root IDs
for `licence-first` and `business-with-holdings` to the runner.

```sh
python3 products/breg/examples/external-views/journey.py \
  --breg-origin "$FIXTURE_BREG_ORIGIN" \
  --source-origin "$FIXTURE_SOURCE_ORIGIN" \
  --officer-token-file "$FIXTURE_OFFICER_TOKEN_FILE" \
  --restricted-token-file "$FIXTURE_RESTRICTED_TOKEN_FILE" \
  --refresh-token-file "$FIXTURE_REFRESH_TOKEN_FILE" \
  --control-key-file "$FIXTURE_CONTROL_KEY_FILE" \
  --licence-root "$FIXTURE_LICENCE_ID" \
  --business-root "$FIXTURE_BUSINESS_ID"
```

The runner exercises live exact and related reads, role concealment before
and after refresh, surname count and paging across unopened licences,
authorized absence, label reuse, company shareholders, retention refusal,
complete snapshot replacement, and interrupted acquisition. It verifies that
a retained Person becomes unavailable after source denial, ambiguity or
disconnection and that recovery restores coverage. Source call counts check
that indexed and denied reads skip acquisition. Database races, expiry
purges and scale have separate acceptance checks.


## Run the million-record fixture

The scale exercise is load-test tooling and lives beside the other BReg load tests. It uses the same candidate binaries, split roles and TLS
setup with a larger synthetic corpus. It sets an explicit freshness and
request budget and records the actual native timings and PostgreSQL plans.
[Scale fixture instructions](../../loadtest/external-views/SCALE.md)
