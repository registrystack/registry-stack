# Run a project for development

Use `rstack dev` to start a checkout's BReg and Casework projects together.
Install matching BReg and Casework components and supply a dedicated development
PostgreSQL server over TLS. `rstack dev` does not start PostgreSQL and does not
use Docker: you supply the server. The products' own development modes are
unchanged by `rstack dev`.

For a walk-through from a checkout to a running pair, see
[Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/).
This file is the reference.

```sh
rstack install breg casework
# Set RSTACK_DEV_DATABASE_URL through your shell's secret provider.
rstack dev check ./licensing --json
rstack dev start ./licensing --ttl 30m --json
rstack dev status RUN_ID
rstack dev token RUN_ID --as applicant --json
rstack dev stop RUN_ID
```

Run `rstack dev check PROJECT [--deny-warnings] [--json]` to validate the plan
and resolve its fixture, grant, and binding references with the installed
product authoring tools. The check works with the database offline. With
`--json`, it writes a `BRegCtlReport` with `command` set to `dev-check`.
Use `--deny-warnings` to refuse any unaccepted warning.

Start reports the product URLs and the journey result.
A failed journey still produces the normal `registry.rstack.dev.v1` run report:
the report has `status` `ready`, `journey.result` `failed`, the failed step and
its reason, and the live run ID. `start` exits 1, but the supervisor and
products keep running. Use `status` to repeat the report, inspect the products
and logs, and then use `stop` to release the run. This differs from a startup
failure, which produces a `registry.rstack.error.v1` error report and cleans up,
or reports the run ID if cleanup is pending. The TTL starts at readiness and
defaults to 30 minutes.
Supply one whole-number value from `1s` to `24h` with an `s`, `m`, or `h` suffix.

### Start a declared application

An optional `application` block starts one already-built local Node 24 host
beside the products. Set `issuer: run` for this mode and pass its built root at
start with `--application-root DIRECTORY`; omit both for the existing
product-only run. `check` validates the declaration and deployment file without
requiring the built root. The application block names a browser `client`, exact
`callbackPath`, local `healthPath`, built `entry`, configuration `prepare` and
`checker` files, a `deployment` file relative to the development project, the
configuration command's `configSchema` and exact `prepareVersion` line, and the
`configEnvironment` variable through which the host reads its generated file.
The built files must stay inside the supplied root; the deployment file must
stay inside the development project. The entry is explicit, including when the
application uses its own default entry.

Before provisioning, `start` checks Node 24, the built files and the
configuration command's `--version` output. The runner picks a loopback issuer
and application port. After the product journey, it writes an owner-only run
input with the declared schema name, real addresses, product audiences, and
paths to a fresh browser-client secret and optional Casework recovery key. It
requests separate resource grants when Casework is present, invokes the declared
command with `--deployment`, `--run` and `--out`, then
invokes the checker with the generated configuration path. The child receives
only the declared configuration-file environment variable and runs in the
built root. The ready report adds `issuer` and `application` URLs. `status`
repeats them, and `stop`, expiry, or a crashed child stops the issuer and app
alongside the products. Configuration commands and built hosts are trusted
local code supplied by the operator; the runner does not fetch or build them.
A later `start` creates a fresh disposable run and databases; it does not
restore unfinished application work.

The browser issuer presents only the plan's synthetic test people. It issues
one resource-bound token per product after a confidential authorization-code
exchange with S256 PKCE. It grants the intersection of the requested scopes and
the selected person's scopes for that product; a request with no overlap is
refused. Browser tokens carry the same grant in `scope` and `registry_scopes`.
In application mode, `name` is presentation-only and `registry_scopes` carries
the selected person's narrowed host scopes. Do not use either as a BReg or
Casework principal claim or as an additional authored grant claim; `check` and
`start` refuse those configurations.
One browser session can obtain a second product grant for the same person;
`prompt=login` opens the person picker again. The authored
BReg and Casework profiles still decide which client and person can use each
operation. Declare the browser client in the relevant BReg requester profiles;
the runner adds it to the runtime's accepted-client list but does not change
the authored package. Browser tokens last at most 15 minutes and expire with
the run; `rstack dev token` continues to issue five-minute CLI tokens.

The [licensing example](examples/licensing/dev.yaml) creates an application in
BReg, requests approval of the captured application in Casework, and checks the
reviewer's decision. Point `start` at the directory containing `dev.yaml`.
Product files remain byte-for-byte unchanged. Generated runtime settings, keys,
and packages live in the run's owner-only scratch directory.

## Supply the PostgreSQL server

The server must be PostgreSQL 17 or newer and must serve TLS. The runner always
verifies the server certificate and host name. It trusts the platform's roots,
or the CA bundle in PEM format named by `RSTACK_DEV_DATABASE_CA`.

The administrator role named in the URL needs `LOGIN CREATEROLE CREATEDB`.
Superuser is not needed for a non-spatial run. The runner sets
`createrole_self_grant` on its own sessions, so you do not configure it. The
administrator also installs `btree_gist`, which PostgreSQL treats as a trusted
extension.
The runner reads `pg_catalog.pg_control_system()` to identify the cluster for
recovery. PostgreSQL allows this function by default.

The administrator URL always carries a password. Set it through
`RSTACK_DEV_DATABASE_URL`, because `--database-url` is visible to other local
users in the process list. The URL must be a `postgres://` or `postgresql://`
URL with one TCP host, a user, a password and one database name. Percent-encode
special characters in the password. The URL accepts these query parameters and
refuses all others:

- `sslmode`: `require`, `verify-ca` or `verify-full`. The runner verifies the
  certificate and host name whichever you choose.
- `connect_timeout` and `application_name`.
- `sslrootcert` is refused. Set `RSTACK_DEV_DATABASE_CA` instead.

### Spatial projects

A spatial BReg project needs PostGIS 3.5 or later installed on the server. The
administrator must be allowed to `CREATE EXTENSION postgis`, which normally
means a superuser or the managed service's equivalent. The run checks that the
server offers a supported PostGIS before it creates anything.

### A local server

This recipe starts a PostgreSQL 17 or newer server on `127.0.0.1` with a
private certificate authority, and creates a least-privilege administrator. It
uses the PostgreSQL and OpenSSL command-line tools. Keep `DEV` outside any
repository.

```sh
DEV="$HOME/rstack-dev-postgres"
mkdir -p "$DEV"
initdb -D "$DEV/data" -U postgres --auth=scram-sha-256 --pwprompt -E UTF8

openssl req -new -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=rstack-dev-ca \
  -addext basicConstraints=critical,CA:TRUE -keyout "$DEV/ca.key" -out "$DEV/ca.pem"
openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$DEV/data/server.key" -out "$DEV/server.csr"
chmod 600 "$DEV/data/server.key"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
  > "$DEV/server.ext"
openssl x509 -req -in "$DEV/server.csr" -CA "$DEV/ca.pem" -CAkey "$DEV/ca.key" \
  -CAcreateserial -days 30 -extfile "$DEV/server.ext" -out "$DEV/data/server.crt"

printf "listen_addresses = '127.0.0.1'\nport = 5432\nssl = on\n" \
  >> "$DEV/data/postgresql.conf"
pg_ctl -D "$DEV/data" -l "$DEV/postgres.log" -w start

CONNECTION="host=127.0.0.1 port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=$DEV/ca.pem"
psql "$CONNECTION" -c "CREATE ROLE devadmin LOGIN CREATEROLE CREATEDB"
psql "$CONNECTION" -c '\password devadmin'

export RSTACK_DEV_DATABASE_CA="$DEV/ca.pem"
# Set RSTACK_DEV_DATABASE_URL to
# postgresql://devadmin:PASSWORD@127.0.0.1:5432/postgres?sslmode=verify-full
```

For a spatial project, install PostGIS for this server and create the
administrator as a superuser instead.

## Write the development plan

Use the [versioned plan schema](../breg/generated/tools/project-dev.v1alpha1.schema.json).
The plan file starts with the schema modeline that editors read, as the
[licensing example](examples/licensing/dev.yaml) does.
List the project's issuer, product directories and audiences in startup order,
and test people with synthetic subjects and exact product grants. A grant selects
the access profile, scopes, and additional claims. Each selected profile gets
the test person's subject in its principal claim. The products enforce their
ordinary permissions. If several people match a step in the BReg project's
`tests/journeys.yaml`, select its alias under
`schemaTestPeople.<journey-id>.<step-id>`. The run obtains the normal
schema-test receipt before packaging.

Every BReg grant must name an access profile the BReg project declares,
including a profile that carries only proposal permissions and so belongs to no
entity. `rstack dev check` refuses a grant that does not, and so does `start`,
before it provisions anything. The error names the plan pointer, for example
`/people/NAME/grants/breg/profile`. A Casework grant must name an access profile
of the Casework project, reported at `/people/NAME/grants/casework/profile`. The run does not compare
scopes with the profile: a profile's required scopes are a per-entity rule, and
a mismatch appears as a failed journey step.

For a native review handoff, `bindings.bregReviewAuthority` identifies the
Casework producer, and `bindings.caseworkContextProvider` identifies the BReg
context provider and action. `rstack dev check` refuses a binding that names a
review authority or action the BReg project does not declare, or a producer or
context provider the Casework project does not declare; `start` refuses it
before it provisions anything. `check` also writes each binding's product
configuration exactly as `start` does. BReg's review-authority reader and
`caseworkctl check --runtime-config` on the Casework configuration refuse what
each product would refuse at startup, and `check` reports the refusal, with the
rule it broke, at the plan field that produced the value. It refuses a
BReg grant profile that is not the `service-status` profile the Casework context
provider's policy names. A binding requests tokens for the other
product's audience as an OAuth resource, so that audience must be an absolute
URI, such as `urn:example:review`. It requests the scopes of its identity's
grant for that product, so those scopes must be OAuth scope-tokens (no quotes or
backslashes) that fit in 4096 bytes when joined by spaces; `check` reports a
violation at the audience or the grant's `scopes`. The run pairs the provider on a private copy
before packaging. A reviewer whose Casework context call forwards the bearer
to BReg declares both grants, one shared client, and `caseworkContext: true`.
Both grants declare the same scopes and additional claims. Casework reads the
token subject or the BReg principal claim. The token carries both audiences
and the authority explicitly shared by both grants.
See the [native review example](../breg/acceptance/reviewed-evidence-journey/dev.yaml).

### Journey steps

A journey runs 1 to 32 steps in order. Each step names the test person it runs
as (`as`), the product, the method, and a relative path that starts with `/v1/`.
A step sends one of two request bodies:

- `body` is a JSON body.
- `raw` is a non-JSON body for methods other than GET: `contentType` and
  `base64`.

A step can also set the `If-Match`, `Idempotency-Key` and
`Registry-Source-Profile` headers. Use URI-safe characters for values in a path.

Each step asserts the response with `expect`:

- `status` is one accepted HTTP status from 200 to 599, or a list of up to 16.
- `json` maps JSON pointers to exact expected values.
- `checks` lists up to 32 assertions. Each tests one JSON pointer with exactly
  one of `equals`, `length` or `contains`.
- `code` is the problem code an error response must carry.

A step remembers values from its response under `capture`. Refer to a capture
as `{{capture-name}}` in a later step's path, request body, header, expected
value, or `find` value. A step cannot use its own captures.
Capture names are unique across the journey. A capture has one `type`:

- `pointer` remembers the string or number at a JSON pointer in the body.
- `header` remembers a response header. `etag` is the supported header.
- `find` searches the array at a JSON pointer for the one item whose `where`
  pointer equals a value, and remembers the item's `pointer` value. The step
  fails if no item or more than one item matches.
- `value` remembers the value at a pointer. With `query`, the value must be a
  URL, and the capture is that query parameter's value.

Use a bounded GET `poll` for asynchronous delivery or result retrieval. Set
`maximumWaitMilliseconds` up to 60 seconds and choose a
`pollIntervalMilliseconds` from 50 to 5000. A journey can make at most 512
requests and transfer at most 8 MiB of request and response bodies in total.

`token` writes a short-lived bearer header file for each grant. Its JSON report
gives the person's `alias`, the `expires_at` time when the tokens expire
(five minutes after issue, or with the run if that is sooner), and a
`credentials` list whose entries carry the `product`, the selected `profile`
and the `header_file` path.
Pass the file to curl with `--header @HEADER_FILE`. With BReg, include the
selected profile as the `accessProfile` query parameter. With Casework, the
header file carries the profile.

## Run isolation

Each run listens on loopback, creates separate databases and migration and
runtime logins, and pins its own public signing key in the runtime files. The
local issuer signs under the project's issuer name with a key unique to the run.
Use synthetic test people and keep the issuer's private directory under your
user account.

Stop and TTL expiry terminate the services and remove the databases, roles,
keys, and run files. A spatial BReg run also creates a `NOLOGIN` role whose name
starts with `breg_bbox_`; cleanup removes it with the others.

### Encrypted fields

A BReg project with encrypted fields runs without extra setup. `start` draws a
development data key for the run from the operating system's random source and
writes it as `field-key` in the run directory, readable only by your user. BReg
reads it through its `local-file` key custody, which it accepts only for a
local development database. The key is never printed, never written to the
checkout, and is removed with the run directory on stop, TTL expiry and a
failed start. When a run needs recovery, the report names the key file under
`recovery.field_encryption_key` until `stop --recover` removes it. Every run
gets a new key, so encrypted data does not outlive its run.

The schema test that `start` runs before activation has no field-encryption
key, so a step in `tests/journeys.yaml` that touches a Record type with an
encrypted field fails it, and `start` reports `breg test failed
(test.step.failed)`. Exercise those Record types in the plan's `journey`
instead.

This key custody is for development only. A deployment supplies its key as
[BReg field encryption](../../docs/site/src/content/docs/configure/breg-field-encryption.mdx)
describes.

The state directory holds one directory per run. It defaults to
`rstack-dev-UID` in the system temporary directory. Set `RSTACK_DEV_STATE_DIR`
to use another location. A run directory is renamed to `.<run_id>.removing`
before it is deleted, and `status` and `stop` ignore that name. If the deletion
is interrupted, delete that directory yourself; the run's field-encryption key
is deleted before the rename, so it holds no key material.

## When a run fails

### Logs

During a run, `<run>/logs/supervisor.log` holds the supervisor's log and
`<run>/logs/<product>-<stage>.log` holds each product stage's log, for example
`breg-check.log`. `status` names the logs directory. When a start fails, the run
directory is removed but its logs are kept at `<state>/failed/<run_id>/logs`,
and the error names that path. Delete kept logs yourself.

### Recovery

If PostgreSQL becomes unavailable during cleanup, the supervisor retries with
backoff for up to 30 minutes. It then writes `cleanup-pending.json` in the run
directory. If the supervisor is lost, the run's process guards stop the product
runtimes and any product tool that was still running. `stop` and `status` report
the run directory, the recorded process groups, and the database and role names.

Release a run whose supervisor is gone with:

```sh
rstack dev stop RUN_ID --recover [--database-url URL]
```

Use plain `stop` while the supervisor is still running. For recovery, use an
administrator URL for the same PostgreSQL cluster and maintenance database used
at startup, with the same administrator rights. `--database-url` defaults to
`RSTACK_DEV_DATABASE_URL`, as for `start`. Recovery checks the recorded cluster
identifier and maintenance database before dropping any resources. It waits for
the process guards to finish, then drops the databases and roles and removes
the run directory. If any step fails, the report gives the reason and the
resources you can check before retrying.
An abrupt machine restart can stop a guard before it writes its completed
cleanup receipt. In that case `--recover` refuses to claim the guarded workload
was reaped, even if the process no longer exists. Verify ownership and finish
cleanup with the manual steps below. The same manual path applies to runs from
an older development build without recovery metadata. Recovery releases the
disposable run; it does not resume its application or pending work.

A successful recovery reports `status` `stopped` and a `recovered` object with
`stopped_process_groups` and `databases_and_roles`.

If you need to finish cleanup by hand, do it in this order:

1. Verify which product processes still belong to the run and stop those
   groups. Use the run's configuration paths and process details to establish
   ownership before signaling a group.
2. Connect to the original PostgreSQL cluster as the administrator. Run
   `DROP DATABASE IF EXISTS "NAME" WITH (FORCE)` for each listed database.
3. Run `DROP ROLE IF EXISTS "NAME"` for each listed role, including a
   `breg_bbox_*` role from a spatial run.
4. Remove the run directory. It holds the run's development field-encryption
   key when `field_encryption_key` is listed.

### Errors and limitations

With `--json`, a refusal or startup failure from `rstack dev` start, status,
token or stop prints one JSON object on standard output, validated by
`schemas/rstack-dev-error.v1.schema.json`. The launcher prints the same object
for failures before the helper starts, such as a missing component.
When a journey assertion fails, `start` exits 1 and prints the regular
`registry.rstack.dev.v1` run report with `status` `ready` and
`journey.result` `failed`. The run remains available for inspection.

- `schema_version` is `registry.rstack.error.v1` and `status` is `refused`.
- `error.class` is `domain` (exit 1: the request, the project, the plan or the
  run's state was refused), `usage` (exit 2: the command line is wrong, such
  as a malformed run ID, `--ttl` or test person name) or `operational` (exit 3:
  the environment failed, a cleanup stalled, or a run needs its resources
  released). Environment failures include a PostgreSQL server that is
  unreachable, refuses the administrator session, or cannot provision a run's
  databases and roles, a product binary that cannot be started, no free
  loopback port, a product or run that does not start in time, and an internal
  failure of the run's supervisor. An interrupted `start` is `domain`.
  `error.message` is the human-readable reason.
- `run_id` is present when the failure concerns a run that still has
  resources to release. Try `stop --recover`; an incomplete guard receipt
  requires the verified manual cleanup above.
- `recovery` accompanies `run_id` when the resources are known. It has `kind`
  (`lost-supervisor` or `cleanup-pending`), `run_directory`, `processes`,
  `objects` or `databases_and_roles`, `field_encryption_key` when the run
  directory still holds the run's key file (the path, never the key), and
  `reason` when `--recover` could not finish.

Without `--json`, the message goes to standard error as `rstack dev: MESSAGE`
with the same exit code. The reports of `rstack dev check` use `BRegCtlReport`
instead. A helper started without the launcher's request prints a plain
message and exits 2.
