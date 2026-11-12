# Run a project for development

Use `rstack dev` to start a checkout's BReg, Casework, and Messaging projects
together. Install matching product components and supply a dedicated development
PostgreSQL server over TLS. `rstack dev` does not start PostgreSQL and does not
use Docker: you supply the server. The products' own development modes are
unchanged by `rstack dev`.

For a walk-through from a checkout to a running project, see
[Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/).
This file is the reference.

```sh
rstack install breg casework messaging
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

The [licensing example](examples/licensing/dev.yaml) creates an application in
BReg, submits and reads back an idempotency-keyed receipt from Messaging,
requests approval of the captured application in Casework, and checks the
reviewer's decision. Its Messaging provider is deliberately unconfigured: the
journey proves local authenticated acceptance and receipt storage, not external
email delivery. Point `start` at the directory containing `dev.yaml`.
Product files remain byte-for-byte unchanged. Generated runtime settings, keys,
and packages live in the run's owner-only scratch directory.

The [prepared Python script](examples/python-script/README.md) consumes the
generated connection with `registry_client.connect()`, reads BReg, and submits
and reads one keyed Messaging receipt without handling a bearer. Its optional
rotation check keeps one Python process and connection alive across a local
runner rotation. Source tests use protocol doubles; the documented live command
is required to establish real runner, credential, and product behavior.

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
a mismatch appears as a failed journey step. A Messaging grant must name one
of the checked package's access profiles. Its client, exact scopes, and actor
kind must match that profile. The local runner accepts Messaging profiles whose
`principalClaim` is `sub`, keeping receipt ownership bound to the declared
service subject.

### Python workload connection

Declare `workloads` when a local Python script or service needs a BReg or
Messaging workload identity. Each binding names one of those products, a
stable synthetic `subject` and `client`, and a `grant` containing one product
profile, one or more exact scopes, and additional claims. Mark exactly one
binding as `default` for each product that has workload bindings. `rstack dev check` verifies BReg profiles
and protects the BReg principal claim. For Messaging it also checks that the
profile is a sender, uses `sub`, admits the client, requires the exact scopes,
and agrees with any required `registry_actor_kind` claim.

When the run becomes ready, `connection_file` in the start and status report
names an owner-only generated Registry Stack Python connection. It contains
the `PlatformPythonConnection` envelope, endpoint and authority metadata, and
a private token reference. Each referenced state is a complete
`PlatformDevWorkloadToken` envelope. Set
`REGISTRY_STACK_CONNECTION` to that path, or pass it to `connect(path=...)`.
The existing run supervisor atomically replaces one complete token-state file
per binding every minute. Tokens expire after at most five minutes and never
outlive or extend the run. The Python process can observe later generations
without restarting. Stopping the run or reaching its TTL removes the
connection and token state with the rest of the run directory.

Each Messaging run gets its own package, loopback runtime, database, migration
role, and runtime role. It trusts the run issuer only for its declared
Messaging audience. A Messaging token is not a BReg token and carries only its
binding's Messaging client, scopes and claims.

The runner's issuer signing key is not referenced by the connection or token
state. The generated client must reject a token state whose run, binding,
product, issuer, subject, client, profile, resource, scopes, declared claims or
run expiry does not match the connection. It must also reject expired state
and generation rollback rather than reusing another binding or credential.

### Local Python person picker

The optional local picker simulates holder or staff admission for a fast edit
loop. It is not OIDC and does not qualify real sign-in, SSO, renewal or
production enrollment. Use real OIDC for shared or non-loopback development.

Declare each local service and its complete authority in `developmentPickers`:

```yaml
developmentPickers:
  holder:
    people: [applicant, applicant-other]
    personProducts: [breg, casework]
    workloads: [registry-script, messaging-service]
  staff:
    people: [reviewer]
    personProducts: [breg, casework]
    workloads: [registry-script, messaging-service]
```

The whole `developmentPickers` field is optional. `holder` and `staff` are
independently optional, but their people must be disjoint. Every named person
must have a grant for every `personProducts` entry. `workloads` must explicitly
name the complete top-level workload set. This prevents a picker service from
loading an undeclared production credential or another local service binding.
If the plan declares no workloads, omit `workloads` or use an empty list.

`start` and `status` add `picker_files`, keyed by persona. Pass only that
owner-only descriptor path to the matching service:

```python
import os

from registry_client.dev_picker import DevelopmentPicker, install_flask

picker = DevelopmentPicker.from_descriptor(
    os.environ["REGISTRY_STACK_DEV_PICKER"]
)
install_flask(
    app,
    picker,
    person_factory=person_factory,
    request_seconds=2,
)
```

There is no boolean development switch. The library mounts the routes only
when the descriptor is in the private run directory, the supervisor still
holds that run's lock, the report is ready and unexpired, and the generated
origin is an exact loopback origin. Bind the Flask or FastAPI development
server to the host and port in `picker.origin`; a different Host or browser
Origin is refused.

The selection page receives non-secret labels and opaque selectors. Person and
workload tokens, subjects, product endpoints and token references remain
server-side. The picker resolves the complete person token set before it opens
a memory-only session. Its pending and authenticated cookies use a random
run-specific namespace, so a restarted run cannot accept an old-run cookie.
The same Python process observes runner token rotation. Stop, TTL expiry,
mixed rotation or a lost supervisor refuses the session before another product
call. The library has no issuer key and cannot mint a replacement token.

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
header file carries the profile. Messaging resolves its access profile from
the token's admitted client, scopes and actor kind, so its header file contains
only the bearer header.

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
For runs from an older development build without recovery metadata, use the
manual cleanup steps below.

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
  resources to release. Use it with `stop --recover`.
- `recovery` accompanies `run_id` when the resources are known. It has `kind`
  (`lost-supervisor` or `cleanup-pending`), `run_directory`, `processes`,
  `objects` or `databases_and_roles`, `field_encryption_key` when the run
  directory still holds the run's key file (the path, never the key), and
  `reason` when `--recover` could not finish.

Without `--json`, the message goes to standard error as `rstack dev: MESSAGE`
with the same exit code. The reports of `rstack dev check` use `BRegCtlReport`
instead. A helper started without the launcher's request prints a plain
message and exits 2.
