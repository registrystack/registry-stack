# Registry Messaging

PostgreSQL 17 or newer is required for package activation and runtime startup.

Registry Messaging delivers operational messages, SMS and email, on behalf of
authorized callers. The caller decides why and when to send and who the
recipient is; Messaging owns rendering from reviewed templates, delivery
through operator-configured providers, and an accountable record of each
attempt. It is a native Rust runtime over PostgreSQL with no broker.

Install, run and operate it with the
[Registry Messaging guides](https://docs.registrystack.org/operate/messaging/).
The [provider examples](examples/providers/) cover the SMTP relay, Twilio SMS
(`form-sms-gateway`, with signed callbacks), AWS End User Messaging SMS
(`aws-sms`, see its [guide](examples/providers/aws-sms/README.md)) and the local
development transports.

## Product boundary

Messaging does not own why or when to send, recipient identity or contact
directories, consent to be contacted, or any registry mutation. Those stay
with the caller's source of record.

- No Messaging crate depends on a Base Registry Engine, Casework, Coordinator,
  Scheduling, or Evidence crate, and no crate of those products depends on the
  Messaging runtime or its tooling. Products reach Messaging over its public
  HTTP contract, like any external caller.
  `scripts/check_dependency_direction.py` enforces this on the forward
  closure of Cargo's resolved graph.
- Messaging inherits no authorization from a caller product. Being allowed to
  act on a Casework item does not make a caller allowed to send; the
  Messaging access profile decides.
- Messaging never writes to another product's database.

## Crates

| Crate | Owns |
|---|---|
| `registry-messaging-core` | Access profiles and their decisions, the package manifest, template checking and rendering, SMS segment counting, message visibility, the problem vocabulary, wire names and DTOs. No I/O. |
| `registry-messaging` | The runtime and the `messaging` binary: configuration, the package loader and digest, authentication, HTTP, metrics, the PostgreSQL store and shared activation ledger, and the audit journal. |
| `registry-messagingctl` | Adopter and local operator tooling, the `messagingctl` binary. |
| `registry-messaging-client` | The bounded Rust client over the runtime's HTTP contract. |

## Running locally

`rstack dev` runs a package end to end on one machine from a development plan. It needs Docker for
PostgreSQL and, when a provider is `smtp`, Mailpit. `messagingctl init` writes the plan, `dev.yaml`,
and a scenario file with the starter:

```bash
messagingctl init ./notices
rstack dev check ./notices
rstack --format json dev start ./notices --ttl 2h > run.json
RUN="$(jq -r .run_id run.json)"
HEADERS="$(rstack dev token "$RUN" --as case-system | awk '$1 == "messaging" && $2 == "headers" {print $3}')"
printf '%s\n' '{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"}}' |
  rstack messaging api /v1/messages --url "$(jq -r .products.messaging run.json)" \
    --header @"$HEADERS" --idempotency-key first --input -
rstack dev stop "$RUN"
```

The run owns everything it starts: a PostgreSQL server, a pinned Mailpit container every `smtp`
provider sends to, a mock gateway every `http` provider sends to, and the Messaging runtime on a
`development-loopback` listener. The containers publish on 127.0.0.1 only and carry the run's label,
so `stop`, TTL expiry and `stop --recover` remove them with the run. The mock gateway answers each
send with `queued` and about a quarter of a second later posts a delivery report, signed with the
run's callback key, to the runtime's callback route, so an SMS reaches `delivered` and an email
reaches `submitted` with its message in Mailpit. The run report lists each sink under `sinks`.

The run's secrets, generated `runtime.yaml`, audit journal and logs live in its own directory
outside the project, which the project never writes to. `rstack dev token RUN --as PERSON` signs a
short-lived bearer token for a person the plan names, carrying the access profile's scopes and
actor kind, with the key the run's runtime trusts. The tokens and the key are for this run only;
nothing about a run is a production posture. A plan that lists BReg and Messaging runs both against
one issuer. [Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/)
describes the plan, the sinks and the run report.

To run the runtime yourself, `messagingctl init DIRECTORY` creates an editable
project with `messaging.yaml`, `providers/`, and `templates/`. Check that
project, then use `messagingctl package` to write a separate installed package
with the shared checksum envelope. Keep the runtime configuration and secrets
outside the installed package. Copy `runtime.example.yaml`, set `package.root`
to the installed directory, and configure explicit listener addresses and
secret references:

```bash
messagingctl init ./notices
messagingctl check --project ./notices
messagingctl generate templates --project ./notices \
  --output ./notices-template-contracts.json
messagingctl package ./notices --output ./notices-installed
messagingctl check --package ./notices-installed
messagingctl check --runtime-config /abs/path/runtime.yaml
messagingctl preview --runtime-config /abs/path/runtime.yaml \
  appointment-reminder 1 --locale fr \
  --data ./notices/templates/appointment-reminder/1/sample.json
messagingctl plan --runtime-config /abs/path/runtime.yaml
messagingctl apply --runtime-config /abs/path/runtime.yaml
messagingctl status --runtime-config /abs/path/runtime.yaml
messaging --runtime-config /abs/path/runtime.yaml serve
```

`messagingctl generate templates --project PROJECT --output FILE` validates the
editable project, then creates a deterministic `MessagingTemplateContracts`
JSON document for another tool. It contains one entry per template version,
with its `id`, string `version`, sorted `locales`, and checked `schema.json`
value as `dataSchema`. The export is separate from the immutable
package inputs and never changes the package digest; an existing output file
is refused rather than overwritten.

Use local JSON Pointer references, such as `#/$defs/name`, in template data
schemas. The current schema validator does not support named anchors or dynamic
references.

`--data` names a JSON file, read relative to the directory the command runs
in like any other relative path; each template version's `sample.json`
serves. `messagingctl plan` and `status` use the runtime credential in
read-only transactions. `messagingctl apply` uses the migration credential to
apply pending migrations, grant a separate runtime role only the required
runtime access, and append the activation in one locked transaction. `serve`
refuses an unknown schema, a different database identity or package, stale
runtime grants, or a weakened split-role boundary. A package change takes
effect on restart after `apply`. Every
`messagingctl` command takes `--format human|json` and exits 0 on success, 1
on a refusal, 2 on a usage error, and 3 when a file, secret, or database could
not be reached. A human failure is one `error[CODE] PATH: MESSAGE` line on
standard error with a `next:` line after it. A `--format json` report opens with
`ok`, `command`, and `status`, then names its format: `apiVersion` is
`id.registrystack.org/formats/messaging/ctl-report/v1alpha1` and `kind` is
`MessagingCtlReport`. A failure lists `diagnostics`; a successful
`preview` is the exception and prints the HTTP preview's body unwrapped.
`examples/formats/ctl-report.json` is the report `check` writes for the
starter project.
`MESSAGING_LOG` accepts `error`, `warn`, or `info` and nothing else.

`messagingctl messages list` and `show` report messages with the recipient
masked, each with its derived status and its dispatch state. `retry`
requeues a message whose dispatch failed as a new generation,
`settle --outcome sent|not-sent` resolves a message whose outcome is
unknown, and `cancel` cancels a queued one; each is decided on the dispatch
state, so a submitted message the provider reported undelivered is not
retried. Each action previews without
`--apply`, and an applied action uses its own request/response audit stream. A failed audit
response after commit reports unavailable while the database effect stays
authoritative. After recovery, inspect or retry according to the action
contract rather than assuming rollback. The
[configuration reference](https://docs.registrystack.org/reference/messaging-configuration/)
documents every key.

## HTTP contract

`generated/registry-messaging.openapi.json` is the contract; it is generated,
never hand-edited. The
[Registry Messaging API contract](https://docs.registrystack.org/reference/apis/registry-messaging/)
describes the routes, limits and problem codes, and the
[configuration reference](https://docs.registrystack.org/reference/messaging-configuration/)
lists every runtime key.

## Verification

```bash
cargo build --locked -p registry-messagingctl
products/messaging/scripts/check-checkpoint.sh
products/messaging/scripts/check-contracts.sh
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_migrate
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_package
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_messages
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_dispatch
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_callbacks
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_retention
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messagingctl --features postgres-test --test postgres_messages_cli
products/messaging/scripts/test-dev.sh
products/messaging/scripts/test-dev-shared-issuer.sh
python3 products/platform/scripts/test-rstack-dev.py --bin-dir "$CARGO_TARGET_DIR/debug" \
  --scratch-parent "$TMPDIR" --messaging
```

The checkpoint runs the database-free checks: dependency direction,
database-suite isolation, the contract validator and its tests, the generated
artifact drift test, `messagingctl init` against the published starter,
`messagingctl check` over the starter, a pinned digest, and five refusals,
`messagingctl preview` byte stability, and `messagingctl messages` refusing a
malformed id and an unreachable database. `test-dev.sh` needs Docker: it
starts `messagingctl dev` on a starter whose SMS provider is the example mock
provider, sends one email and one SMS, requires the SMS to be `delivered`
through one applied signed callback and the email to be `submitted` with one
message in Mailpit, and requires the stopped session to leave no container.
`test-dev-shared-issuer.sh` also needs Docker: it starts a BReg owner with the
two Messaging requester clients and their explicit resource, runs the same
Messaging journey with borrowed tokens, exercises retained-owner restart and
replacement refusals, and requires Messaging cleanup to leave the owner
running.
The harness's `--messaging` mode needs Docker: it runs the starter under `rstack dev` with no other
product, requires the scenario's SMS to reach the run's gateway, sends an email that reaches the
run's Mailpit, and requires the stopped run to leave no container.
Each PostgreSQL suite works in its own schema inside the database the
URL names and fails, rather than skipping, when the URL is absent. A test
binary that skips because its database is absent is not database
verification.

Regenerate the committed artifacts with:

```bash
cargo run -p registry-messaging --features schema --example runtime-schema -- \
  --output products/messaging/generated/runtime
cargo run -p registry-messaging --features schema --example openapi -- \
  --output products/messaging/generated
```

## Observe an original receipt

`POST /v1/messages/receipt` accepts the original request body and
`Idempotency-Key`. The caller authenticates as for any Messaging route: its
client resolves to an access profile, the token carries that profile's
required scopes, and the profile's `principalClaim` names the owner
principal. The route returns `200` with the retained original success
receipt only to the verified issuer and principal that submitted under the
key, for the same request. It needs no sender profile or template permission,
does not count against the caller's rate or daily limit, and never renders,
submits, dispatches, or writes anything. A caller resolving to another
principal cannot observe the receipt. `409 receipt.unresolved` covers
unavailable evidence such as a missing, expired, or changed receipt and does
not prove that no effect occurred.

To bind ownership to the token's subject, configure the caller's access
profile with `principalClaim: sub`. A profile that names another claim owns
its receipts under that claim's value, and cannot substitute a different
principal to observe one.
