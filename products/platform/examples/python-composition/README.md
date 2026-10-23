# Direct Python composition

This reference application uses released `registry-stack-client` 0.43.0 to
prepare a BReg Proposal, expose Casework reviewer operations, apply an exact
approved source version, and submit one reviewed notice to Messaging. It needs
no Coordinator. Choose only the products your application uses; this example's
apply-and-notify command deliberately uses all three.

The application Record remains the original intake. An officer's issuance
Action creates a separate Proposal whose inputs include the application and
attachment provenance references. Casework reviews that exact version and its
effects. Only BReg applies it, with source-owned revision, uniqueness, and
permission checks. The example never consumes a review as transferable write
authority and never bypasses the native SDK's lifecycle link or ETag.

## Install and configure

Use Python 3.11 or later and `uv sync --locked`. This installs the published
wheel; Rust is not required. Copy `config.example.json` to a private operator
file and replace its service origins, profiles, and credential file paths.
Each product gets a separate resource-bound provider. A `privateKeyJwt` object
uses the released canonical helper's `token_endpoint`, `client_id`,
`client_key`, `resource`, and `scopes` settings instead of a `headerFile`.
Keep the key and token configuration out of source control.

Give `inbox` a durable application-owned directory. The example creates its
SQLite file owner-only. The wake receiver listens on loopback behind your
TLS edge; the edge owns network access limits. Configure the same bearer token
and recipient binding in Casework's completion destination. The
[completion receiver contract](../../../casework/COMPLETION-RECEIVERS.md)
owns its protocol. An empty `204` works with released and candidate senders.

## Walk the application

Run commands from this directory. Use an officer configuration for preparation
and an independently authorized applier configuration for reconciliation.
Supply domain inputs from the configured issuance Action; `inputs.json` is the
inputs object itself, including its original application and attachment refs.

```sh
uv run --locked service.py --config officer.json prepare issue-licence inputs.json issue-example
uv run --locked service.py --config staff.json review-tasks
```

The first command returns the Proposal id, exact submission version, and
effect digest. Register those immutable values with a complete Messaging
request in `notice.json`:

```sh
uv run --locked service.py --config applier.json register <proposal-id> <version> <effect-digest> notice.json
uv run --locked service.py --config receiver.json serve-wakes
```

A reviewer reads the task and source context through their application's UI
before deciding. The explicit `decide` command accepts the displayed task
revision, a stable decision key, and the product's decision document. It is
never invoked automatically by a wake.

```sh
uv run --locked service.py --config staff.json decide <task-id> <revision> <decision-key> decision.json
uv run --locked service.py --config applier.json reconcile
```

The wake only records a durable hint, keyed to the authenticated event identity
and exact bytes, before acknowledging it. It carries no decision or apply
permission. Reconciliation reads the Proposal from BReg, keeps the registered
version and effect digest, and uses the source-issued Apply capability.
After source application is confirmed, it submits the unchanged notice under
one stable Messaging key. A submission receipt proves admission, not delivery;
read Messaging's message state when delivery matters.

Run a single reconciliation process for this small example. Each job has a
bounded attempt budget. On an uncertain Apply or notice send, retain the same
keys and bodies and read authoritative state; never register a fresh key to
escape an unknown outcome. Exhausted budgets require operator recovery.
The owning product's idempotency horizon and data retention still apply.

## Verify

`uv run --locked python -m unittest discover -s tests -v` covers durable wake
acceptance, restart persistence, replay conflicts, and credential/binding
refusals. Live composition proof requires configured BReg, Casework, and
Messaging instances, separate least-privilege callers, and a real reviewed
issuance Action. Unit tests and an import smoke do not establish that journey.
