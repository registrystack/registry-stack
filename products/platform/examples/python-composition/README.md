# Direct Python composition

This reference application uses released `registry-stack-client` 0.43.0 to
prepare a BReg Proposal, expose Casework reviewer operations, apply an exact
approved source version, and submit one reviewed notice to Messaging. It needs
no Coordinator. Choose only the products your application uses; this example's
apply-and-notify command deliberately uses all three.

The application Record remains the original intake. An officer's issuance
Action creates a separate Proposal whose inputs name the application and
separate issuance terms. Attachment bytes occupy a governed Proposal slot. Casework reviews that exact version and its
effects. Only BReg applies it, with source-owned revision, uniqueness, and
permission checks. The example never consumes a review as transferable write
authority and never bypasses the native SDK's lifecycle link or ETag.

## Install and configure

Use an ordinary Registry Stack source archive or checkout, Python 3.11 or later,
and `uv sync --locked` from this example directory. Retain the archive layout: the
example reads BReg's maintained generated lifecycle schema at
`products/breg/generated/event-schemas/proposal-lifecycle.schema.json`. This installs the published
wheel; Rust is not required. Copy `config.example.json` to a private operator
file and replace its service origins, profiles, and credential file paths.
Each product gets a separate resource-bound provider. A `privateKeyJwt` object
uses the released canonical helper's `token_endpoint`, `client_id`,
`client_key`, `resource`, and `scopes` settings instead of a `headerFile`.
Its optional `audience` identifies the OAuth token endpoint as the client
assertion's recipient. It is distinct from `resource`, which requests the
product access token. Each product validates that access token's audience,
scopes, and permissions; this application does not impose a singleton audience.
Keep the key and token configuration out of source control.

Give `inbox` a durable application-owned directory. The example creates its
SQLite file owner-only. The wake receiver listens on loopback behind your
TLS edge; the edge owns network access limits. BReg owns the Casework completion
for its Proposals. Configure a BReg signed event destination for this
application's `/hooks/breg` route, with the same key bytes as `hookKeyFile`.
Set `hookSource`, `hookType`, and `hookSchema` to the producer's exact envelope.
The native `verify_webhook_delivery` helper verifies the method, path, headers,
and raw bytes under the maintained BReg delivery contract. The receiver also
checks the delivery time within five minutes and persists the event identity
and body digest before returning an empty `204`. It validates the native Proposal
payload against BReg's maintained generated lifecycle schema in the source archive, checks the
envelope against signed metadata and its Proposal subject, and stores only the
Proposal id, submission version, effect digest, event identity, and body digest.
The unit suite checks that the validator loads the owning schema. Run reconciliation
on a timer as well: a missing hook must not prevent an authoritative source reread.

## Walk the application

Run commands from this directory. Use an officer configuration for preparation
and an independently authorized applier configuration for reconciliation.
Supply domain inputs from the configured issuance Action; `inputs.json` is the
inputs object itself. It follows the configured Action's schema; do not add
fictitious provenance or attachment fields. The optional licensing adaptation
accepts `--intake-proposal <id>`: it reads an applied native `submit-application`
Proposal, checks its exact receipt version, effect digest, and application result
link, downloads its frozen `supporting-document` slot, and uploads those bytes
into the issuance Proposal before Submit. It refuses a cross-application intake
before creating the new draft. This adaptation expects the reviewed-licensing
starter's Action and slot contract; generic preparation without that option
copies no document.

```sh
uv run --locked service.py --config officer.json prepare issue-licence inputs.json issue-example --intake-proposal <applied-intake-proposal-id>
uv run --locked service.py --config staff.json review-tasks
uv run --locked service.py --config staff.json review-context <task-id>
```

The first command returns the Proposal id, exact submission version, and
effect digest. Register those immutable values with a complete Messaging
request in `notice.json`:

```sh
uv run --locked service.py --config applier.json register <proposal-id> <version> <effect-digest> notice.json
uv run --locked service.py --config receiver.json serve-wakes
```

A reviewer reads the task and source context through their application's UI,
then explicitly claims the displayed revision when the policy requires a held
task. Use the revision returned by `claim` for the subsequent decision. `review-context` uses that reviewer's Casework authority and
`caseworkSourceProfile` for the source projection; a producer token does not
grant reviewer access. The explicit `decide` command accepts the displayed task
revision, a stable decision key, and the product's decision document. It is
never invoked automatically by a wake.

```sh
uv run --locked service.py --config staff.json claim <task-id> <displayed-revision> <claim-key>
uv run --locked service.py --config staff.json decide <task-id> <claimed-revision> <decision-key> decision.json
uv run --locked service.py --config applier.json reconcile
```

The wake only records a durable hint, keyed to the authenticated event identity
and exact bytes, before acknowledging it. It carries no decision or apply
permission. Reconciliation prioritizes exact matching pending hints, reads the Proposal
from BReg, keeps the registered version and effect digest, and consumes matching
hints only after that authoritative binding check. It uses the source-issued
Apply capability. Timer passes scan registered jobs even without a hook.
After source application is confirmed, it records `notice-uncertain` before
submitting the unchanged notice under one stable Messaging key. If the response
is lost, later passes read the original command receipt with the same caller,
key, and body, including at the attempt budget. They do not resubmit it. A typed
native failure with `outcome_unknown=false` restores the prepared state for a
bounded retry, except an expired or conflicting original key, which requires
investigation. Unknown outcomes and untyped failures retain uncertainty. An unresolved or expired receipt leaves
the job uncertain and requires investigation; it does not establish no effect.
A submission receipt proves admission, not delivery; read Messaging's message
state when delivery matters.

Run a single reconciliation process for this small example. A per-job refusal
does not stop later jobs in the selected batch. Its diagnostic names a fixed
`stage` and a `job` reference: the first 16 hexadecimal characters of the
SHA-256 of the stored Proposal id. Correlate that reference locally with the
inbox. Exception text, Proposal ids, notice payloads, and credentials are not
included in these diagnostics. Startup, credential configuration, corrupt
stored JSON, and SQLite failures still fail the command visibly.

Each job has a bounded attempt budget. Failed source reads, mismatched registered
bindings, and failed preparation consume one attempt; waiting for a source-issued
Apply capability does not. Each new Apply or notice submission is charged before
dispatch and requires remaining budget, including when Apply and notification
would otherwise happen in the same pass. An uncertain notice continues reading
its original receipt at the budget without consuming another attempt or
resubmitting. A completed-job count describes only the jobs completed in that
pass; consult the diagnostics for jobs that remain unresolved.

On an uncertain Apply or notice send, retain the same keys and bodies and read
authoritative state; never register a fresh key to escape an unknown outcome.
For a binding refusal, inspect the registered version and effect digest alongside
the native Proposal; this service does not replace the accepted binding. For an
Apply or notice refusal, inspect the authoritative source or original notice
receipt before deciding whether recovery is safe. Exhausted budgets require
operator recovery; this example does not reset them automatically. Keep the same
configured caller across recovery and restarts. The owning product's idempotency
horizon and data retention still apply.

## Verify

`uv run --locked python -m unittest discover -s tests -v` covers durable wake
acceptance, restart persistence, replay conflicts, the pinned native constructors,
review context authority, HTTP acknowledgment ordering, and uncertain notice
receipt recovery. Live composition proof requires configured BReg, Casework, and
Messaging instances, separate least-privilege callers, and a real reviewed
issuance Action. Unit tests and an import smoke do not establish that journey.
