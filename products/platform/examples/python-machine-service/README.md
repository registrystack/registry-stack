# Keyed Python machine-service effect

This reference shows a Flask machine endpoint performing one keyed Registry Messaging effect through the `registry-stack-client` wheel.
It separates the verified Coordinator caller from the service's Messaging workload authority, keeps recipients and templates in protected application state, and recovers an uncertain submission without sending it again.
It targets the candidate Python service APIs in this checkout.
It is not a published capability until the assembled wheel and release evidence say so.

The endpoint accepts only this caller command:

```json
{"key":"renewal-2026-001","noticeId":"notice-001"}
```

It does not accept a bearer for Messaging, recipient, template, binding, URL, subject, scope, or workload profile.
The Flask adapter verifies the service caller and supplies an immutable `MachineContext`.
`registry_client.connect()` selects the default or declared named Messaging binding and supplies its workload credential internally.

## Effect and recovery contract

Application business logic writes the complete Messaging request to the owner-only SQLite database before this endpoint is called.
The protected row binds the admitted caller, including issuer and resource, notice ID, complete request, and stable workload-authority ID.
That earlier business transaction remains application code because this example cannot decide who should receive a notice or which template is appropriate.

For the effect endpoint, the application:

1. Derives a 64-character downstream key from the service namespace, verified caller issuer, resource, subject, client, profile, persona, stable operation, and caller command key.
2. Atomically stores the exact authority ID, canonical request bytes, and request digest under that key.
3. Commits the command as `unknown` before calling `stack.messaging.submit` or a named binding's `submit`.
4. Stores a successful native receipt, or a typed product refusal that proves no effect occurred.
5. Uses `message_receipt` with the original key and request for every later `unknown` attempt.

Only the transition from `prepared` to `unknown` may call `submit`.
A process stop, lost response, malformed native success, later authorization denial, or expired retained receipt therefore cannot cause an automatic second submission.
A changed request under the same caller command key conflicts and cannot receive the original receipt.
Two verified callers choosing the same input key derive different downstream keys.

The response is deliberately small:

| HTTP | Body state | Meaning for Coordinator |
| --- | --- | --- |
| `200` | `accepted` | Messaging returned or recovered the original receipt. |
| `202` | `uncertain` | Keep the supplied recovery reference and repeat only the same command. |
| `409` | `uncertain` | The key was already bound to different work; do not classify it as a no-effect refusal. |
| `422` | `refused` | Input or a typed Messaging problem established that this command caused no effect. |
| `429` | `not-processed` | Local submission capacity was unavailable before this command started a native effect. |

An unusable response after Messaging accepted the command remains recoverable because the receipt is committed before Flask encodes the response.
The Coordinator `external.command/v1` interpreter should declare only the `200 accepted`, `422 refused`, and `429 not-processed` shapes.
Every other status or shape remains uncertain.

`MessageEffect` emits one structured application audit event for each returned command result and changed-command conflict. Its fields are the operation, a deployment-keyed HMAC caller reference, the configured workload-authority fingerprint, the recovery reference, and the outcome. Recipients, templates, request bodies, credentials, and exception messages are absent. `create_app` requires an injected audit sink; the environment factory writes each bounded JSON event to stderr, which the deployment must capture. Keep the audit key stable for cross-command correlation; rotating it changes only the audit reference, not command recovery. This example does not provide durable, append-only audit storage. Messaging's own audit remains the product record of native acceptance and delivery.

## Configure the service

Use Python 3.11 or later and the assembled `registry-stack-client` wheel from the same Registry Stack source or release as the services.
The source facade directory is not a substitute for that wheel.

Install Flask from this project's lock, then supply the matching wheel explicitly:

```sh
uv sync --locked
sdk='registry-stack-client==<matching-release-version>'
# Prepared source candidates may use an absolute wheel path instead.
uv run --locked --with "$sdk" python service.py
```

Set these variables before starting the process:

- `REGISTRY_STACK_CONNECTION` names the owner-only service connection consumed by `connect()`.
- `MESSAGE_EFFECT_DATABASE` names an application data file inside an owner-only directory.
- `MESSAGE_EFFECT_SERVICE_NAMESPACE` is a stable identifier for this admitted service, not a deployment revision.
- `MESSAGE_EFFECT_AUDIT_KEY_HEX` is a secret, independently generated 32-byte audit key encoded as 64 hexadecimal characters; inject it at process start through the operator's secret manager, without writing it into the connection or fixture.
- `MESSAGE_EFFECT_TARGETS` is a JSON object mapping checked workload-authority fingerprints to a named Messaging binding, or to `null` for the default.

For example:

```sh
export REGISTRY_STACK_CONNECTION=/run/secrets/renewal-service/connection.json
export MESSAGE_EFFECT_DATABASE=/var/lib/renewal-service/message-effects/effects.sqlite3
export MESSAGE_EFFECT_SERVICE_NAMESPACE=urn:example:service:renewal-notices
export MESSAGE_EFFECT_TARGETS='{"<default-authority-fingerprint>":null,"<regional-authority-fingerprint>":"regional-notices"}'
```

The target map is trusted operator configuration, but `MessagingTargets` verifies every key against the selected binding before serving requests.
Obtain the default fingerprint from `stack.authority("messaging").fingerprint`, or a named fingerprint from `stack.using("regional-notices").authority.fingerprint`.
The non-secret fingerprint covers the product and the connection's declared issuer, subject, client ID, profile, resource, sorted scopes, and declared non-secret additional claims.
It deliberately excludes the binding alias, endpoint URL, token endpoint, and client-key reference.
Renaming an alias, moving an endpoint, or rotating a key while retaining the same authority therefore preserves receipt recovery.
Changing any covered declaration changes the fingerprint and makes a stale target mapping fail application construction, before any effect is attempted under another declared identity.
The connection does not inspect bearer bytes, so this proves continuity of the closed operator declaration, not that an issuer emitted matching claims.
A live issuer and Messaging recovery check remains required before claiming effective issuer/subject continuity under L2-04.

Construct the application inside each server worker after fork.
The module imports no native client at import time, and `create_app_from_environment()` calls `connect()` during application construction.
The built-in `app.run` path is a loopback development runner, not the production server recipe.

## Populate protected notice state

`MessageEffectStore.put_notice` represents an earlier application transaction.
Call it only with the verified `MachineContext`, the business-authorized recipient and template request, and the authority ID selected by protected application policy.
An existing `(caller, noticeId)` row is immutable and rejects changed content.

The SQLite implementation demonstrates one host with multiple threads or worker processes sharing a private local filesystem.
It uses an owner-only database, WAL, full synchronization, atomic state transitions, and a unique derived command key.
Owner-only file permissions do not encrypt recipient or template data at rest, so use storage protection appropriate to the institution's data policy.
A multi-host deployment should implement the same transitions in its application database rather than place SQLite on network storage.

## Verify

Run the pure-Python recovery and Flask boundary tests:

```sh
uv run --locked python -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py' -v
ruff format --check .
ruff check .
```

The tests cover exact protected-request forwarding, bounded duplicate-free JSON input, two configured bindings, caller-separated keys, changed-command conflicts, concurrent duplicates, native declared refusal, unknown outcome, process stop after acceptance, restart recovery, response-encoding failure, authority rename versus replacement, expired receipt behavior, machine admission, the pre-effect-only `429` rule, and minimized application audit correlation.

They use protocol doubles and do not establish a real issuer, Messaging, Coordinator, built-wheel, Linux, or multi-host result.
Complete acceptance still needs the matching assembled wheel, a real machine token, two real workload bindings, Messaging product denials and receipts, and Coordinator's actual `external.command/v1` interpretation and same-command recovery path.
