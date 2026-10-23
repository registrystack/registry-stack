# HTTP problems and recovery

Use the owning route contract to decide whether an operation completed, was
refused, or has an unknown outcome. A shared envelope does not change a
product's authorization, concealed existence, or retry semantics.

## Problem envelope

The common RFC 9457 response is `application/problem+json` with six fields:

| Field | Contract |
|---|---|
| `type` | Absolute opaque problem URI owned by the product. Never dereference it to authorize recovery. |
| `title` | Fixed safe category text. |
| `status` | Integer equal to the HTTP status. |
| `detail` | Fixed safe guidance, with no submitted or source values. |
| `code` | At most 128 ASCII bytes, `family.reason`. Each segment starts with a lowercase letter and contains lowercase letters, digits or hyphens. |
| `traceId` | Canonical nonzero 32 lowercase hexadecimal characters, equal to the trace in the response `traceparent`. |

`registry-platform-httpsec` supplies `ProblemBody`, `TraceContext`, and the
strict client `ProblemDocument`. The server replaces malformed or repeated
trace input and never reflects `tracestate`. A product may create a fresh
response trace. Problems use `Cache-Control: no-store`.

Extensions must be explicitly defined, structurally bounded, and safe. A
field path may name declared structure, never a record identifier or submitted
value. Render's bounded pointer list and Casework's validation metadata remain
product contracts. Clients reject duplicate members, excessive bytes and
invalid known members. A closed client rejects extensions unless its owning
contract explicitly accepts them; sharing the core envelope does not widen it.

Discovery preserves its problem type URIs and adds `request.invalid`,
`request.not-found`, `request.result-bound-exceeded`, and `service.unavailable`
codes, fixed `detail`, and `traceId`. Its indeterminate 503 carries no guessed
retry interval. Its client also accepts the original `type`/`title`/`status`
trio and genuinely additive members. When supplied, recognized members must be
bounded and valid: a known type's `code` must agree, `detail` must be safe text,
and `traceId` must match a valid response `traceparent`. Compatible guidance
may change without exact-text matching. Unknown future Discovery problem types
retain their bounded, status-only fallback. Render uses the same core with its
own vocabulary and extensions.

## Deliberate response exceptions

Casework `GET /v1/review-requests/{requestId}/result` returns bodyless 202 for
pending, 404 for concealed-or-unknown, and 410 for expired. The shared Review
client maps these states without requiring a problem body. A result still
must match the persisted accepted request, policy, subject and submission digest.

Scheduling returns the same public appointment outcome when the appointment
is missing or denied. Keep that concealment when presenting or classifying a
failure. Its readiness route follows its own deployment health contract.

Invalid credentials use generic 401 `authentication.refused`. Profile or
route authority failures retain the product's documented 403 or concealment;
a verifier outage retains its documented 503. Internal stage diagnostics do
not become public error details.

## Idempotency and retries

Use a caller-owned key and keep the original body, headers and accepted binding
when reconciling an uncertain mutation. Reusing a key with another request
is 409 `idempotency.key-reused` from Casework, Coordinator, Messaging and
Scheduling, and 409 `idempotency.conflict` from BReg. Classify a 409 by the
product that returned it.

128 bytes is portable key guidance, not a replacement for route limits.
BReg and Coordinator preserve their existing 256-byte bounds; Casework,
Scheduling and Messaging keep their owning limits. `idempotency.key-invalid`
means a missing or invalid key under that route's rules; never classify a
valid 129-256-byte BReg or Coordinator key as invalid for portability.

`Retry-After` appears only when the server knows a useful interval. Messaging
rate/quota refusals supply bounded waits; Casework polling and readiness use
their owning response contracts. Evidence `503 source.unavailable` omits `Retry-After` when upstream recovery
time is unknown, while meaningful rate-limit hints remain. Source-data
reachability does not decide Evidence `/ready`: an instance with healthy
required dependencies can remain ready during a source-data outage. No
data-endpoint probes are added to readiness.

An indeterminate outage, a deterministic
non-retryable failure, or a readiness contract without a known interval need
not carry it. Clients preserve absent, invalid and bounded interval states;
waiting remains a caller decision. A header never authorizes a fresh-key
repeat of an uncertain mutation. See [client retry rules](../../crates/CLIENTS.md).

BReg pagination uses `$top` and `$skiptoken` (Python `top`); Casework,
Scheduling and Coordinator use `limit` and `cursor`. SDKs expose each actual
contract and do not automatically follow continuations.
