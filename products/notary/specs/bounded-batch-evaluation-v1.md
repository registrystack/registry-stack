# Bounded batch evaluation v1

Status: runtime contract for `POST /v1/batch-evaluations`

## Scope

Batch evaluation is a bounded transport convenience for repeating the existing
single-evaluation policy over multiple targets. It does not introduce a Relay
batch protocol, batch credential issuance, or an OID4VCI batch route. Every
member keeps the authorization, purpose, consent, provenance, minimization,
and audit requirements of a corresponding single evaluation.

The concrete threat is amplification. An apparently small request can consume
quota, reserve durable idempotency state, dispatch private consultations, and
retain results for many targets. The invariant is that admission for the whole
batch is bounded and side-effect free. Only admitted members may enter the
side-effecting execution phase.

## Limits

The platform ceiling is 100 members. It is not configurable upward. The
effective member limit is:

```text
min(
  100,
  evidence.inline_batch_limit,
  selected_claim_1.operations.batch_evaluate.max_subjects,
  ...,
  selected_claim_n.operations.batch_evaluate.max_subjects
)
```

Both configurable limits accept only `1..=100`. Configuration loading rejects
zero and values above 100. A request above the effective limit returns HTTP
413 with `batch.too_large` before quota debit, idempotency reservation, Relay
dispatch, source access, or retained evaluation state.

The member limit composes with existing independent bounds:

- the HTTP request body is at most 1 MiB;
- one Relay result is at most 64 KiB;
- one batch may form at most 256 consultation groups;
- one Relay operation has a 25 second deadline;
- the outer request timeout defaults to 30 seconds and must preserve the Relay
  deadline plus the runtime reserve;
- member concurrency defaults to 16 and Relay concurrency defaults to 8; and
- the Rust client accepts at most a 16 MiB response.

There is intentionally no aggregate byte counter across all Relay results.
Operators and clients should use smaller batches when member results approach
the per-result or response-read bounds.

## Two-phase processing

Phase one performs pure admission and planning for every member. It validates
the member count, claims and versions, operation enablement, authorization,
purpose, disclosure, format, identity shape, relationship, consultation
contracts, and consultation-group bound. Any phase-one failure rejects the
whole request. No member is dispatched.

Phase two performs admitted work with bounded concurrency. The response is an
ordered HTTP 200 result whose `items` preserve request order. Each item is
either `succeeded` with its normal minimized claim results or `failed` with a
closed, value-free error. A member's operational failure does not turn into a
claim value or `no_match`, and it does not erase the outcomes of other
members.

## Identity, audit, and replay

Registry-backed batches require one caller-scoped `Idempotency-Key`. The
runtime derives deterministic child identities from the caller, outer key,
request digest, and member index. The same caller must retry an interrupted or
lost-acknowledgement request with the same outer key and identical body.
Completed requests replay their stored ordered response. A changed body,
caller scope, or execution-defining configuration conflicts with the existing
key.

Cancellation returns no partial response and commits no partial retained
evaluations. Relay work already dispatched before cancellation may have been
observed by Relay or its source. A retry therefore reuses the deterministic
child identity while allowing a new transport attempt.

Audit records are value-free. Each member records its input index, outcome,
requester and target types, keyed requester and target pseudonyms when an
identifier is available, and consultation evidence. Failed attempts use the
same keyed-pseudonym construction as successful attempts. Raw identifiers,
consultation inputs, consultation outputs, and claim values must never enter
the audit record or ordinary logs.

## Issuance boundary

Batch evaluation produces evaluation responses only. It cannot issue a batch
credential and it cannot use an OID4VCI batch credential route. A successful
member may be retained only under the normal single-evaluation retention and
issuance rules. Any later credential request is a separate authorized action
over one retained evaluation.

## Release evidence

Before a release candidate is promoted, the frozen candidate must execute
10,000 repeated bounded batches with exact request and response digests. The
evidence must cover process restart, a lost acknowledgement, cancellation
followed by retry, stable child identities, ordered results, and the absence of
extra Relay dispatch on a completed replay.
