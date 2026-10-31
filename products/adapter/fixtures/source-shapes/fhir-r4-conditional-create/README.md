# Source shape: FHIR R4 conditional create of a Patient

A source-shape fixture, not a maintained pack. It holds one upstream write
shape against the authoring check, the compiler, fixture replay, and the
served runtime. Authored from the public FHIR R4 specification only; no
server was contacted.

## The shape

`records-create` on the `breg-records` profile, written to a FHIR R4 server
so that a retried create never makes a second Patient:

- FHIR's own answer is conditional create: `POST /Patient` with
  `If-None-Exist: identifier=<system>|<value>`
  (https://hl7.org/fhir/R4/http.html#ccreate). No match creates, one match
  returns the existing resource, several matches fail with `412`.
- The facade write carries `Idempotency-Key`, deduplicated by
  `idempotentConsumer`.
- Timeouts and connection failures redeliver once; that is only safe
  because the upstream write is conditional (`idempotentUpstream: true`).
- `412` maps to `source.write-rejected` (409); other `upstream.http` to the
  same code with a different title; malformed answers to
  `source.upstream-error` (502).
- The created Patient is read back (`GET /Patient/{{id}}`) and mapped to the
  record.

## What it proves

- The write rules hold on this shape:
  - removing `idempotentUpstream` gives
    `adapter.route.redelivery-over-non-safe-send`;
  - a second non-safe send gives `adapter.route.multiple-non-safe-sends`;
  - sends outside `idempotentConsumer` give
    `adapter.route.write-without-idempotency`.
- Budget arithmetic: 2 sends x (1 + 1) + 1 = 5; budget 4 refused, 5 passes.
- `adapterctl compile --check` holds the committed `generated/openapi.json`,
  and `adapterctl fixtures replay` replays `fixtures/create-new.yaml` (token
  acquisition, transaction, and read-back) through the idempotent-consumer
  control path in memory; `products/adapter/scripts/check-contracts.sh`
  runs both.
- `crates/registry-adapter/tests/experiments_served.rs` (feature
  `postgres-test`, run by `products/adapter/scripts/test-postgres.sh`)
  serves the shape through the real Adapter binary against a socket
  upstream.

## Recorded gaps

These were recorded against the authoring model when the shape was written;
the pack's comments point here. `CONCEPT.md` holds the current contract for
each construct.

1. **The `If-None-Exist` header.** `to.parameters` has no request headers,
   so the direct form cannot be authored. The pack routes the condition
   through the body instead: a one-entry `transaction` Bundle posted to the
   base with `entry.request.ifNoneExist`
   (https://hl7.org/fhir/R4/bundle-definitions.html#Bundle.entry.request.ifNoneExist).
   That works only on servers that support transactions, changes the status
   semantics (the HTTP status is the Bundle's `200`; the per-entry status is
   in `entry[0].response.status`), and returns no resource without
   `Prefer: return=representation`, also a request header. Hence the second
   send to read the Patient back.
2. **The idempotency claim is unverifiable.** `idempotentUpstream: true` is
   a bare assertion. Changing the send to a plain `POST /Patient` (which
   creates a duplicate on every retry) still passes the check. Nothing ties
   the claim to a mechanism (a conditional header, an upstream idempotency
   key, a PUT to a client-chosen id).
3. **Status inside a 200.** The transaction-response entry status
   (`201 Created` vs `200 OK` for an existing match) is not an HTTP status,
   so `okStatusCodeRange` and the error classes cannot see it; a script
   would have to raise. There is no construct for "raise this error class
   from a script result" (Camel `throwException`:
   https://camel.apache.org/components/next/eips/throwException-eip.html).
4. **Comparing the status.** The 412 test needs Rhai
   (`scripts/is-multiple-match.rhai`) because the inline languages have no
   comparison (Camel would use Simple `${header.CamelHttpResponseCode} == 412`).
5. **DELETE is not a method.** `httpMethod` accepts only `GET`, `POST`,
   `PUT`, `PATCH`, so `records.delete` against FHIR cannot be bound.

## Check

```
adapterctl check products/adapter/fixtures/source-shapes/fhir-r4-conditional-create/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/fixtures/source-shapes/fhir-r4-conditional-create/runtime.yaml
```
