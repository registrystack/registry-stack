# Experiment 2: FHIR R4 conditional create of a Patient

Status: experiment, not a maintained pack. Authored from the public FHIR R4
specification only; no server was contacted. Nothing here changes Rust.

## What it tries to express

`records.create` on the `breg-records` profile, written to a FHIR R4 server
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
- The created Patient is read back (`GET /Patient/{id}`) and mapped to the
  record.

## What it proves

- The write rules work as designed on this shape:
  - removing `idempotentUpstream` gives
    `adapter.route.redelivery-over-non-safe-send` (probe `e2-not-idempotent`);
  - a second non-safe send gives `adapter.route.multiple-non-safe-sends`
    (probe `e2-two-writes`);
  - sends outside `idempotentConsumer` give
    `adapter.route.write-without-idempotency` (probe `e2-no-consumer`).
- Budget arithmetic: 2 sends x (1 + 1) + 1 = 5; budget 4 refused, 5 passes
  (probes `e2-budget4`, `e2-budget5`).

## What it could not express (gaps)

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
   a bare assertion. Probe `e2-direct-post` changes the send to a plain
   `POST /Patient` (which creates a duplicate on every retry) and the check
   still passes. Nothing ties the claim to a mechanism (a conditional header,
   an upstream idempotency key, a PUT to a client-chosen id).
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
   `PUT`, `PATCH` (probe `e2-delete`), so `records.delete` against FHIR
   cannot be bound.
6. **Fixtures.** An entry holds one upstream exchange, no facade request,
   and no request headers (probes `e2-fixture-two-exchanges`,
   `e2-fixture-request-headers`), so the create-then-read and the
   `Idempotency-Key` replay cannot be recorded.

## Check defects found

- **Endpoint-wide idempotency inheritance** (probe `e2-no-operation`): with
  `operation` omitted on the POST, and `idempotentUpstream: true` moved onto
  the unrelated `fhir.read`, redelivery over the POST passes. The check
  treats any idempotent operation on the endpoint as covering an unnamed
  send.
- **Redelivery does not look through `direct:`** (probe `e2-direct-hop`):
  with no `idempotentUpstream` at all, moving the POST into a
  `direct:postTransaction` route makes redelivery over it pass.
- `redelivery-over-non-safe-send` is reported twice, once at
  `/routes/createPatient` (a route template, not a route) and once at
  `/routes/patientCreate`.

## Check run

```
adapterctl check products/adapter/experiments/fhir-r4-conditional-create/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/experiments/fhir-r4-conditional-create/runtime.yaml
Authoring check passed.
0 errors, 0 warnings in 9 files
exit=0
```

Probe outputs are recorded verbatim in the findings report returned with these
experiments, not in this directory.
