# Source shape: FHIR R4 conditional create of a Patient

A source-shape fixture, not a maintained pack. It holds one upstream write
shape against the authoring check, the compiler, fixture replay, and the
served runtime. The synthetic fixtures remain documented examples. A
bounded controlled acceptance also exercised this exact transaction shape
against HAPI FHIR 8.12.0 serving FHIR 4.0.1; that does not establish general
FHIR server compatibility.

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
- `412` raises `outcome.rejected`, which the profile maps to
  `source.write-rejected` (409). Other HTTP, malformed, script, validation,
  timeout, and connection failures retain their engine classes for the
  profile to map. The pack never constructs a problem body.
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
  acquisition, transaction, and read-back) plus the minimized fixture derived
  from a HAPI multiple-match refusal in `fixtures/multiple-match.yaml` through
  the idempotent-consumer control path in memory;
  `products/adapter/scripts/check-contracts.sh` runs both.
- `crates/registry-adapter/tests/experiments_served.rs` (feature
  `postgres-test`, run by `products/adapter/scripts/test-postgres.sh`)
  serves the shape through the real Adapter binary against a socket
  upstream.
- A bounded controlled HAPI FHIR 8.12.0 acceptance served this shape through
  the normal Adapter facade. It verified one conditional create and read-back,
  exact same-key replay with no new provider effect, a new key with the same
  identifier returning the same Patient, and a real multiple-match refusal
  mapped to `source.write-rejected`. This is evidence for the retained
  transaction shape only.

## Recorded gaps

These were recorded against the authoring model when the shape was written;
the pack's comments point here. `CONCEPT.md` holds the current contract for
each construct.

1. **The retained transaction form.** The current endpoint model can
   allowlist `If-None-Exist` under `requestHeaders`, and a preceding
   `setHeader` can therefore author the direct conditional-create form. This
   older shape still routes the condition through the body: a one-entry
   `transaction` Bundle posted to the base with `entry.request.ifNoneExist`
   (https://hl7.org/fhir/R4/bundle-definitions.html#Bundle.entry.request.ifNoneExist).
   That works only on servers that support transactions, changes the status
   semantics (the HTTP status is the Bundle's `200`; the per-entry status is
   in `entry[0].response.status`), and this shape does not set the now-supported
   `Prefer: return=representation` header. Hence the second send to read the
   Patient back. The controlled HAPI acceptance covers this transaction form,
   not the direct header form.
2. **The idempotency claim is unverifiable.** `idempotentUpstream: true` is
   a bare assertion. Changing the send to a plain `POST /Patient` (which
   creates a duplicate on every retry) still passes the check. Nothing ties
   the claim to a mechanism (a conditional header, an upstream idempotency
   key, a PUT to a client-chosen id).
3. **Status inside a 200.** HAPI returns HTTP 412 for the captured
   multiple-match case, which the pack translates with `throwException`.
   A server may instead return a transaction-response whose entry status
   (`201 Created` vs `200 OK` for an existing match) is not an HTTP status,
   so `okStatusCodeRange` and the error classes cannot see it; a script
   must inspect it and a subsequent branch must raise the appropriate closed
   class with Camel `throwException`:
   https://camel.apache.org/components/next/eips/throwException-eip.html.
4. **Comparing the status.** The 412 test needs Rhai
   (`scripts/is-multiple-match.rhai`) because the inline languages have no
   comparison. Script views expose the engine header under the lowercase key
   `headers["camelhttpresponsecode"]`; Camel Simple would use
   `${header.CamelHttpResponseCode} == 412`.
5. **DELETE remains outside the method set.** `httpMethod` accepts only
   `GET`, `POST`, `PUT`, and `PATCH`, so `records.delete` against FHIR cannot
   be bound.

## Check

```
adapterctl check products/adapter/fixtures/source-shapes/fhir-r4-conditional-create/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --runtime products/adapter/fixtures/source-shapes/fhir-r4-conditional-create/runtime.yaml
```
