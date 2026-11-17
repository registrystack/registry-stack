# Public certificate check example

A holder (or anyone the holder shows the paper to) scans a QR code on a
certificate and sees whether that certificate is currently valid, suspended,
revoked or expired, with the fields printed on it. No account is needed. A
static page calls one Evidence route, `POST /v1/public-check`, which evaluates
one configured requirement against current registry state.

The route is experimental (`v1alpha1`). It is an unauthenticated route that
reads registry data, so read the proxy rule in the operator guide below before exposing it.

## What is in this directory

| Path | Purpose |
| --- | --- |
| `evidence.yaml` | The project: one assertion definition with a `publicCheck` member. |
| `public-check-target.yaml` | A check-only target (own signer, audit and subject-binding keys, and a minimal `authentication` block). |
| `check-authority.yaml` | The target authority that activates `publicCheck.definition`. It also carries one relying-service profile, because offline fixture evaluation resolves each case through an access profile; a deployed check-only instance that does not run fixtures can use `accessProfiles: {}`. |
| `functions/derive-certificate-check.rhai` | Maps registry states onto `valid`, `suspended`, `revoked`, `expired`, builds the printed fields, and refuses a status or date it cannot use. |
| `schemas/certificate-printed-fields.json` | Closed schema for the printed fields. Evidence accepts a reviewed structured value of 1 to 16 fields, and this definition also caps it at 1024 serialized bytes. |
| `fixtures/certificate-status.yaml` | One record per status, a record issued before check codes existed, and a record whose status the derivation refuses. |
| `adapter-packs/` | A synthetic pack whose certificate route projects a `checkCode` fact. Its facts schema declares types only (see the operator guide for why). |
| `page/` | The static page: `index.html`, `check.js`, `check.css`, and `check.test.mjs`. |

## How the two keys work

The package declares the ceiling and the target authority grants it, as for any
other Evidence disclosure:

```yaml
# evidence.yaml, on the assertion definition
publicCheck:
  checkCodeFact: checkCode   # projected source fact holding the stored code
  statusOutput: status       # controlled-category output, values within the four statuses
  fieldsOutput: printed      # reviewed-structured-value output; its inner fields become "fields"
```

```yaml
# check-authority.yaml
publicCheck:
  definition: certificate-status
```

Declaring `publicCheck` in the package does nothing by itself. Until a target
authority activates it, the route is not registered and answers like any
unknown route. One activated definition serves one Evidence process.

## The request and the answer

```
POST /v1/public-check
Content-Type: application/json

{"documentNumber": "RN-2026-004217", "checkCode": "K7QWM4XRT5PZ3NB6VHJYDC2A"}
```

The check code is exactly 24 characters of base32 (`^[A-Z2-7]{24}$`). The
server uppercases ASCII letters before comparing, so lowercase input is
accepted; the stored code is uppercase. A match returns:

```json
{
  "schema": "registry.evidence.public-check/v1alpha1",
  "status": "valid",
  "fields": {"holderName": "Jordan Sample", "issuedOn": "2025-03-01", "expiresOn": "2099-12-31"},
  "observedAt": "2026-11-08T09:14:03Z"
}
```

The answer is not signed. A wrong number, a wrong code, a record with no stored
code and every other unresolved case return the same `404 resource.not-found`,
so the response does not say which part was wrong.

Malformed input returns `400 evidence.invalid-request` or
`400 request.selector-invalid` before any audit or registry read. That includes
a value that passes the selector profile but that the Source's inputs schema
refuses, such as one with a `/`, a `%` or a dot segment.

The runtime compares the check code only after the Source returns a record. Any
Source failure before that point (transport, timeout, budget, an error status
from the Source, or protocol, which includes a facts-schema refusal and an
extract-script failure) answers `503 source.unavailable`. The only statuses are
`valid`, `suspended`, `revoked` and `expired`; anything else fails closed.

## Exposing and operating the route

The route is unauthenticated, so put a path-restricted proxy in front of it
before exposing it. The proxy rule, pack-writing constraints, check-code
generation, QR URL and page hosting are in
[Operate the Registry Evidence audit log](https://docs.registrystack.org/operate/evidence-audit/#expose-the-public-check-route).

## Running the page locally

The page has no dependencies and no build step. For a quick local look:

```sh
python3 -m http.server 8000 --directory page
```

Test its pure functions (fragment parsing, code normalization, request body,
status messages) with:

```sh
node --test page/check.test.mjs
```
