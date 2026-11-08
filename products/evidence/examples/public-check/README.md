# Public certificate check example

A holder (or anyone the holder shows the paper to) scans a QR code on a
certificate and sees whether that certificate is currently valid, suspended,
revoked or expired, with the fields printed on it. No account is needed. A
static page calls one Evidence route, `POST /v1/public-check`, which evaluates
one configured requirement against current registry state.

The route is experimental (`v1alpha1`). It is an unauthenticated route that
reads registry data, so read the proxy rule below before exposing it.

## What is in this directory

| Path | Purpose |
| --- | --- |
| `evidence.yaml` | The project: one assertion definition with a `publicCheck` member. |
| `public-check-target.yaml` | A check-only target (own signer, audit and subject-binding keys, and a minimal `authentication` block). |
| `check-authority.yaml` | The target authority that activates `publicCheck.definition`. It also carries one relying-service profile, because offline fixture evaluation resolves each case through an access profile; a deployed check-only instance that does not run fixtures can use `accessProfiles: {}`. |
| `functions/derive-certificate-check.rhai` | Maps registry states onto `valid`, `suspended`, `revoked`, `expired`, builds the printed fields, and refuses a status or date it cannot use. |
| `schemas/certificate-printed-fields.json` | Closed schema for the printed fields. Evidence accepts a reviewed structured value of 1 to 16 fields, and this definition also caps it at 1024 serialized bytes. |
| `fixtures/certificate-status.yaml` | One record per status, a record issued before check codes existed, and a record whose status the derivation refuses. |
| `adapter-packs/` | A synthetic pack whose certificate route projects a `checkCode` fact. Its facts schema declares types only (see "Writing a pack for a public check"). |
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

## The proxy rule

Run Evidence bound privately and put a path-restricted proxy in front of it. The
proxy must:

1. Forward exactly `POST` and `OPTIONS` on `/v1/public-check`. The proxy
   refuses everything else: the fragment below answers 403 to other methods on
   that path, and any other path matches no location and answers 404.
2. Apply a per-client request limit and a cap on the whole path, and answer 429
   when either is exceeded. Evidence has no rate limiter on this route and never
   reads a client address.
3. Keep no log with client addresses for that location, access or error. Nginx
   writes the client address into error-log lines, including `limit_req`
   refusals and upstream errors.
4. Terminate TLS on the check origin that is printed on the certificate.

The following nginx fragment illustrates the rule. It is not shipped
configuration; adapt it to your proxy.

```nginx
limit_req_zone $binary_remote_addr zone=check:1m rate=10r/m;
limit_req_zone $server_name zone=check_all:1m rate=300r/m;
limit_req_status 429;
limit_req_log_level warn;
location = /v1/public-check {
    limit_except POST OPTIONS { deny all; }
    limit_req zone=check burst=5 nodelay;
    limit_req zone=check_all burst=50 nodelay;
    access_log off;
    error_log /dev/null crit;
    proxy_pass http://127.0.0.1:8090;
}
```

The location-level `error_log /dev/null crit;` keeps `limit_req` refusals
(logged at `warn` here) and upstream errors out of any file. The operator gives
up the proxy-side upstream error lines for this path; Evidence still audits and
logs its own failures.

Run the check on its own Evidence instance, with only this definition and its
own keys. That keeps institutional signing keys out of an internet-reachable
process and stops a flood on the public path from using admission slots that
relying services need. A shared instance works but is not recommended.

## Writing a pack for a public check

The runtime compares the check code only after the Source returns a record, and
a number with no record never reaches a record-content failure. If a pack
refused one record's content before that comparison (a facts-schema refusal, a
script throw), the resulting 503 would show that the record exists. A register
that answers an error status for one record but not for an unknown number has
the same effect. The example
pack therefore keeps its facts schema to member types, declares a record whose
number does not exactly match the requested number as no-match, and checks
record content in the derivation, which runs after the comparison. There only a
caller holding the right check code sees a failure.

Give the Source's inputs schema a pattern for the number, as
`schemas/inputs.json` does. A number the inputs schema refuses answers `400`,
and the page says the number or code is not in the expected format. A number
it admits but that the route cannot place in a request path segment (a `/`, a
`%`, a dot segment) answers `503` instead, and the page says the service is
unavailable. If your certificate numbers can contain `/`, bind the number to a
query parameter rather than a path segment.

## Generating check codes

The system that issues the certificate generates the code and stores it on the
record; Evidence does not. Use 15 bytes from the operating system's random
source, encoded as base32 (RFC 4648) without padding. 15 bytes is 120 bits and
encodes to exactly 24 characters.

```python
import base64
import secrets

check_code = base64.b32encode(secrets.token_bytes(15)).decode("ascii")
assert len(check_code) == 24 and "=" not in check_code
```

Do not derive the code from the certificate number or from any key. It is a
capability the holder hands to the checker. A record issued before codes existed
has no code and can never match.

## The QR URL

Print this URL in the QR code, and print the check origin as text beside it so a
reader can tell a genuine paper from one pointing at a look-alike page:

```
https://check.example.org/#n=<url-encoded number>&c=<code>
```

The number and code are in the URL fragment (after `#`). Browsers do not send
the fragment to the static host, so the host's access log never holds a code.
The page removes the fragment from the address bar and the history entry once
it has read it. With no fragment the page shows a two-field form instead. The
page strips spaces and hyphens from the code before sending it.

## Serving the page

Serve the contents of `page/` from any static host on the check origin, or from
the same origin as the proxy. Then:

- Set the `check-endpoint` meta value in `index.html` to your route, for example
  `https://check.example.org/v1/public-check`.
- Set `connect-src` in the page's Content-Security-Policy meta to that origin.
- Evidence answers `OPTIONS` on the route and sends `Access-Control-Allow-Origin: *`,
  so the page can live on a different origin from the proxy. The route carries no
  cookie or token, so the wildcard grants nothing a plain HTTP client lacks.

The page has no dependencies and no build step. It writes every value from the
network with `textContent`, stores nothing, and loads nothing from a third party.
For a quick local look:

```sh
python3 -m http.server 8000 --directory page
```

Test its pure functions (fragment parsing, code normalization, request body,
status messages) with:

```sh
node --test page/check.test.mjs
```
