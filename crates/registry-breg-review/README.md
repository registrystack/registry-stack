# Base Registry Engine review page

`breg-review` is a small server-rendered page where a signed-in person reads
their own Base Registry Engine change-request draft beside the record it would
change, and submits it. It is the place a person confirms a change another
tool, such as an agent acting for them, prepared as a draft.

The page has no authority of its own. It signs the person in, keeps their
access token on the server, and makes every read and the submit with that
token through one configured access profile. What the person may see and
submit is the registry's decision, not the page's.

## Configuration

`breg-review --runtime-config /absolute/path/review.yaml` reads one closed YAML
document. Unknown keys are refused, and an error names the key path without
echoing its value.

```yaml
apiVersion: registry.registrystack.org/breg-review-runtime/v1alpha1
kind: BRegReviewRuntimeConfig
listener:
  bind: 127.0.0.1:8110
  tlsTermination: operator-controlled-upstream   # or development-loopback
  networkExposure: private-address               # or container-private
publicOrigin: https://review.example
secretProviders:
  file:
    root: /run/secrets/breg-review
signIn:
  issuer: https://issuer.example
  clientId: citizen-review-page
  clientKeyRef: secret:file/client-key.jwk       # private JWK for private_key_jwt
  scopes: [address-correction:self]
registry:
  baseUrl: https://registry.example
  resource: https://registry.example/citizen-address-correction
  entity: address-correction-request             # the change-request entity
  targetField: address                           # the reference to the changed record
  accessProfile: citizen-review
audit:
  path: /var/lib/breg-review/journal
  hashKeyRef: secret:file/audit-key
limits:                                           # optional
  perCitizen: { requestsPerMinute: 120, burst: 30 }      # each signed-in person
  globalSignIn: { requestsPerMinute: 600, burst: 120 }   # everyone, sign-in routes only
session:                                          # optional
  maximumSessions: 10000
  maximumPendingSignIns: 10000
  maximumLifetimeSeconds: 3600
  signInLifetimeSeconds: 600
```

Secrets are references (`secret:file/...` or `secret:env/...`), never inline
values. The redirect URI registered with the provider is `publicOrigin` followed
by `/signin/callback`. `development-loopback` is for a loopback listener only:
it drops `Secure`, the `__Host-` cookie prefix, and HSTS, and relaxes the
provider endpoint policy to loopback HTTP.

`BREG_REVIEW_LOG` selects the operational log level: `error`, `warn`, or
`info` (the default). Any other value stops startup with exit status 2, so a
typo cannot silently change what is logged. The operational log is JSON on
standard error.

## Sign-in

The page is an OpenID Connect relying party and a confidential OAuth client.

1. `GET /signin?return=/requests/{id}` starts the authorization code flow with
   PKCE (S256), a `state`, a `nonce`, and the RFC 8707 `resource`. The pending
   sign-in lives on the server; the browser holds only a random identifier in a
   `SameSite=Lax` cookie.
2. `GET /signin/callback` checks the `state` against that cookie and the RFC
   9207 `iss` parameter (required when the provider advertises it), then
   redeems the code with `private_key_jwt` client authentication through
   `registry-platform-httputil`. It verifies the ID token's signature, issuer,
   audience, expiry, and `nonce` against the provider's JWKS.
3. It opens a session keyed by a random identifier in a `SameSite=Strict`
   cookie. Because a Strict cookie is not sent on the cross-site redirect back
   from the provider, the callback answers with a short page that continues to
   the review page from the page's own origin.

A session ends at `maximumLifetimeSeconds` or when the access token expires,
whichever comes first; a token that states no expiry opens no session. When
the registry stops accepting the token, the session ends and the person is sent
to sign in again.

## Review and submit

`GET /requests/{id}` reads the draft, then reads the record its `targetField`
names, both under the person's token. The registry does not tie a request's
target to the person holding the request, so a draft naming a record this
person may not read renders the same neutral not-found page as a missing draft,
with no form. When both reads succeed, the page shows the current values next to
the proposed ones, labelled from caller-filtered registry metadata.

The submit form appears only when the registry offers `submit_request` on the
draft. The page remembers that exact action and a fresh idempotency key as a
view bound to the session and the request. `POST /requests/{id}/submit`
checks the CSRF token, repeats both reads, and only then submits the remembered
action under its key. A crafted form cannot skip the target read, a replayed
submit returns the first receipt, and a stale view renders the current state
with a notice instead of submitting.

## Security model

- The browser never holds a token. Cookies are `HttpOnly`, `Path=/`, and in
  production `Secure` with the `__Host-` prefix.
- Every response carries a deny-by-default content security policy that allows
  only the page's own stylesheet and form targets. Every response except the
  stylesheet carries `Cache-Control: no-store`.
- Form bodies are bounded, single-valued, and closed to the `csrf` and `view`
  fields. CSRF tokens are compared in constant time.
- The page reads neither peer addresses nor forwarded headers, so it cannot
  tell one browser from another before sign-in, and behind a reverse proxy
  every browser would share one address anyway. It keeps two limits of its
  own:
  - `limits.perCitizen` applies to every request that presents a session,
    keyed by the signed-in person, so one person's sessions share it and
    never slow anyone else.
  - `limits.globalSignIn` is one limit shared by everyone on `/signin` and
    `/signin/callback`. It bounds the sign-in work the page does, and a flood
    of sign-in starts can use it up for everyone until it refills.
- Per-client limiting belongs at the edge proxy, and operators must configure
  it there: the page's global sign-in limit is a ceiling, not a defense for
  any one person.
- Every started sign-in waits in memory until its callback or
  `signInLifetimeSeconds`. Startup refuses a `maximumPendingSignIns` smaller
  than the sign-ins `globalSignIn` admits in that lifetime (its burst plus its
  rate over the lifetime), so the limit, not a full store, is what refuses a
  sign-in. A full store would still answer a `sign-ins-exhausted` page.
- The audit journal is hash-chained and records each sign-in, read, submit, and
  sign-out with its outcome. It names people and the client only by keyed
  pseudonyms and never holds a token, cookie, CSRF value, record value, or
  network address.
  When the journal cannot record an action, the page refuses the action.
- Neither the operational log nor the journal carries a token, code, state,
  nonce, cookie, or subject identifier.

## Tests

`cargo test -p registry-breg-review` runs the page against a mock registry and
the platform test authorization server, and runs the built binary to check its
startup refusals and that a full journey leaves no credential in its log or
journal.

The `postgres-test` feature adds `tests/postgres_breg.rs`, which runs the page
against a real Base Registry Engine serving the citizen address correction
acceptance project on a disposable PostgreSQL database. It needs
`BREG_TEST_DATABASE_URL` and fails, rather than skips, without it:

```bash
BREG_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
  cargo test --locked -p registry-breg-review --features postgres-test --test postgres_breg
```

`registry-breg` is a dev-dependency, linked only into tests; the page itself
depends on the registry through `registry-breg-client` alone, and
`products/breg/scripts/check-service-dependencies.sh` fails if the runtime
enters its normal dependency graph. The Base Registry Engine PostgreSQL lane
(`products/breg/scripts/test-postgres.sh`) runs this test.
