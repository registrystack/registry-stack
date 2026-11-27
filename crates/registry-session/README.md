# registry-session

A small session service beside a gateway. A person signs in once through the
service. It keeps their tokens on the server and gives the browser one opaque
cookie. The gateway asks the service, on every call to a signed-in route, which
bearer token to attach. The service checks. It never proxies.

## Operator obligations and trade-offs

### The check listener must be reachable only by the gateway

The check listener hands out bearer tokens to any caller that holds a session
cookie, and it trusts the `Origin`, `Sec-Fetch-Site` and `Registry-Client`
headers the caller sends. It has no authentication of its own. Keep it on a
loopback or private address that only the gateway reaches.

With `networkExposure: container-private`, the runtime file may bind the check
listener to the unspecified address. `registry-session check` reports that as the
warning `platform.session-runtime.check-listener-unspecified`. Restrict the check
port to the gateway with a network policy or an equivalent control.

### The session store is bounded

The store holds at most `session.maximumSessions` sessions. A session ends in any
of these ways:

- the person signs out,
- it passes `session.absoluteLifetimeSeconds`,
- no request presents it for `session.idleLifetimeSeconds` (default 1800, between
  300 and the absolute lifetime),
- a sign-in by the same person pushes out their oldest session (three at once),
- the issuer refuses its renewal.

When the store is full, a sign-in first drops every session that is past its
absolute or idle lifetime. If the store is still full, the sign-in is refused with
503 `session.busy`. New sign-ins are refused rather than live sessions evicted.
The trade-off is that a flood of sign-ins can keep new people out until sessions
go idle, while nobody already signed in is signed out by the flood. Size
`maximumSessions` for your population, watch for `session.busy`, and rate-limit
sign-ins at the gateway.

### Renewal and an unreachable issuer

A call to a module is renewed when the access token has less than the smaller of
`session.renewBeforeSeconds` and half its issued lifetime left. A check never
waits on the issuer while its token is still valid:

- if another check is already renewing the session, the call is allowed with the
  unexpired token at once,
- after the issuer cannot be reached, renewal for that session backs off (5
  seconds, doubling to at most 60), and calls use the unexpired token meanwhile.
  An expired token during the backoff answers 503 `session.unavailable` without a
  call to the issuer,
- at most 32 renewals are in flight at the issuer across the whole service, and a
  call that finds none free uses its unexpired token.

`issuer.timeoutMilliseconds` (default 2000) must be below
`gateway.checkTimeoutMilliseconds` (default 3000), so the gateway does not give up
on a check that is still waiting for the issuer. A timeout after the issuer has
rotated a refresh token behaves like a lost response: the next renewal presents a
spent token, the issuer may revoke the token family, and the session ends. Do not
set the timeout below the issuer's real latency.

### Revocation of sessions that end without a sign-out

When a session ends without a sign-out (absolute or idle expiry, eviction, a
refused renewal), its remaining refresh tokens are revoked at the issuer on a
bounded background queue, off the request path. A full queue or a revocation the
issuer does not confirm is logged in fixed text and counted. Keep the issuer's
refresh token lifetime no longer than `session.absoluteLifetimeSeconds` as well.

### Pages do not consult the issuer

A page route needs a session of its kind and nothing more. A session revoked at
the issuer keeps passing page checks until a module renewal fails or the session
reaches its absolute or idle lifetime.

### Health routes

`/healthz` and `/readyz` share the check router. The gateway sends every check
under the `/check` prefix, so no original path can reach them. The generated
gateway configuration asserts that prefix. Do not drop it from a hand-written one.

### Modules on the person audience

A module routed on `audience: person` must carry the name of a product that is a
member of the person audience as its `id`. `registry-session check
--identity-receipt` refuses a person-audience module whose id is not one of the
receipt's person-audience member products. A product with its own audience, such
as a scheduling product, is written with that audience instead of `person`.

### The public origin

`publicOrigin` is written as a browser sends it in the `Origin` header: lower-case
scheme and host, no default port, no path, no trailing slash. Under
`development-loopback` it must be `http://127.0.0.1`, `http://[::1]` or
`http://localhost`, with any port.
