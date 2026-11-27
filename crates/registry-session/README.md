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

### Revocation happens off the request path

No request waits on the issuer to end a session or a sign-in. Whatever drops a
refresh token hands it to a bounded background queue (1024 entries) that revokes it
at the issuer:

- a sign-out removes the session, writes the audit record, clears the cookie and
  redirects to the issuer's end-session endpoint at once, then queues the
  revocations. It never waits for a renewal in flight. A renewal that finishes
  after the session is gone revokes the token it rotated,
- absolute expiry, idle expiry, eviction and a refused renewal,
- a session a new sign-in pushes out (three at once per person), and the session a
  browser already holds when someone signs in through it,
- a sign-in that fails, expires, or is abandoned, including the refresh tokens of
  the hops it had finished. A sign-in the person never returns to is reaped every 15
  seconds, as are sessions nobody presents again,
- a callback the gateway or the browser gives up on. The callback's work runs in its
  own task, so tokens the issuer issued are not dropped half way. A session that task
  opens with nobody left to receive it is ended at once.

A full queue or a revocation the issuer does not confirm is logged in fixed text and
counted, never hidden. Keep the issuer's refresh token lifetime no longer than
`session.absoluteLifetimeSeconds` as well.

The service keeps no state on disk. A restart or a shutdown drops every session and
every sign-in in progress without revoking their refresh tokens: they stay live at the
issuer until their own expiry. Set the issuer's refresh token lifetime with that in
mind.

### Rate limits

`rateLimits.globalSignIn` is one bucket for everyone starting a sign-in. A start is
charged only once its return path is accepted. A callback is never charged, because it
needs the pending sign-in a charged start created, so a person already at the issuer
always comes back. The default (900 a minute, burst 300) is generous so a burst of real
sign-ins is not refused. The service reads no peer address and no forwarded header, so
it cannot tell one client from another: limit each address on `/session/sign-in` at the
gateway.

`rateLimits.perPerson` is one bucket per signed-in person, shared by their sessions. It
covers the sign-in that names the person (once, when the first hop returns) and
`GET /session/me`. It does not cover sign-out, which always ends the session, or the
gateway check, which leaves limits on module calls to the modules and the gateway.

### Access token audience

After each hop and each renewal the service reads the `aud` of the access token the
issuer returned, from the token's payload, and refuses the sign-in (or ends the
session) when it does not contain the resource the request asked for, revoking what the
issuer issued. The payload comes from the issuer's own token endpoint, so its signature
is not checked here: this guards against an issuer that ignores the requested resource.
A token that is not a JWT with a readable `aud` cannot be checked, is kept, and the gap
is logged in fixed text. An issuer that returns opaque access tokens therefore gets no
audience check from this service.

### Sign-out is a top-level form post

The issuer's session ends only when the browser visits its end-session endpoint as a
top-level navigation. A sign-out sent by `fetch` follows the 303 as a cross-origin
request, so it cannot end the issuer's session: the next sign-in in that browser may
be silent as the same person. Pages sign out with a form `POST` to `/session/sign-out`.

### A module's `signIns` list is routing, not access control

`signIns` on a module names the kinds of sign-in the gateway routes to it. It does not
decide who may act: a person can sign in through either kind of application, and every
refusal of a staff action must come from the product itself.

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
receipt's person-audience member products, and refuses a receipt that lists an entry
that is not a string. A product with its own audience, such as a scheduling product,
is written with that audience instead of `person`.

### The public origin

`publicOrigin` is written as a browser sends it in the `Origin` header: lower-case
scheme and host, no default port, no path, no trailing slash. Under
`development-loopback` it must be `http://127.0.0.1`, `http://[::1]` or
`http://localhost`, with any port.

### The generated gateway fragments and the host's chain

`registry-session gateway envoy` writes four fragments from the runtime file.
Splice them in as their header comments say, and check the result with
`registry-session --runtime-config <file> gateway envoy --verify-assembled <envoy.yaml>`.

- **Filter order.** The three filters (`registry-session.csrf`,
  `registry-session.check`, `registry-session.strip-cookies`) go at the head of the
  host's HTTP filter chain, ahead of the host's own filters and its router, in that
  order. Host filters then never see the session cookie on a host route, and on a
  signed-in route they see the check's `Authorization`, not the browser's.
- **Local reply.** The generated mapper must be the first mapper of the connection
  manager's `local_reply_config`. Envoy uses the first mapper that matches.
- **Routes.** The generated routes go first in the virtual host that serves the
  public authority, in the generated order. Routes delivered by RDS cannot be
  verified, so write the route configuration inline.
- **Authority and ports.** `gateway.authority` is lower case, as a browser sends it.
  When it carries a port, the connection manager must not strip ports before routing
  (`strip_any_host_port` and `strip_matching_host_port` are refused by the verifier),
  or no generated route would match.
- **Host filters.** `gateway.hostFilters` lists the host's own filters. It may not
  name the service's filters or the router. Every route under `/session/` (the five
  public paths and the catch-all 404) switches every host filter off, so a host
  authentication or authorization filter never refuses or alters sign-in, sign-out,
  who-am-I or the 404. A module route switches them off except those it keeps with
  `keepHostFilters`.
- **No environment.** The generator reads no environment variable: a `${NAME}`
  expression in the gateway members, a module id or prefix, or `publicOrigin` is
  refused, so `--check` gives the same answer everywhere.
- **Writes need an `Origin`.** A write to a module is refused (403 `session.refused`)
  unless it carries the page header, an `Origin` equal to the public origin, and, when
  sent, `Sec-Fetch-Site: same-origin`. A browser sends `Origin` on every write, so its
  absence means the gateway dropped it.
