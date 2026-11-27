# registry-session

A small session service beside a gateway. A person signs in once through the
service. It keeps their tokens on the server and gives the browser one opaque
cookie. The gateway asks the service, on every call to a signed-in route, which
bearer token to attach. The service checks. It never proxies.

This is not an identity provider or a token issuer. It uses the configured
identity provider's authorization-code and refresh-token flows. Sessions and
pending sign-ins live only in memory, in one replica. A restart loses them.
The binary is source-build only while `SESSION_FIRST_RELEASE` in
`release/scripts/release_roster.py` is unset.

## Configuration and commands

`registry-session --runtime-config /absolute/path/session-runtime.yaml`
starts two listeners. `listener.bind` serves the browser-facing
`/session/sign-in`, `/session/callback`, `/session/sign-out`,
`/session/signed-out` and `/session/me` routes behind the gateway.
`checkListener` serves the gateway's per-call check under `/check/`, plus
`/healthz` and `/readyz`. Keep that second listener private to the gateway.
The process stops both listeners on SIGINT or SIGTERM and lets requests in
flight finish.

The runtime file is a closed YAML document with
`apiVersion: id.registrystack.org/formats/platform/session-runtime/v1alpha1`
and `kind: PlatformSessionRuntimeConfig`. Its JSON Schema is
[`session-runtime.schema.json`](../../products/platform/generated/session-runtime/session-runtime.schema.json).
[Configure the session service](../../docs/site/src/content/docs/configure/session.mdx)
walks through a synthetic deployment, its identity applications and gateway.
Secrets are `secret:file/...` or `secret:env/...` references under declared
`secretProviders`, never inline values. Startup resolves them and opens the
audit destination before listening.

`registry-session --runtime-config /absolute/path/session-runtime.yaml check`
checks the same runtime model offline. It reads no secret, calls no provider,
opens no socket and writes no audit file. `--format json` writes a
`PlatformSessionCtlReport`. It exits 0 when accepted, 1 when refused (or on
a warning with `--deny-warnings`), 2 for usage errors and 3 for unreadable
input. Without `--environment`, environment expressions are checked only
for syntax and position. `--identity-receipt /absolute/path/identity-receipt.json`
also checks the person audience, member product ids and each sign-in's
derived audience set against the identity generator's receipt.

`registry-session --runtime-config /absolute/path/session-runtime.yaml gateway envoy --out /absolute/path/fragments`
writes the four Envoy fragments. `--check /absolute/path/fragments` compares
them byte for byte. `--verify-assembled /absolute/path/envoy.yaml` checks the
assembled static gateway configuration against the runtime file.
Regenerate, splice and verify after every runtime change.

The production session cookie is `__Host-registry-session`: an opaque
256-bit identifier with `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`,
without `Domain`. The temporary sign-in cookie is
`__Host-registry-signin`. Under `development-loopback` the names become
`registry-session` and `registry-signin`, without `Secure`.

## Answers a page can recognise

A module call without a live session gets 401 `session.expired`.
A refused route or origin gets 403 `session.refused`.
An unavailable check gets 503 `session.unavailable`, and so does a call to one
of the service's own `/session/` routes when the gateway cannot reach the
service.
A page request without the required kind of session redirects to sign-in.

Problem `type` URIs start with
`https://id.registrystack.org/problems/registry-platform/session/`.
The remaining problem suffixes are `return-refused` (400),
`rate-limited` (429), `busy` (503), `not-found` (404),
`method-not-allowed` (405) and `internal` (500).
Each problem carries its matching `session.*` code.
A page recognises a session problem by both its type URI and
`registry-session-answer: 1`. The gateway removes that marker from product
responses. The gateway's reserved `/session/` catch-all answers an unmarked
404.

The generated `registry-session.csrf` filter answers Envoy's plain 403, with no
marker and no problem body, to a write whose `Origin` is another site, the
issuer, or missing. A page in normal use never sends such a request: the
browser sends the page's own `Origin` on every write. So that refusal means a
forged or misrouted request, not a session a page should restore, and it stays
unmarked.

A module or page `prefix` that ends with `/` holds the paths below it. One
without a closing `/` holds its own path and the paths below it at a segment
boundary: `/functions/v1/renew` holds `/functions/v1/renew` and
`/functions/v1/renew/x`, not `/functions/v1/renewal`. The generated route
matches it with `path_separated_prefix`. `/a/b` and `/a/b/` count as the same
prefix, so one file may not hold both.

## Build and test

Run from the workspace root:

```sh
cargo build --locked -p registry-session
cargo test --locked -p registry-session --all-features
cargo clippy --locked -p registry-session --all-targets --all-features -- -D warnings
```

The tests exercise the public and check listeners over loopback HTTP with a
test issuer, token renewal and revocation, offline checks and deterministic
gateway generation and verification.

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
`session.renewBeforeSeconds` and half its issued lifetime left. The check
that starts a renewal waits for that attempt. Other checks keep serving with
an unexpired token:

- if another check is already renewing the session, the call is allowed with the
  unexpired token at once,
- after the issuer cannot be reached, renewal for that session backs off (5
  seconds, doubling to at most 60), and calls use the unexpired token meanwhile.
  An expired token during the backoff answers 503 `session.unavailable` without a
  call to the issuer,
- at most 32 renewals are in flight at the issuer across the whole service, and a
  call that finds none free uses its unexpired token.

`issuer.attemptTimeoutMilliseconds` (default 2000) must be below
`gateway.checkTimeoutMilliseconds` (default 3000), so the gateway does not give up
on a check that is still waiting for the issuer. A timeout after the issuer has
rotated a refresh token behaves like a lost response: the next renewal presents a
spent token, the issuer may revoke the token family, and the session ends. Do not
set the timeout below the issuer's real latency.

### Revocation happens off the request path

No request waits on the issuer to end a session or a sign-in. Whatever drops a
refresh token hands it to a bounded background queue (1024 entries) that revokes it
at the issuer:

- a sign-out removes the session and queues its revocations, writes the audit
  record, clears the cookie and redirects to the issuer's end-session endpoint.
  It never waits for a renewal in flight. A renewal that finishes
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
A token that is not a JWT with a readable `aud` is refused the same way, with a fixed-text
log line, so an issuer that returns opaque access tokens cannot be used with this service.

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

`--verify-assembled` is an allow-list. It passes only a file it reads exactly as
Envoy reads it and whose every path to a request for the public authority it can
see. Anything else is refused with a finding that names the member and says why;
it does not try to model the rest of Envoy.

- **Reading.** Anchors, aliases, merge keys and tags are refused (Envoy accepts
  them, so a shared connection manager written once with an anchor must be written
  out in full). Every field is written in snake_case: Envoy also reads a field by
  its lowerCamelCase name, and the check refuses any key with an upper-case letter
  outside metadata, a JSON body format, runtime values and the names under
  `typed_per_filter_config`. Booleans are `true` or `false`: a plain `y`, `n`,
  `yes`, `no`, `on` or `off` is a boolean to Envoy and is refused. Enum values are
  read in any case, as Envoy reads them.
- **Static only.** Listeners, routes, virtual hosts and filters are written inline.
  `dynamic_resources` with `lds_config` or `ads_config`, RDS, scoped routes, VHDS,
  `config_discovery`, the legacy `per_filter_config` and a `TypedStruct` are
  refused. Every listener's network filters are HTTP connection managers; any other
  network filter (a `tcp_proxy`, for one) is refused. A runtime layer that sets a key
  under `registry-session.`, or a disk or RTDS layer, is refused.
- **Every connection manager.** A connection manager is public when one of its
  virtual hosts has a wildcard domain or names the authority's host (in any case,
  with any port or a trailing dot). Every public manager gets the full check, HTTP/3
  listeners included. An internal manager must name exact internal domains, none of
  them the authority's host; it is not checked further.
- **Filter order.** The three filters (`registry-session.csrf`,
  `registry-session.check`, `registry-session.strip-cookies`) go at the head of the
  host's HTTP filter chain, ahead of the host's own filters, in that order, and
  appear once. The router ends the chain. An upgrade (`upgrade_configs`) may not
  bring its own filter list: upgrades use the main chain.
- **Local reply.** The two generated mappers must be the first mappers of the
  connection manager's `local_reply_config`, as generated and in order: a 503 from
  a failed check (`UAEX`), then a 503 with an upstream failure flag on a request
  path under `/session/`. Envoy uses the first mapper that matches. A host route's
  503 matches neither. A later mapper may not answer with a 3xx status or add the
  answer marker.
- **Routes.** The generated routes go first, as generated and in order, in a
  virtual host of their own whose only domain is the public authority. Envoy picks
  that virtual host for the authority in any case, so the routes do not match on
  `:authority` themselves. Host routes may follow them there, matched by `prefix`,
  `path` or `path_separated_prefix` only, and not under `/session/` or under a
  generated prefix (compared in any case, and at a segment boundary for a prefix
  without a closing `/`). No route outside the generated ones
  reaches a module or page cluster or the service's own clusters, picks its cluster
  from a header or plugin, mirrors requests, matches `:authority` with
  `invert_match`, or switches one of the service's filters, at the route, weighted
  cluster, virtual host or route configuration level. Every other route removes the
  answer marker and nothing adds it. Neither the generated virtual host nor the
  route configuration adds an `authorization` or `cookie` request header.
- **Authority and ports.** `gateway.authority` is lower case, as a browser sends it.
  When it carries a port, the connection manager must not strip ports before routing
  (`strip_any_host_port`, `strip_matching_host_port` and
  `ignore_port_in_host_matching` are refused), or the generated virtual host would
  not match. Set `strip_trailing_host_dot: true`, and `strip_matching_host_port: true`
  when the authority has no port, so the browser's forms of the authority all reach
  the generated virtual host.
- **Host filters (deny by default).** `gateway.hostFilters` lists every one of the
  host's own filters in the chain except the router; a filter in the chain it does
  not list is refused. It may not name the service's filters or the router. Every
  generated route switches every listed filter off, except a module or page route
  that keeps one with `keepHostFilters`. A kept filter runs after the check and sees
  the person's bearer token in `Authorization`, so keep only filters that neither
  rewrite the path nor clear the route cache, and never one that reads or changes
  `authorization` (the check refuses a kept filter that names it). No host filter
  may name the answer marker. A kept filter cannot answer a CORS preflight on a
  signed-in route: the check meets it first.
- **Redirects.** No route in the file redirects, and `require_tls` is `NONE`. A
  plain-HTTP listener that only redirects to https is refused too: serve that
  redirect outside this Envoy, or not at all.
- **No environment.** The generator reads no environment variable: a `${NAME}`
  expression in the gateway members, a module id or prefix, or `publicOrigin` is
  refused, so `--check` gives the same answer everywhere.
- **Writes need an `Origin`.** A write to a module is refused (403 `session.refused`)
  unless it carries the page header, an `Origin` equal to the public origin, and, when
  sent, `Sec-Fetch-Site: same-origin`. A browser sends `Origin` on every write, so its
  absence means the gateway dropped it.
