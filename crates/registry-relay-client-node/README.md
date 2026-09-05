# registry-relay-client-node

Thin napi-rs binding for the Rust `registry-relay-client` SDK. It exposes no
JavaScript HTTP, routing, authentication, retry, or problem parsing logic.
All Relay wire handling remains in the wrapped Rust client.

This crate publishes through the unified `@registrystack/client` package.
Install the exact client version that matches the Relay deployment, and use its
`relay` namespace:

```sh
npm install "@registrystack/client@<version>"
```

The root package selects one exact native package for Linux amd64 with glibc,
Linux arm64 with glibc, or macOS arm64. Linux addons target glibc 2.17; the
installed Node.js runtime may impose a newer system requirement. The Linux
packages do not support musl-based distributions such as Alpine.

Registry Stack v0.22.0 through v0.26.0 published this binding on its own, as
`@registrystack/relay-client`. Those versions stay published and unchanged, and
no later version joins them: from v0.26.1 the maintained Node.js client is
`@registrystack/client`.

```js
const { relay: { RelayClient } } = require('@registrystack/client');
const client = new RelayClient({ baseUrl: 'https://relay.example.invalid/' });
const health = await client.health();
```

Pass request choices as plain objects. Paginated collection responses return a
validated continuation object that can be handed only to the matching method:

```js
const first = await client.listRecords('people', {
  pageSize: 25,
  fields: ['name'],
  format: 'json',
});
const second = first.kind === 'complete' && first.continuation
  ? await client.continueListRecords(first.continuation)
  : null;
```

List options may contain declared equality `filters` but never `bbox`. Named
searches instead require a `[west, south, east, north]` WGS84 `bbox` and do not
accept equality filters:

```js
const premises = await client.search('premises', 'within-bbox', {
  bbox: [100.45, 13.65, 100.65, 13.85],
  pageSize: 25,
});
```

Resource discovery similarly returns a closed `{ cursor }` continuation object
for `continueResources`; raw cursor strings are not accepted.

Before native conversion, every call clones its inputs from an acyclic plain
JSON graph. Objects must have `Object.prototype` or a null prototype and must
contain only own enumerable string data properties; proxies, accessors, symbol
members, exotic prototypes, sparse arrays, and non-JSON values are rejected.
One aggregate budget per call permits at most 128 levels, 100,000 values, and
4 MiB of UTF-8 string data. These checks prevent recursive native conversion
of cyclic or active JavaScript objects.

Integer-valued configuration and request options must satisfy
`Number.isSafeInteger` and the bound of their target option. Safe integers are
preserved exactly across native conversion.

Raw OpenAPI, artifact, and SDMX responses carry `body` as a Node `Buffer` and
`mediaType` as the accepted server media type.

Authentication is optional. Configure either one static bearer token or one
private-key-JWT provider. The latter accepts `tokenEndpoint`, `clientId`, and a
private `clientKey` JWK, plus the timeout, audience, refresh, user-agent, and
CA-pinning settings declared in `client.d.ts`. Its token request contains only
`grant_type`, `client_assertion_type`, and `client_assertion`. It deliberately
has no scope, RFC 8707 resource, or body `client_id` option. If an issuer needs
one of those fields, obtain a short-lived bearer token separately and pass it
as `{ authorization: { static: token } }`; Rust callers can instead implement a
custom `TokenProvider`.

Every mapped failure is thrown as `RelayClientError` with a stable `kind` and,
when the Rust error provides them, `code`, `status`, `traceId`,
`retryAfterSeconds`, `transportKind`, and `tokenKind`. No error exposes token
or private-key material.
