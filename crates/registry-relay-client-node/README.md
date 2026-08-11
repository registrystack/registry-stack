# registry-relay-client-node

Thin napi-rs binding for the Rust `registry-relay-client` SDK. It exposes no
JavaScript HTTP, routing, authentication, retry, or problem parsing logic.
All Relay wire handling remains in the wrapped Rust client.

```js
const { RelayClient } = require('@registrystack/relay-client');
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

Resource discovery similarly returns a closed `{ cursor }` continuation object
for `continueResources`; raw cursor strings are not accepted.

Before native conversion, every call clones its inputs from an acyclic plain
JSON graph. Objects must have `Object.prototype` or a null prototype and must
contain only own enumerable string data properties; proxies, accessors, symbol
members, exotic prototypes, sparse arrays, and non-JSON values are rejected.
One aggregate budget per call permits at most 128 levels, 100,000 values, and
4 MiB of UTF-8 string data. These checks prevent recursive native conversion
of cyclic or active JavaScript objects.

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
