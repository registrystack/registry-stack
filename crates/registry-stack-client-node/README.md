# @registrystack/client

One versioned Node.js package for the Discovery, Evidence, Relay, Base Registry
Engine, Casework, and Messaging client APIs in Registry Stack.

## Install

```sh
npm install "@registrystack/client@<version>"
```

Requires Node.js 22.12 or newer. Supported targets are macOS arm64, Linux
arm64 with glibc, and Linux x64 with glibc; installing the package pulls in
one platform-specific optional dependency containing all six native
bindings.

## Usage

```js
const { discovery, evidence, relay, breg, casework, messaging } = require('@registrystack/client');

const registry = new breg.BaseRegistryClient({
  baseUrl: 'https://registry.example.invalid/',
});
const work = new casework.CaseworkClient({
  baseUrl: 'https://casework.example.invalid/',
});
const sender = new messaging.MessagingClient({
  baseUrl: 'https://messaging.example.invalid/',
});
```

## Products

- `discovery`: Registry Discovery, bounded search and resolution over a
  curated index.
- `evidence`: Evidence Gateway, request and verify signed minimum-disclosure
  assertions.
- `relay`: Registry Relay, scoped read-only APIs over existing sources.
- `breg`: Base Registry Engine, records, contracts, writes, lifecycle, and typed
  applied-request result navigation.
- `casework`: Registry Casework, staff inbox, claims, drafts, decisions,
  recovery, history, holdings, and directory bootstrap.
- `messaging`: Registry Messaging, submit one message under a caller-chosen
  idempotency key, read what is known about its delivery, cancel it before
  dispatch, and preview a template version without sending.

Each product remains in its own namespace because its routing,
authentication, errors, and verification rules are different.

## TypeScript

A TypeScript consumer also needs the Node type definitions, and must name
them. The published declarations use `Buffer`, a Node.js global, and
TypeScript 6 does not load installed `@types` packages on its own, so a
project compiling against the declarations reports `TS2591` on every use of
`Buffer` until it has both installed the package and listed it in
`compilerOptions.types`:

```sh
npm install --save-dev "@types/node"
```

```json
{
  "compilerOptions": {
    "types": ["node"]
  }
}
```

The package does not declare that dependency itself, because a JavaScript
consumer does not need it.

## Base Registry Engine notes

`breg.BaseRegistryClient.registryContract()` returns caller-filtered
`operations` with typed field, readable request field, request, and list-query
descriptors; those
descriptions grant no authority, so select the opaque create, patch, and
lifecycle authorities from that same contract before executing a mutation.
Methods ending in `Json` keep values exact across the Node number boundary:
they accept domain JSON text and return `valueJson` alongside the usual
trace, ETag, location, and opaque continuation. The client never retries a
mutation automatically. See
[Exact JSON in Node](https://docs.registrystack.org/reference/client-api/#exact-json-in-node)
for the full rules.

`breg.verifyWebhookDelivery({ method, path, headers, body, key })` authenticates
the exact bytes of one Version 1 webhook delivery. The result returns
`deliveryTime` and `idempotencyKey`; the receiver must bound clock skew and
deduplicate once-only effects on authenticated `source` plus `id`, or on an
application business key. See
[Verify a webhook delivery](https://docs.registrystack.org/reference/client-api/#verify-a-webhook-delivery)
for a receiver example.

## Versioning

Install the exact client version that matches the deployment. The unified
package is published beginning with Registry Stack v0.26.1. Existing
standalone client packages remain available for earlier versions, but the
release process does not publish new standalone versions once this package
is active.

The `casework` namespace is part of the unified package beginning with
Registry Stack v0.30.0, and the `messaging` namespace beginning with Registry
Stack v0.35.0.

## Casework notes

The Casework module is for a trusted server host. Each call takes that request's
bearer token and selected Casework profile; source-reading calls also take the
selected source profile. The client does not retain them. Browsers should send
only the host's session cookie. Claim, release, and decide consume the
caller-filtered action returned on the item, including its exact route and
`ifMatch` revision. Mutations require a caller-controlled idempotency key and
are never retried automatically. After a lost response, use
`recoverDecisionByKey` with the original key so recovery does not depend on the
attempt identifier being received.

## Messaging notes

The Messaging module is for a trusted server host. Each call takes that
request's bearer token; the client does not retain it. `submit` requires a
caller-chosen idempotency key: a retry after a lost response sends the same key
and request, and the runtime answers the stored receipt again instead of
accepting a second message. The client never retries a submission
automatically. `message` reads the delivery state the runtime knows, including
its attempt history; it does not return the rendered content. `cancel`
withdraws a message that has not been dispatched and answers its view; a
cancellation that lost the race to dispatch or to a final state answers
`message.dispatch-started` or `message.terminal` and is never retried.
`preview` renders one template version for a locale and data and sends
nothing. A submission over its access profile's request rate or daily limit
fails with `rate-limit.exceeded` or `quota.exceeded` and status 429;
`retryAfterSeconds` carries the wait the runtime asked for, at most one day,
and the client never waits or retries on its own.

## Documentation

- [Client API reference](https://docs.registrystack.org/reference/client-api/)
- [Repository](https://github.com/registrystack/registry-stack)
- [Issue tracker](https://github.com/registrystack/registry-stack/issues)

## License

Apache-2.0
