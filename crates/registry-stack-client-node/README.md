# @registrystack/client

One versioned Node.js package for the Discovery, Evidence, Base Registry
Engine, Casework, Messaging, Scheduling, and Coordinator client APIs in Registry Stack.

Coordinator joins the client roster at v0.44.0. Its imports below require a
Coordinator-enabled v0.44.0 candidate or published package; published v0.43.0
contains the earlier six products. Check the version-specific release assets
before installing. Source integration does not establish publication.

## Install

```sh
npm install "@registrystack/client@<version>"
```

Requires Node.js 24.11 or newer. Supported targets are macOS arm64, Linux
arm64 with glibc, and Linux x64 with glibc; installing the package pulls in
one platform-specific optional dependency containing all seven native
bindings.

## Usage

```js
const { discovery, evidence, breg, casework, messaging, scheduling, coordinator } = require('@registrystack/client');

const registry = new breg.BaseRegistryClient({
  baseUrl: 'https://registry.example.invalid/',
});
const work = new casework.CaseworkClient({
  baseUrl: 'https://casework.example.invalid/',
});
const messages = new messaging.MessagingClient({
  baseUrl: 'https://messaging.example.invalid/',
});
const appointments = new scheduling.SchedulingClient({
  baseUrl: 'https://scheduling.example.invalid/',
});
const workflows = new coordinator.CoordinatorClient({
  baseUrl: 'https://coordinator.example.invalid/',
});
```

## Products

- `discovery`: Registry Discovery, bounded search and resolution over a
  curated index.
- `evidence`: Evidence Gateway, request and verify signed minimum-disclosure
  assertions.
- `breg`: Base Registry Engine, records, contracts, writes, lifecycle, and typed
  applied-request result navigation.
- `casework`: Registry Casework, pinned review policies, producer requests and
  results, review task staffing, private decision drafts, receipts, and Directory.
- `messaging`: Registry Messaging, submit, inspect, cancel, and preview
  institution-owned messages.
- `scheduling`: Registry Scheduling, published offerings, availability,
  holds, and appointments over operator-anchored supply.

- `coordinator`: Registry Coordinator, workflow contracts, admission, run status,
  inspection, and operator recovery. It is optional for direct product composition.

Each product remains in its own namespace because its routing,
authentication, errors, and verification rules are different.

## Compatibility metadata

The package includes the tested server baseline and compatible patch line for
the Discovery namespace. Read the version-matched record through the exported
JSON path:

```js
const compatibility = require('@registrystack/client/compatibility.json');
```

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
trace, ETag, location, and opaque continuation. See
[Exact JSON in Node](https://docs.registrystack.org/reference/client-api/#exact-json-in-node)
for the full rules.

A keyed BReg, Casework, Messaging, or Scheduling mutation whose outcome is
unknown is resent identically under the same idempotency key up to
`maximumMutationRetries` times, a client option: 0 to 2, default 2, and 0 sends it
once. Casework review-request create and cancel are excluded from this retry.
Reads, unkeyed calls, and every 4xx refusal are never resent. When the returned error
still reports `outcomeUnknown`, the mutation may have taken effect: recover by
sending it again under the same key, because a new key could apply it twice.
`outcomeUnknown` is false for `410 idempotency.expired`, but there an earlier
attempt under the key was answered and may have committed: reconcile that
attempt before choosing a new key.
See [Unknown outcomes](https://docs.registrystack.org/reference/client-api/#unknown-outcomes-and-the-same-key-retry).

`breg.verifyHookDelivery({ method, path, headers, body, key })` authenticates
the exact bytes of one Version 1 hook delivery. The result returns
`deliveryTime` and `idempotencyKey`; the receiver must bound clock skew and
deduplicate once-only effects on authenticated `source` plus `id`, or on an
application business key. See
[Verify a hook delivery](https://docs.registrystack.org/reference/client-api/#verify-a-hook-delivery)
for a receiver example.

## Versioning

Install the exact client version that matches the deployment. The unified
package is published beginning with Registry Stack v0.26.1. Existing
standalone client packages remain available for earlier versions, but the
release process does not publish new standalone versions once this package
is active.

The `casework` namespace is part of the unified package beginning with
Registry Stack v0.30.0.

The `messaging` namespace is part of the unified package beginning with
Registry Stack v0.38.0.

The `scheduling` namespace is part of the unified package beginning with
Registry Stack v0.40.0.

## Casework notes

The Casework module is for a trusted server host. Producer, reviewer, and
Directory calls take that request's bearer token and selected Casework profile. Current-source context
operations also take the selected source profile; submitted-context reviews
need no provider. Credentials remain the host's responsibility.

`reviewPolicy` discovers a compiled closure; admission requires its exact
`identity` binding, or the binding generated from the reviewed project.
`casework.submissionDigest(producerId, sourceNamespace, request)` computes the
canonical expected submission digest locally. Submit with
`createOrRecoverReviewRequest`, retaining the request and caller-chosen key.
After a lost response, repeat that same operation with the same binding, body,
key, and digest. Producer create/cancel calls are never automatically resent.
Read the accepted request's result with `reviewResult` or resume `reviewResults`.
A result records a review outcome and grants no external apply or write authority.

Reviewers use `reviewTasks`, `nextReviewTask`, and `reviewTaskHoldings`. Claim,
release, and decision calls take the task UUID, displayed numeric revision,
and caller-chosen idempotency key. Recover a lost decision response with
`reviewTask`; `decisionReceipt` is disclosed only to its deciding caller.
`ownReviewDecisions` discovers that caller's retained receipts after a fresh
sign-in. `supervisoryReviewTasks` returns bounded task and accountability
references for currently served queues, with a holder-free state.

A changed policy binding requires explicit review before a new submission.
Keep staffing filters and profiles unchanged across snapshot cursors; restart
without the cursor after `410 review.result-expired`.

## Documentation

- [Client API reference](https://docs.registrystack.org/reference/client-api/)
- [Repository](https://github.com/registrystack/registry-stack)
- [Issue tracker](https://github.com/registrystack/registry-stack/issues)

## License

Apache-2.0

Coordinator joins the seven-product roster at v0.44.0. The source facade also
contains held `render` and `@registrystack/client/render` namespaces. Default
assembly omits Render; `--include-render` adds it to an explicit local candidate
and does not authorize publication. Render takes a token or a resource-bound provider with
`bearerToken()` and performs one bounded render exchange. A correlation key is
not a durable idempotency promise. `outcomeUnknown` and `transportKind` preserve
whether an exchange may have completed; provider errors keep their own class.
Coordinator is optional.
