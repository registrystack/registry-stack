# registry-breg-client-node

Internal napi-rs binding for the Rust `registry-breg-client` SDK. It is built
into the public `@registrystack/client` package and is not published as a
standalone npm package.

```js
const { breg: { BaseRegistryClient } } = require('@registrystack/client');
const client = new BaseRegistryClient({ baseUrl: 'https://registry.example.invalid/' });
const health = await client.health();
```

Writes never accept caller-supplied operation routes as authority. Fetch a
caller-filtered registry contract, select the expected operation and profile,
then pass the returned opaque binding to `createRecord` or `patchRecord`.
Lifecycle actions similarly require a metadata-selected authority and an
action promoted from one Registry Record.

Every call accepts only a bounded, acyclic graph of plain JSON inputs. Proxies,
accessors, symbols, exotic objects, sparse arrays, non-finite numbers, more
than 128 levels or 100,000 nodes, and more than 4 MiB of string data are
rejected before native conversion.

Authentication is optional. Configure either one static bearer token or the
private-key-JWT provider declared in `client.d.ts`. The client performs one
exchange per method, never follows redirects, never uses ambient proxy
configuration, never retries, and never follows links automatically.

Failures are `BaseRegistryClientError` values with a stable `kind` and, where
available, `code`, `planRefusal`, `status`, `traceId`, `transportKind`, and
`tokenKind`. Errors do not expose token, private-key, record, or lifecycle
payload values.

## Exact values and application metadata

Use the public server-side package `@registrystack/client` and its `breg`
namespace. `registryContract(profile).operations` exposes typed, caller-filtered
field, request, and query descriptors. Labels are inert presentation text;
`schemaJson` preserves JSON Schema numbers. Descriptors grant no authority.
Continue to use `selectCreate`, `selectPatch`, and `selectLifecycle` to obtain
opaque authorities bound to the client source and selected profile.

Methods ending in `Json` keep domain values on the Rust side of the JavaScript
number boundary. `getRecordJson`, `listRecordsJson`, `continueListJson`,
`lookupRecordJson`, `createRecordJson`, `patchRecordJson`, and
`executeLifecycleActionJson` return `valueJson` with the same trace, ETag,
location, and opaque continuation semantics as their object counterparts.
`lifecycleActionsJson` accepts a complete record envelope as JSON text; its
opaque actions expose `bodyJson` and `reviewJson` for exact display.

```js
const { breg } = require('@registrystack/client');
const client = new breg.BaseRegistryClient({ baseUrl, authorization: { static: token } });
const contract = await client.registryContract(profile);
const operation = contract.operations.find(value => value.kind === 'create');
const binding = contract.selectCreate(operation.id, profile);
const result = await client.createRecordJson(binding,
  '{"quantity":9007199254740992,"amount":"12.3400","date":"2026-09-08"}',
  'caller-chosen-idempotency-key');
// Keep result.valueJson intact, or inspect it with a lossless JSON library.
```

Inputs are the same domain data object or field-based patch array accepted by
the corresponding object method, encoded as JSON text. They are not arbitrary
HTTP request bodies. The client refuses duplicates, invalid JSON, bounds
violations, and numeric literals whose value would change during decoding.
Mutation builders also enforce BReg's existing numeric model: for example,
`9007199254740992` is supported while `9007199254740993` is refused before
network I/O. Exponent or decimal spellings cannot bypass the exact-value check.
Fixed-scale decimals remain JSON strings. Null and absent members remain distinct.
Do not round unsupported input to make it pass. JSON whitespace and equivalent
number spellings may be canonicalized; the promise concerns values and types.

Actions retain their original opaque authority and exact retry semantics.
A lost response is still uncertain, and the caller must explicitly choose
whether to retry the same action with the same idempotency key. The client
performs no automatic mutation retry or durable session recovery.
