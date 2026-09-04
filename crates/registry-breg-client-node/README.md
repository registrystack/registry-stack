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
