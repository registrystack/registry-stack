# @registrystack/client

One versioned Node.js package for the Discovery, Evidence, Relay, and Base
Registry Engine client APIs in Registry Stack.

## Install

```sh
npm install "@registrystack/client@<version>"
```

Requires Node.js 22.12 or newer. Supported targets are macOS arm64, Linux
arm64 with glibc, and Linux x64 with glibc; installing the package pulls in
one platform-specific optional dependency containing all four native
bindings.

## Usage

```js
const { discovery, evidence, relay, breg } = require('@registrystack/client');

const registry = new breg.BaseRegistryClient({
  baseUrl: 'https://registry.example.invalid/',
});
```

## Products

- `discovery`: Registry Discovery, bounded search and resolution over a
  curated index.
- `evidence`: Evidence Gateway, request and verify signed minimum-disclosure
  assertions.
- `relay`: Registry Relay, scoped read-only APIs over existing sources.
- `breg`: Base Registry Engine, records, contracts, writes, and lifecycle.

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
`operations` with typed field, request, and list-query descriptors; those
descriptions grant no authority, so select the opaque create, patch, and
lifecycle authorities from that same contract before executing a mutation.
Methods ending in `Json` keep values exact across the Node number boundary:
they accept domain JSON text and return `valueJson` alongside the usual
trace, ETag, location, and opaque continuation. The client never retries a
mutation automatically. See
[Exact JSON in Node](https://docs.registrystack.org/reference/client-api/#exact-json-in-node)
for the full rules.

## Versioning

Install the exact client version that matches the deployment. The unified
package is published beginning with Registry Stack v0.26.1. Existing
standalone client packages remain available for earlier versions, but the
release process does not publish new standalone versions once this package
is active.

## Documentation

- [Client API reference](https://docs.registrystack.org/reference/client-api/)
- [Repository](https://github.com/registrystack/registry-stack)
- [Issue tracker](https://github.com/registrystack/registry-stack/issues)

## License

Apache-2.0
