# `@registrystack/client`

One versioned Node.js package for the Discovery, Evidence, Relay, and Base
Registry Engine client APIs in Registry Stack.

```sh
npm install "@registrystack/client@<version>"
```

```js
const { discovery, evidence, relay, breg } = require('@registrystack/client');

const registry = new breg.BaseRegistryClient({
  baseUrl: 'https://registry.example.invalid/',
});
```

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

Each product remains in its own namespace because its routing,
authentication, errors, and verification rules are different. The package
uses one platform-specific native dependency containing all four bindings.
Supported targets are macOS arm64, Linux arm64 with glibc, and Linux x64 with
glibc. Install the exact client version that matches the deployment.

The unified package is published beginning with Registry Stack v0.26.1.
Existing standalone client packages remain available for earlier versions,
but the release process does not publish new standalone versions once this
package is active.

For server-side BReg applications, `breg.BaseRegistryClient.registryContract()`
returns caller-filtered `operations` with typed field, request, and list-query
descriptors. Descriptions do not grant authority: select opaque create, patch,
and lifecycle authorities from that same contract before executing mutations.

Use BReg methods ending in `Json` when values must cross Node without numeric
coercion. They accept domain JSON text and return `valueJson` plus the usual
trace, ETag, location, and opaque continuation. `lifecycleActionsJson` accepts a
record envelope; opaque actions expose `bodyJson` and `reviewJson`. Decode these
strings with a lossless JSON library when displaying wide numbers. Decimal
fields remain fixed-scale strings, and null remains distinct from absence.
Duplicate members and silently rounded literals are refused. Existing BReg
integer restrictions still apply: `9007199254740992` is a supported write,
whereas `9007199254740993` is refused before I/O. Do not round refused values.
The client never retries a mutation automatically.
