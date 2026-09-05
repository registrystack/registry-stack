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
