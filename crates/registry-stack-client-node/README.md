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

Each product remains in its own namespace because its routing,
authentication, errors, and verification rules are different. The package
uses one platform-specific native dependency containing all four bindings.
Supported targets are macOS arm64, Linux arm64 with glibc, and Linux x64 with
glibc. Install the exact client version that matches the deployment.

The unified package is published beginning with Registry Stack v0.26.1.
Existing standalone client packages remain available for earlier versions,
but the release process does not publish new standalone versions once this
package is active.
