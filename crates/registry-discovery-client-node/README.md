# registry-discovery-client-node

Thin napi-rs binding for the bounded Rust `registry-discovery-client` SDK.
It performs exact service search, Evidence Type resolution, and ambiguity-safe
selection. A returned selection is inert public metadata. The application must
apply its own trust policy before calling the selected Evidence or Relay
endpoint.

Starting with Registry Stack v0.22.0, install the exact client version that
matches the Discovery deployment:

```sh
npm install "@registrystack/discovery-client@<version>"
```

The root package selects the native package for Linux amd64 with glibc, Linux
arm64 with glibc, or macOS arm64. Linux packages require glibc rather than
musl, so Alpine Linux is not supported.

Published npm installations select a separately published native package for
macOS arm64, Linux arm64 glibc, or Linux x64 glibc. The root package contains
the JavaScript API only, so normal installs do not download an unused native
binary.

```js
const { DiscoveryClient } = require('@registrystack/discovery-client');

const client = new DiscoveryClient('https://discovery.example.invalid/');
const services = await client.searchServices({
  serviceKind: ['evidence'],
  evidenceType: ['urn:example:evidence-type'],
});
const selection = client.selectExact(services, {
  recordId: services.items[0].recordId,
  matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type' },
});
```

Persist the plain `selection` object if it is useful, but never treat its
catalog origin, endpoint, issuer, or capability claims as trusted solely
because Discovery returned them.
