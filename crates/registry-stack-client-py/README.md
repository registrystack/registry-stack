# registry-stack-client

One versioned Python package for the Discovery, Evidence, Relay, and Base
Registry Engine client APIs in Registry Stack.

The distribution installs as `registry-stack-client` and imports as
`registry_client`. The two spellings differ, so `import registry_stack_client`
raises `ModuleNotFoundError`.

```sh
python -m pip install "registry-stack-client==<version>"
```

```python
from registry_client import breg, discovery, evidence, relay

registry = breg.BaseRegistryClient("https://registry.example.invalid/")
```

Each product remains in its own module namespace, `registry_client.breg`,
`registry_client.discovery`, `registry_client.evidence`, and
`registry_client.relay`, because its routing, authentication, errors, and
verification rules are different. These namespaces also keep the unified
distribution's files disjoint from earlier standalone client distributions, so
installing or uninstalling either package cannot remove files owned by the
other. The unified package is published beginning with Registry Stack v0.26.1.
Existing standalone client packages remain available for earlier versions, but
later releases use this unified entry point.

Wheels cover macOS arm64, Linux arm64 with glibc, and Linux x64 with glibc,
and require glibc 2.17 or newer on Linux. Install the exact client version that
matches the deployment.

The `crates/registry-stack-client-py` directory in the Registry Stack
repository holds this public metadata and the Python facade. It is not built
directly. `release/scripts/assemble-registry-client-wheel.py` combines the four
version-matched internal native wheels with the facade and emits the only
publishable Python distribution, using this file as the PyPI description.
