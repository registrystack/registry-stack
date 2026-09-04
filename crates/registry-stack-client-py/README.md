# registry-stack-client

One versioned Python package for the Discovery, Evidence, Relay, and Base
Registry Engine client APIs in Registry Stack.

```sh
python -m pip install "registry-stack-client==<version>"
```

```python
from registry_client import breg, discovery, evidence, relay

registry = breg.BaseRegistryClient("https://registry.example.invalid/")
```

Each product remains in its own `registry_client.<product>` module namespace
because its routing, authentication, errors, and verification rules are
different. These namespaces also keep the unified distribution's files
disjoint from earlier standalone client distributions, so installing or
uninstalling either package cannot remove files owned by the other. The first
public unified package is planned for the Registry Stack release after v0.26.0.
Existing standalone client packages remain available for earlier versions, but
later releases use this unified entry point.

This directory holds the public metadata and Python facade. It is not built
directly. `release/scripts/assemble-registry-client-wheel.py` combines the four
version-matched internal native wheels with this facade and emits the only
publishable Python distribution.
