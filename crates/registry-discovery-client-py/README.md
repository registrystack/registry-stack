# registry-discovery-client-py

Synchronous PyO3 binding for the bounded Rust `registry-discovery-client` SDK.
It performs exact service search, Evidence Type resolution, and ambiguity-safe
selection. A returned selection is inert public metadata. Apply local trust
policy before calling its Evidence or Relay endpoint.

Starting with Registry Stack v0.22.0, install the exact client version that
matches the Discovery deployment:

```sh
python -m pip install "registry-discovery-client==<version>"
```

PyPI carries manylinux wheels requiring glibc 2.17 or newer for Linux amd64
and Linux arm64, plus a macOS arm64 wheel.

The public methods accept only ordinary built-in JSON values: `None`, `bool`,
signed 64-bit `int`, finite `float`, `str`, `list`, and `dict` with string keys.
They reject custom objects, subclasses, tuples, cycles, and oversized values
before sending a request. Invalid configuration always raises
`DiscoveryClientError(kind="configuration")`; invalid request or selection
values raise `DiscoveryClientError(kind="query")`. Error messages never echo
caller values.

```python
from registry_discovery_client import DiscoveryClient

client = DiscoveryClient("https://discovery.example.invalid/")
services = client.search_services({
    "serviceKind": ["evidence"],
    "evidenceType": ["urn:example:evidence-type"],
})
selection = client.select_exact(services, {
    "recordId": services["items"][0]["recordId"],
    "matchedCapability": {
        "kind": "evidence-type",
        "id": "urn:example:evidence-type",
    },
})
```
