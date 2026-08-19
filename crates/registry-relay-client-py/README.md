# Registry Relay client for Python

This package is the thin synchronous Python binding for
`registry-relay-client`. It performs one bounded Relay SDK exchange per method;
a configured private-key-JWT provider may perform a separate token acquisition
or refresh exchange. The binding does not implement HTTP routing,
authentication, retries, pagination, or Relay Problem Details itself.

Starting with Registry Stack v0.23.0, install the exact client version that
matches the Relay deployment:

```sh
python -m pip install "registry-relay-client==<version>"
```

PyPI carries manylinux wheels requiring glibc 2.17 or newer for Linux amd64 and
Linux arm64, plus a macOS arm64 wheel. Registry Stack v0.20.0 and v0.20.1
remain available only as wheels attached to their GitHub Releases.

```python
from registry_relay_client import RelayClient

client = RelayClient(base_url="https://relay.example")
result = client.service_metadata()
if result["kind"] == "complete":
    print(result["value"]["name"])
```

Authentication uses an exactly-one-key wrapper. Supply a static bearer as:

```python
client = RelayClient(
    base_url="https://relay.example/prefix",
    authorization={"static": short_lived_token},
)
```

Private-key JWT uses the alternative wrapper member:

```python
client = RelayClient(
    base_url="https://relay.example/prefix",
    authorization={
        "private_key_jwt": {
            "token_endpoint": "https://issuer.example/oauth/token",
            "client_id": "relying-party",
            "client_key": private_jwk,
        }
    },
)
```

Top-level `trusted_root_certificates` configures the Relay deployment
connection. A token endpoint using a private CA needs its own byte-valued
`trusted_root_certificates` inside `private_key_jwt`; the two trust inputs are
deliberately independent.

The built-in private-key-JWT flow sends only `grant_type`,
`client_assertion_type`, and `client_assertion`. It does not send `scope`,
`resource`, a body `client_id`, or deployment-defined form members. When an
issuer requires any of those fields, acquire a short-lived bearer separately
and pass it through `authorization={"static": token}`.

Every method is blocking and releases the Python GIL while the private
current-thread Tokio runtime waits for I/O. Conditional methods return a plain
mapping discriminated by `kind`: either `complete` with `value`, `trace_id`,
and optional `etag`, or `not_modified` with `trace_id` and `etag`. Page results
also carry a plain `continuation`, which only the matching continuation method
accepts. Raw OpenAPI, artifact, and SDMX bodies are returned as `bytes`.
The PEP 561 stub types fixed service, capability, resource, Record envelope,
page, and outcome structures while keeping deployment-defined `domainData`
as JSON values.

List and search requests follow their distinct Relay contracts. A list accepts
optional equality `filters` and never accepts `bbox`. A named search requires a
four-number `bbox` ordered as west, south, east, north. The bbox must be a
concrete Python `list` or a four-item `tuple`; other sequence implementations
are rejected. Search never accepts `filters`:

```python
listed = client.list_records("people", filters={"status": "active"})
nearby = client.search("people", "nearby", bbox=[100.0, 13.0, 101.0, 14.0])
```

The client validates these shapes before performing a Relay exchange.

Build and test from the workspace root:

```sh
cargo build --locked -p registry-relay-client-py --lib \
  --features registry-relay-client-py/extension-module
python3 -m unittest discover -s crates/registry-relay-client-py/tests/python -v
```
