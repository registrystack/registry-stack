# Registry Relay client for Python

This package is the thin synchronous Python binding for
`registry-relay-client`. It performs one bounded SDK exchange per method and
does not implement HTTP routing, authentication, retries, pagination, or Relay
Problem Details itself.

```python
from registry_relay_client import RelayClient

client = RelayClient(base_url="https://relay.example")
result = client.service_metadata()
if result["kind"] == "complete":
    print(result["value"]["name"])
```

An optional static bearer is supplied as a string. Private-key JWT uses an
exactly-one-key wrapper:

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
and pass it as the static `authorization` string.

Every method is blocking and releases the Python GIL while the private
current-thread Tokio runtime waits for I/O. Conditional methods return a plain
mapping discriminated by `kind`: either `complete` with `value`, `trace_id`,
and optional `etag`, or `not_modified` with `trace_id` and `etag`. Page results
also carry a plain `continuation`, which only the matching continuation method
accepts. Raw OpenAPI, artifact, and SDMX bodies are returned as `bytes`.

Build and test from the workspace root:

```sh
cargo build --locked -p registry-relay-client-py --lib \
  --features registry-relay-client-py/extension-module
python3 -m unittest discover -s crates/registry-relay-client-py/tests/python -v
```
