# Registry Casework client

`registry-casework-client` is the canonical bounded Rust client for Registry
Casework. It exposes Casework's source-neutral work-item and directory HTTP
contract. It does not contain Base Registry Engine routes or protocol types.

The client takes a bearer token and explicit Casework profile for each call.
Source-reading calls also take an explicit source profile. It never retains a
human token, follows redirects, or automatically retries a mutation. Direct
mutations carry the item or directory revision the caller displayed and a
caller-supplied idempotency key. Response-loss recovery reuses the original
key and the server's stored prepared attempt.
