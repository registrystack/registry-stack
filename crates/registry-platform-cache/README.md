# registry-platform-cache

Small cache-store primitives for registry services.

## What It Provides

- `CacheStore`, an async trait for `get`, `set`, `set_if_absent`,
  `compare_and_set`, `delete`, and readiness checks.
- `CacheKey`, a redacted-debug key wrapper with helpers for hashed keys derived
  from sensitive scope material.
- `InMemoryCacheStore` for tests and explicit local single-process mode.

## Security Notes

Prefer `CacheKey::from_hashed_parts` when a key is derived from subject ids,
issuer ids, nonces, JWT ids, or tenant identifiers. `Debug` output redacts cache
key values, but backend keys are still visible to operators of the backing store.

This crate is mechanism only. Security contracts such as replay rejection should
live in narrower crates, for example `registry-platform-replay`, so callers do
not accidentally use plain `set` where `set_if_absent` is required.

## Testing

```sh
cargo test -p registry-platform-cache
```

## License

Apache-2.0.
