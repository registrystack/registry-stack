# Registry Platform Canonical JSON

`registry-platform-canonical-json` is the single Registry Stack implementation
of RFC 8785 JSON Canonicalization Scheme (JCS). It provides deterministic bytes
for hashes, signatures, JWK thumbprints, manifests, policies, and reviewed
configuration artifacts.

The crate applies ECMAScript finite IEEE 754 binary64 number serialization,
orders object names by UTF-16 code units, preserves array order and Unicode
code points, and emits no insignificant whitespace.

`parse_json_strict` is the shared raw JSON boundary for signed, hashed, or
structurally interpreted artifacts. It recursively rejects duplicate object
names and raw integer tokens that are not exactly representable as binary64
before returning a `serde_json::Value`; callers must bound the byte slice before
parsing. The integer check occurs before `serde_json` can round an out-of-range
plain integer token through `f64`. Fractional or exponent-form number tokens use
`serde_json`'s correctly rounded binary64 semantics, as RFC 8785 expects, and may
therefore canonicalize to a rounded floating-point value. `canonicalize_json`
applies the exactness rule to already constructed integer `Value`s so distinct
integer values cannot collapse to the same canonical bytes. Exact identifiers
outside that contract must be encoded as strings.

Canonicalization validates every number before emitting output and writes JSON
string escaping directly into the result buffer rather than allocating
per-string serialization copies. Callers that treat canonical bytes as
sensitive remain responsible for zeroizing the returned buffer after use.
