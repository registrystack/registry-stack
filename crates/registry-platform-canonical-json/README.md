# Registry Platform Canonical JSON

`registry-platform-canonical-json` is the single Registry Stack implementation
of RFC 8785 JSON Canonicalization Scheme (JCS). It provides deterministic bytes
for hashes, signatures, JWK thumbprints, manifests, policies, and reviewed
configuration artifacts.

The crate applies ECMAScript finite IEEE 754 binary64 number serialization,
orders object names by UTF-16 code units, preserves array order and Unicode
code points, and emits no insignificant whitespace.

Callers must validate raw input as I-JSON before parsing it into
`serde_json::Value`. In particular, duplicate object names must be rejected at
the raw JSON boundary because a parsed value cannot recover names discarded by
a parser. Integer `Value`s that are not exactly representable as binary64 are
rejected so distinct inputs cannot collapse to the same canonical bytes. Such
integers must be encoded as strings.
