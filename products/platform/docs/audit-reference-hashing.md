# Audit Reference Hashing

`registry-platform-audit` owns the generic audit reference hashing primitive used
by registry services to record stable, privacy-preserving handles in audit
events.

The platform primitive deliberately does not define service domain semantics.
Consumers must choose the reference class, scope, and canonical input for their
own product surface.

## Contract

Use `AuditKeyHasher::audit_reference_hash(class, scope, canonical_input)` when a
service needs a deterministic audit handle for a sensitive value.

- `class` is required and versioned by the consuming service, for example
  `matched-reference-v1`, `table-id-v1`, or `primary-key-v1`.
- `scope` may be empty, but should carry the narrowest stable privacy boundary
  available, such as purpose, dataset/entity, tenant, or route family.
- `canonical_input` is required and must be stable, explicit, and reviewed by
  the consuming service. Platform treats it as opaque bytes.
- Output uses the same encoding as other audit hashes:
  `hmac-sha256:<digest>` in keyed production mode and `sha256:<digest>` in
  explicit development mode.

The primitive domain-separates audit reference hashes from raw
`AuditKeyHasher::hash` output and from audit-chain record hashes. Changing class,
scope, or canonical input changes the output.

The framed input to the platform hasher is:

```text
registry-platform:audit-reference:v1 || "\0" || len(class) || "\0" || class || "\0" || len(scope) || "\0" || scope || "\0" || len(canonical_input) || "\0" || canonical_input
```

`class` and `canonical_input` must be non-empty. `scope` may be empty, but the
empty value is still length-framed.

## Service Responsibilities

Services remain responsible for:

- deciding which raw values may be represented by durable audit handles;
- canonicalizing identifiers, attributes, and records before hashing;
- documenting retention, rotation, and erasure expectations;
- avoiding long-lived pseudonyms for failed matching attempts unless product
  policy explicitly requires repeat-probe correlation;
- testing that audit records do not contain raw sensitive strings.

`registry-platform-testing::assert_json_absent_strings` is available for focused
non-leak assertions in downstream service tests.

For generic audit redaction of lookup values, use
`AuditKeyHasher::sensitive_value_hash(field, value)`. It is field-bound and uses
the same audit reference framing, but it does not replace product-specific
pseudonym classes.
