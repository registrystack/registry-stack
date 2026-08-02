# DHIS2 adult-status deployment project

This is a complete, simple target bundle for a deployment that derives one
adult-status boolean from DHIS2 Tracker.

The reviewed governance bundle is under `bundle/`. Process-local paths,
listener settings, and the private-CA file binding are in `runtime.yaml`.
Deployments review and mount both files read-only, but staging and production
may use different runtime files without changing evidence semantics.

Before deployment, the operator changes only:

- `.example` OIDC and DHIS2 hosts;
- the DHIS2 program, organisation unit, and date-of-birth attribute UIDs;
- issuer, provider, trust-domain, framework, evidence-type, and concept URIs;
- authority tags and purposes;
- the referenced secret files; and
- the runtime paths, listener binding, and private-CA bundle file.

The source performs one page-one lookup for exactly one tracked-entity
reference with `pageSize=2`. A second page is never followed. That two-result
ceiling is governed adapter policy declared by this reviewed bundle and
rendered by its preparation script so one bounded response separates a unique
match from ambiguity. It is not a Rust domain rule and not a DHIS2 property.
Because the Tracker response can contain attributes beyond the one consumed by
the adapter, the source honestly declares `record-transformed` posture.
Extraction carries the returned `trackedEntity` only as a transient fact, and
the derivation requires its exact equality with the authorized subject
selector before evaluating the date of birth. A returned-record mismatch fails
closed as the internal `derivation_input_error` category and collapses publicly
into the same `evidence_not_available` problem as an unresolved lookup, so the
caller cannot learn that a record was found. It is never signed as either adult
or not adult. The raw tracked entity reference is never included in evidence.
`pageSize`, `page`, and `totalPages` are strings because they become lexical URL
query values. In contrast, the OpenCRVS project's JSON body keeps numeric and
boolean constants typed.

Required secret files beneath `/run/secrets/registry-evidence`, each owned by
the service identity with mode `0600`, are:

```text
signing-ed25519-private-jwk
audit-hmac-key
subject-binding-hmac-key
dhis2-username
dhis2-password
```

The audit and subject-binding files must contain independently generated raw
key material of at least 32 bytes each; they are not base64-decoded. The
signing file contains one private Ed25519 JWK. No secret value is stored in
this project.

Author with synthetic fixtures first, then promote the same reviewed `bundle/`
bytes through staging and production. Bind environment-specific runtime paths,
credentials, private CA, and signing key in each environment. Staging must
verify the configured `at+jwt` header and claims, readiness, one approved
synthetic source lookup, audit durability, and JWS verification. See the
[authoring and promotion workflow](../CONFIG.md#authoring-and-promotion-workflow).
