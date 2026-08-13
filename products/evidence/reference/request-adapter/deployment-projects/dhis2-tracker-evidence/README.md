# DHIS2 Tracker deployment project

This complete target bundle uses two DHIS2 Tracker programmes for two separate
minimum-disclosure requirements:

- adult status from the configured date-of-birth attribute; and
- professional licence status as an active-licence boolean plus a bounded
  expiry category.

The two requirements are independent. Each has its own source, extraction
script, fact schema, derivation, authority profile, purpose, validity period,
disclosure family, and fixtures. A caller authorized for one learns nothing
about the other.

The reviewed governance bundle is under `bundle/`. Process-local paths,
listener settings, and the private-CA file binding are in `runtime.yaml`.
Deployments review and mount both files read-only, but staging and production
may use different runtime files without changing evidence semantics.

Before deployment, the operator changes only:

- `.example` OIDC and DHIS2 hosts;
- the DHIS2 programme, organisation unit, attribute, and programme-stage UIDs;
- issuer, provider, trust-domain, framework, evidence-type, and concept URIs;
- authority tags and purposes;
- the referenced secret files; and
- the runtime paths, listener binding, and private-CA bundle file.

## Shared lookup shape

Both sources reuse `adapters/prepare.rhai`. It reads only the closed
`program`, `organisationUnit`, `providerFields`, `pageSize`, `page`, and
`totalPages` parameters, so the same reviewed preparation renders both
requests and neither requirement can widen the other's query. Extraction stays
separate because the two sources validate and emit different facts.

Each source performs one page-one lookup for exactly one tracked-entity
reference with `pageSize=2`. A second page is never followed. That two-result
ceiling is governed adapter policy declared by this reviewed bundle and
rendered by its preparation script so one bounded response separates a unique
match from ambiguity. It is not a Rust domain rule and not a DHIS2 property.
Both extractions require the complete `page`, `pageSize`, `total`, and
`pageCount` pager, check that the page count agrees with the total and the page
size, and check that the returned collection agrees with the total. A truncated
or inconsistent pager is a protocol failure rather than a silently smaller
result set.

Because a Tracker response can carry attributes and enrollments beyond the ones
consumed by an adapter, both sources honestly declare `record-transformed`
posture. Extraction carries the returned `trackedEntity` only as a transient
fact, and each derivation requires its exact equality with the authorized
subject selector before evaluating anything else. A returned-record mismatch
fails closed as the internal `derivation_input_error` category and collapses
publicly into the same `evidence.unavailable` problem as an unresolved
lookup, so the caller cannot learn that a record was found. The raw tracked
entity reference is never included in evidence.

`pageSize`, `page`, and `totalPages` are strings because they become lexical
URL query values. In contrast, the OpenCRVS project's JSON body keeps numeric
and boolean constants typed.

## Adult status

One tracked entity is resolved by exact reference and one boolean is derived
from the configured date-of-birth attribute against the requirement's
`minimum_age_years`. The date of birth is never disclosed. A record whose
configured attribute is absent, duplicated, or not a string is unresolved or a
protocol failure, never a signed `false`.

## Professional licence status

The licence source projects the nested
`enrollments[program,status,events[programStage,status]]` shape. Extraction
selects the single enrollment in the configured licence programme, rejects a
duplicate enrollment in that programme as a protocol failure, and reads the
restriction programme stage from that enrollment's events. A restriction is
recorded only when an event in the configured stage carries the configured
completed status; a scheduled or otherwise incomplete restriction event is not
a restriction in force.

The derivation signs an active-licence boolean and an expiry category. The
boolean requires the configured active enrollment state, no recorded
restriction, and a legal local date inside the validity window. The category
comes from `bucket_number` over the closed `expiry_buckets` parameter, so a
verifier learns how soon the licence lapses without learning the date. A
validity window that ends before it starts is an inconsistent record and is
rejected as `derivation_input_error` rather than signed as expired.

The `absentRestrictionEventMeansUnrestricted` adapter parameter is a
governance declaration, not a convenience default. When the deployment sets it
`true`, as here, an enrollment recording no restriction event at all is read as
unrestricted, and that reading is reviewed bundle policy rather than an
inference from DHIS2 behavior. When a deployment cannot make that statement it
sets the parameter `false`, extraction omits `restriction_recorded`, the fact
schema rejects the incomplete fact set, and the requirement is unresolved.
Evidence has no third state to sign: a missing signal must either be governed
into a definite reading or stop the assertion.

## Secrets

Required secret files beneath `/run/secrets/registry-evidence`, each owned by
the service identity with exact mode `0400` or `0600`, are:

```text
audit-hmac-key
subject-binding-hmac-key
dhis2-username
dhis2-password
```

Both sources authenticate with the same credential files. A deployment whose
licence programme is served by a separate DHIS2 instance or a separate service
account gives that source its own `baseUrl` and its own secret references.

The audit and subject-binding files must contain independently generated raw
key material of at least 32 bytes each; they are not base64-decoded. Production
signing uses the pinned P-256 version in Transit through the workload-local
Unix-socket proxy. Evidence receives no provider token or private signing key.
No secret value is stored in this project.

Author with synthetic fixtures first, then promote the same reviewed `bundle/`
bytes through staging and production. Bind environment-specific runtime paths,
credentials, private CA, public signing key, and pinned Transit version in each
environment. Staging must
verify the configured `at+jwt` header and claims, readiness, one approved
synthetic source lookup per requirement, audit durability, and JWS
verification. See the
[authoring and production-build workflow](../CONFIG.md#authoring-and-production-build-workflow).
