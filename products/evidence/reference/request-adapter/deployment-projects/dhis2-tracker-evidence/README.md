# DHIS2 Tracker deployment project

This complete target bundle uses two DHIS2 Tracker programmes for two separate
minimum-disclosure requirements:

- adult status from the configured date-of-birth attribute; and
- professional licence status as an active-licence boolean plus a bounded
  expiry category.

The two requirements are independent. Each has its own pack route, fact
schema, derivation, authority profile, purpose, validity period, disclosure
family, and fixtures. A caller authorized for one learns nothing about the
other. Both routes come from the maintained `dhis2-tracker` Adapter pack, and
the bundle captures that pack and every pinned artifact by digest.

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

The maintained pack owns both fixed provider requests. The bundle binds only
the minimized `recordReference` input from the authorized subject and selects
one reviewed route. Programme, organisation unit, projected provider fields,
page size, page, and total-page behavior stay digest-covered pack policy, so a
bundle cannot widen the provider query through source parameters.

Each route performs one page-one lookup for exactly one tracked-entity
reference with `pageSize=2`. A second page is never followed. That two-result
ceiling is reviewed pack policy, allowing one bounded response to distinguish a
unique match from ambiguity. It is not a Rust domain rule and not a DHIS2
property. Both routes require the complete `page`, `pageSize`, `total`, and
`pageCount` pager, check that the page count agrees with the total and page
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

The professional-licence pack route explicitly treats an enrollment with no
restriction event as unrestricted. This is reviewed, digest-covered route
policy rather than an inference made by the Evidence bundle. A deployment that
cannot adopt that rule must publish a distinct pack route and digest; it cannot
change the result through runtime configuration. Evidence has no third state to
sign: a missing signal must either have a governed reading or stop the
assertion.

## Secrets

Required secret files beneath `/run/secrets/registry-evidence`, each owned by
the service identity with exact mode `0400` or `0600`, are:

```text
audit-hmac-key
subject-binding-hmac-key
dhis2-username
dhis2-password
```

Both routes select the same governed `population-tracker` connection, whose
runtime binding supplies these credential files. A deployment whose licence
programme is served by a separate DHIS2 instance or service account declares a
second governed connection policy and matching runtime binding, then binds the
licence source to that connection.

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
