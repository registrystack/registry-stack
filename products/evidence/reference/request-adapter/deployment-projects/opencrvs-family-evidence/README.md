# OpenCRVS family-evidence deployment project

Status: deployment-shaped for a country configuration with governed stable
parent references; not a generic OpenCRVS capability claim

This complete target bundle uses one uniquely resolved registered birth event
for three separate minimum-disclosure requirements:

- adult status from `dateOfEvent`;
- exact registered-parent confirmation against a separately authorized
  candidate reference; and
- identification of the registered parents as one or two audience-scoped
  entity references.

The reviewed governance bundle is under `bundle/`. Process-local paths and
listener settings are in `runtime.yaml`. Deployments review and mount both
inputs read-only, but staging and production may use different runtime files
without changing evidence semantics.

Both OpenCRVS sources reuse `birth-event-prepare.rhai`; the closed
`selectorRole` parameter selects the already validated `subject` or `child`
role. Extraction remains separate because the two sources validate and emit
different facts.

The event lookup sends only the child tracking ID. Extraction retains the
returned tracking ID as a narrow fact, and each derivation requires it to equal
the independently authorized child selector before producing a value. The
candidate-parent reference comes from the authenticated grant and is supplied
only to the relationship derivation. Raw parent references enter transient extraction and
derivation but never production evidence, audit, logs, errors, metrics, traces,
or failure artifacts. Sanitized synthetic references are intentionally present
in local contract fixtures.

## Deployment decisions

Replace the separate `.example` OIDC, OpenCRVS authorization, and OpenCRVS
Event Search hosts and every `urn:gov:example:*` identifier. Confirm the exact
client capability or scope assigned by that deployment. In the family source,
replace these illustrative declaration field identifiers:

```text
mother.personReference
father.personReference
```

They must name the target country configuration's complete set of stable,
opaque parent references from the same namespace used by the
`civil-person-reference-v1` candidate selector. If the OpenCRVS deployment
does not return such fields, this exact-reference configuration is not
deployable unchanged.

The example's closed source contract also states that:

- `urn:gov:example:opencrvs:registered-parent-set:v1` identifies the reviewed
  country-specific relationship-set semantics;
- `urn:gov:example:opencrvs:person` is the shared candidate and source-reference
  namespace;
- absence of either configured declaration field authoritatively means no
  registered parent in that slot, rather than unreturned or unavailable data;
  and
- at least one registered parent reference is required for this project.

Those statements are trusted deployment governance, enforced through adapter
parameters, fact schema constants, and derivation checks. They are not inferred
from generic OpenCRVS behavior.

A country may instead review a deterministic tuple comparison over returned
attributes, such as an authoritative identifier plus date of birth. That is a
different versioned derivation and selector profile. Fuzzy search, candidate
ranking, and silent fallback from missing identifiers to names are not part of
this example.

The portable concepts say `registered parent`. Rename them to `legal parent`
only when the jurisdiction explicitly governs the configured record fields and
matching rule as proof of legal parentage. Registered parent, biological
parent, guardian, and current parental responsibility are not interchangeable.

## Negative evidence

The relationship derivation may return `false` only when all of these are
true:

1. exactly one registered birth event was resolved;
2. its returned tracking ID exactly matches the authorized child selector;
3. the configured fields constitute the complete authoritative parent set;
4. every present reference is valid and references are unique; and
5. exact membership found no candidate match.

No event, multiple events, missing declaration data, an empty parent set, a
wrong type, or a namespace mismatch stops without a signed negative.

## OAuth and secrets

This example places the client credentials in the token request body, so no
credential reaches a URL that an authorization server, proxy, or ingress may
log. `form-body` and `basic-header` are the only placements Version 1 offers.
Locally, the complete token URL, body, response, and debug output must be
stripped or redacted, redirects denied, and token responses bounded.

The token endpoint returns only `access_token` and `token_type`. RFC 6749
section 5.1 makes `expires_in` recommended rather than required, so the bundle
states `assumedLifetimeSeconds` and the cache stays clamped to
`maximumCacheSeconds`.

Required secret files beneath `/run/secrets/registry-evidence`, each owned by
the service identity with exact mode `0400` or `0600`, are:

```text
audit-hmac-key
subject-binding-hmac-key
opencrvs-client-id
opencrvs-client-secret
```

The audit and subject-binding files must contain independently generated raw
key material of at least 32 bytes each; they are not base64-decoded. Production
signing uses the pinned P-256 version in Transit through the workload-local
Unix-socket proxy. Evidence receives no provider token or private signing key.
No credential or live subject identifier is stored in this project.

Author with synthetic fixtures first, then promote the same reviewed `bundle/`
bytes through staging and production. Bind environment-specific runtime paths,
credentials, private CA, public signing key, and pinned Transit version in each
environment. Staging must
verify the configured `at+jwt` header and claims, OAuth bootstrap, readiness,
one approved synthetic source lookup, audit durability, and JWS verification.
See the [authoring and production-build workflow](../CONFIG.md#authoring-and-production-build-workflow).
