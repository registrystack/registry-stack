# Protected-read deployment project

This complete target bundle reads a protected, scoped, read-only registry API
rather than a registry product's own API, and supports one minimum-disclosure
requirement: residence region as a coarse controlled code.

It is the pattern to copy when the registry data already sits behind an API
that projects fields, filters by an exact reference, and reports whether a
result page is complete. Registry Relay presents sources that way, so a Relay
deployment is the worked example, but nothing in this bundle names Relay or
depends on it. Any protected read with the same three properties fits.

The reviewed governance bundle is under `bundle/`. Process-local paths and
listener settings are in `runtime.yaml`. Deployments review and mount both
files read-only, but staging and production may use different runtime files
without changing evidence semantics.

Before deployment, the operator changes only:

- `.example` token-issuer and registry-API hosts;
- the dataset, entity, and field names in the request path and
  `providerFields`;
- issuer, provider, trust-domain, framework, evidence-type, and concept URIs;
- the codelist entries and disclosed region codes;
- authority tags and purposes;
- the referenced secret files; and
- the runtime paths and listener binding.

## Lookup shape

The source performs one collection read filtered to exactly one record
reference, projected to the two fields the requirement needs, with a page
bound of two. A second page is never followed. That two-result ceiling is
governed adapter policy declared by this reviewed bundle and rendered by
`adapters/prepare.rhai`, so one bounded response separates a unique match from
ambiguity. It is not a Rust domain rule and not a property of any registry
product.

This envelope reports no total count, only a page of records and a flag saying
whether further pages exist. Uniqueness is therefore decided from both signals
together: exactly one record and no further pages is a unique match, more than
one record or a claim of further pages is ambiguous, and an empty page that
still claims further pages contradicts itself and fails as a protocol error.
That is the general shape for cursor-paginated collections; a provider that
reports a total instead is read the way the tracker project reads its pager.

A source that cannot distinguish zero, one, and multiple matches in one bounded
request is not a Version 1 integration. See the
[provider prerequisites](../CONFIG.md#provider-prerequisites).

Because the protected read already restricts the response to the requested
fields, the source declares `field-projected` posture. Extraction carries the
returned record identifier only as a transient fact, and the derivation
requires its exact equality with the authorized subject selector before
evaluating anything else. A returned-record mismatch fails closed as the
internal `derivation_input_error` category and collapses publicly into the same
`evidence.unavailable` problem as an unresolved lookup, so the caller cannot
learn that a record was found.

`providerFields` and `resultLimit` are strings because they become lexical URL
query values, and both are pinned by the adapter-parameter schema: the field
list is the projection this requirement is entitled to, and the page bound is
the ambiguity signal, so neither is an operator dial.

## Purpose declaration

The registry API requires a declared purpose on every request. It is pinned as
a fixed header in the reviewed bundle, so no caller and no script can widen the
purpose the registry sees or record. The purpose the registry logs is the same
purpose the authority profile grants and the assertion carries.

## Residence region

One record is resolved by exact reference and one controlled code is signed.
The register's own region code never leaves the service: `codelists/`
maps several register codes onto each disclosed region, and only the codes in
`allowed_outputs` can pass the output gate. A register code with no reviewed
mapping leaves the requirement unresolved rather than passing the precise code
through, and a record carrying no region at all is refused by the fact schema
before derivation runs, so an absent region can never be read as a region.

## Authentication

Inbound callers present access tokens from the deployment's own issuer. A
deployment with no identity provider runs Registry Mint as that issuer:
Evidence verifies Mint-issued tokens exactly the way it verifies any other OIDC
issuer, and the protected registry API in front of the source data is pointed
at the same issuer. Neither service depends on the other.

Outbound, the source authenticates to the registry API with the OAuth 2.0
client-credentials grant against that same issuer, placing the credentials in
the form body and caching the token for at most a minute. A deployment whose
registry API accepts a different credential kind changes only the source's
`authentication` block.

The registry API here is presented over ordinary public TLS, so `runtime.yaml`
declares no private trust profile and the source names none. A deployment whose
registry API sits behind an internal CA adds a profile to `outboundTls` and
names it on the source, the way the other reference projects do.

## Secrets

Required secret files beneath `/run/secrets/registry-evidence`, each owned by
the service identity with mode `0600`, are:

```text
audit-hmac-key
subject-binding-hmac-key
registry-api-client-id
registry-api-client-secret
```

The audit and subject-binding files must contain independently generated raw
key material of at least 32 bytes each; they are not base64-decoded. Production
signing uses the pinned P-256 version in Transit through the workload-local
Unix-socket proxy. Evidence receives no provider token or private signing key.
No secret value is stored in this project.

Author with synthetic fixtures first, then promote the same reviewed `bundle/`
bytes through staging and production. Bind environment-specific runtime paths,
credentials, public signing key, and pinned Transit version in each environment.
Staging must verify the
configured `at+jwt` header and claims, readiness, one approved synthetic source
lookup, audit durability, and JWS verification. See the
[authoring and production-build workflow](../CONFIG.md#authoring-and-production-build-workflow).
