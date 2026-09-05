# Evidence Version 1 configuration reference

Status: Implemented Version 1 configuration contract

Evidence starts from two closed, startup-only inputs:

1. `bundle/evidence.yaml` and its referenced bundle files define governed
   evidence semantics and source authority.
2. `runtime.yaml` binds that bundle to one process, filesystem, listener, audit
   destination, secret mount, signer transport and pinned version, and local
   TLS trust files.

Both inputs are reviewed, validated completely before readiness, mounted
read-only, and immutable for the process lifetime. Evidence computes stable
bundle and runtime revisions at startup; audit events carry the governed bundle
revision. Runtime configuration is not an override layer. It cannot
change a source origin, request, credential kind, requirement, authority,
selector, disclosure rule, rate limit, signing policy, or audit fail-closed
policy.

Unknown keys are rejected at every level. All names below are exact and
case-sensitive unless the field explicitly says otherwise.

## What an adopter normally edits

Most adopters should need to edit only:

- deployment URIs, hosts, identifiers, purposes, authority tags, and selector
  field names in `evidence.yaml`;
- one small preparation script, where the source's transport needs one, and one
  extraction script per distinct provider request/response shape;
- one derivation script per requirement;
- the closed parameter and fact schemas beside those scripts;
- sanitized fixtures;
- process-local paths, listener settings, and signer bindings in `runtime.yaml`;
  and
- secret and private-CA files outside the project.

Changing Rust, defining a source-product plugin, or adding a product-specific
configuration variant is not part of ordinary adoption.

## Publish the service for discovery

Put the public facts that cannot be derived into the governed target:

```yaml
publication:
  serviceId: urn:example:evidence-service
  title: National Evidence service
  description: Minimum-disclosure assertions from the responsible authority
  endpointUrl: https://evidence.example.org
  jurisdictions: [urn:example:jurisdiction:national]
```

`endpointUrl` is the native Evidence client base URL, not the
`/v1/evidence` request route. HTTPS is required outside local authoring; local
fixtures may use numeric loopback HTTP. Evidence derives the legal issuer,
technical provider, exact compatible binding-and-response capability profiles,
and evidence type identifiers from the governed bundle. Binding modes and
response formats are never independent tags that a client could combine into
an impossible operation. Evidence publishes one record with a distinct derived
`bindingId` for each exact Evidence Type and compatible profile pair, which
also prevents cross-requirement matches. Build the production candidate with:

```sh
evidencectl build --project <project> --target <target> --output <candidate>
```

The command compiles, validates, seals, and atomically publishes
`bundle/catalog.jsonld`; ordinary target-host package and bundle checks verify
the same bytes.
Evidence validates exact regeneration at startup and serves those packaged bytes
at `GET /catalog.jsonld` without authentication, source access, signing, or
audit work. This public-facts projection supports search and is not a trust
anchor. Provider-public-projection tests exclude private source, credential,
policy, script, selector, and audit configuration.

## Provider prerequisites

Decide compatibility before authoring scripts. These are the prerequisites for
an `http-json` source, which reads the provider's own API. A provider that meets
none of them may still be reachable as a `sqlite-extract` source, whose
prerequisite is a different one: the publisher must be able to produce a
snapshot of the data and to state when it was published.

An `http-json` provider must:

- expose a bounded lookup at a fixed origin over HTTPS, except numeric loopback
  HTTP used only by deterministic local tests;
- accept one fixed `GET` or `POST` and return JSON with media type
  `application/json` or `application/graphql-response+json`;
- let one response distinguish zero, one, and multiple matches, either through
  a trustworthy total count plus at most one minimized result, or through a
  caller-controlled hard result limit of at least two;
- not require page traversal, a response-provided next URL, or a retry. A
  provider may require the closed search-then-fetch profile, but both endpoints
  and the scalar fact binding must be reviewable and fixed before startup;
- support a query/body/path lookup narrow enough that Evidence does not fetch
  a broad candidate set; and
- provide the complete facts and relationship-set completeness needed by the
  requirement, or expose a governed intermediary that does.

An unbounded array without a trustworthy count or hard result limit is not
adaptable in Version 1. Neither is a provider that requires broad retrieval and
local candidate selection. Use or build a governed bounded-lookup facade
outside Evidence rather than weakening the one-request and no-matcher boundary.

The hard result limit itself is governed adapter policy. Its value, such as
`resultLimit: 2` in the source's `adapterParameters`, is declared by the
reviewed source configuration and rendered into the request by that source's
preparation script. Rust enforces the generic one-request-per-stage,
projection, and response bounds around it and holds no domain rule about a
two-result ceiling.
The number is not a property of any source product; a different reviewed
configuration may declare a different limit as long as one response still
distinguishes zero, one, and multiple matches.

## Governed bundle

The governed file is `bundle/evidence.yaml`.

### Top-level sections

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | Bundle schema version. Version 1 requires integer `1`. |
| `assuranceProfile` | yes | Explicitly `local`, `production`, or `evidence-grade`. Runtime configuration cannot override it. |
| `service` | yes | Evidence provider identity and trust domain. |
| `issuer` | yes | Issuer identity placed in evidence. |
| `authentication` | yes | Closed inbound OIDC access-token verification policy. |
| `audit` | yes | Audit format, pseudonymization key reference/version, and fail-closed policy. Storage location is runtime-owned. |
| `subjectBinding` | yes | Subject-binding key reference/version. The key is the same whichever binding mode a requirement selects; the modes are domain-separated inside the derivation. |
| `rateLimits` | yes | Governed anti-enumeration and request limits. |
| `signing` | yes | Evidence/JWS format, algorithm, key references, validity, JWKS path, and rollover policy. |
| `responseFormats` | no | Response formats the whole deployment permits. Omission means `[signed-jws]`. Declare it explicitly in production bundles. |
| `acquisitionCapabilities` | no | Gated acquisition kinds and source optimizations this bundle opts in to, at most two entries: `search-then-fetch-set` and `source-batch`. Omission and `[]` both enable nothing. |
| `holderBoundBatchMaxSize` | no | Ceiling of 1 through 16 on how many assertions one holder-bound release may carry. Omission means 1, so a bundle written before batch release cannot serve a batch. |
| `selectorProfiles` | yes | Closed caller/grant/context selector shapes. |
| `sources` | yes | Fixed source authorities, transport policy, scripts, schemas, and bounds. |
| `authorityProfiles` | yes | Who may request which requirement, purpose, audience, roles, profiles, and value origins. |
| `requirements` | yes | Evidence semantics, source, derivation, concepts, fixtures, and disclosure family. |

`local` is an authoring profile. A local requirement may omit `fixtures` while
the provider contract is still being written. This does not disable any other
runtime boundary: the bundle and runtime remain immutable, inbound
authentication and authorization remain required, source requests remain fixed
and bounded, signing and both audit gates remain fail-closed, and assertions
are visibly marked `local`. Local Mint may use only the exact canonical issuer origin
`http://127.0.0.1:<non-zero-port>` and the same origin's
`/.well-known/jwks.json`; other authentication URLs remain HTTPS.

`production` and `evidence-grade` are deployable profiles. Every requirement
must reference a fixture suite, and the existing complete coverage validation
must pass before the bundle loads. No receipt, certification command, build
artifact, or alternate evaluator is introduced by the assurance profile.

### Service, issuer, and inbound authentication

| Section or key | Required | Meaning |
|---|---|---|
| `service.providerId` | yes | Technical Evidence provider URI placed in evidence. |
| `service.publicOrigin` | yes | Exact canonical public Evidence origin used by RFC 9728 metadata. HTTPS is required outside the numeric-loopback local profile. |
| `service.trustDomain` | yes | One operator-controlled trust-domain URI for the process. |
| `issuer.id` | yes | Legal issuer URI placed in evidence. Governance must authorize the provider to act for it. |
| `authentication.kind` | yes | Exactly `oidc-access-token`. |
| `authentication.issuer`, `authentication.jwksUri` | yes | Exact HTTPS token issuer and JWKS endpoint. Path-based issuers are supported. The fixed JWKS endpoint may resolve to a public or private HTTPS address; DNS is pinned for each fetch, ambient proxies are disabled, and cloud-metadata destinations remain prohibited. |
| `authentication.audiences` | yes | Non-empty exact audience allowlist. |
| `authentication.tokenTypes` | yes | Non-empty allowlist containing only `at+jwt` and/or `application/at+jwt`. |
| `authentication.algorithms` | yes | Non-empty allowlist containing only `EdDSA`, `ES256`, and/or `RS256`. No algorithm fallback is permitted. |
| `authentication.principalClaim` | yes | The only claim used for the principal. Its absence denies; `client_id`, `azp`, request data, and proxy headers are not fallbacks. |
| `authentication.requesterTagsClaim` | yes | Claim containing the requester tags matched against an authority profile. |
| `authentication.evidenceAudienceClaim` | yes | Claim containing the exact evidence audience. The public request cannot choose another audience. |
| `authentication.grantIdClaim`, `authentication.grantAuthorityClaim` | yes | Claims used only when an `authenticated-grant` origin is selected. The authority must equal the matched authority-profile id. |
| `authentication.maximumTokenLifetimeSeconds` | yes | Positive maximum accepted `exp - iat`, up to 86,400 seconds. Its presence requires `iat`, `exp > iat`, and an interval within the maximum. |
| `authentication.revokedKeyIds` | yes | Explicit emergency denylist, including an empty list. It is checked before cached JWKS key selection. |
| `authentication.actorClaim` | no | Optional verified actor claim. Omission does not enable a fallback actor source. |

### Audit, subject binding, rates, and signing

| Section | Required fields and rule |
|---|---|
| `audit` | `format: keyed-jsonl`, file-only `hashSecretRef`, positive `hashKeyVersion`, and `failClosed: true`. The referenced master contains at least 32 raw secret bytes. Rust HKDF-separates chain and identifier subkeys. The runtime file owns storage location. |
| `subjectBinding` | File-only `secretRef` and positive `keyVersion`. The referenced master contains at least 32 raw secret bytes, uses a distinct reference, and must resolve to bytes distinct from the audit master. Rust derives purpose-scoped bindings over the complete canonical role/profile/value bundle, never per-field hashes. The remaining scope input is the requirement's binding mode: the authenticated audience for an audience-scoped requirement, the presented holder key thumbprint for a holder-bound one. The two derivations are domain-separated, so one mode's binding can never be read as the other's. |
| `rateLimits` | Positive `requestsPerPrincipalPerMinute`, `burstPerPrincipal`, and `failedSelectorAttemptsPerPrincipalAuthorityPerMinute`. Raw selector values never become rate-limit labels. |
| `signing` | Exact keys are `format: flattened-jws-json`, `algorithm: ES256`, `activePublicJwkFile`, `publishedPublicJwkFiles`, `revokedKeyIds`, fixed `jwksPath`, `maximumAssertionValiditySeconds`, and `verifierClockSkewSeconds`. Every exact public EC P-256 JWK has a 43-character RFC 7638 thumbprint `kid`; active, published, and revoked sets are disjoint. Missing signing material fails readiness; there is no unsigned fallback. |
| `responseFormats` | Closed unique list of 1 through 3 entries drawn from `signed-jws`, `unsigned-json`, and `sd-jwt-vc`. `signed-jws` must always be present; a bundle that omits it is rejected at startup. Every other format additionally requires the matched grant to permit it, and signing material must still be ready even for an unsigned response. |

### Selector profiles

Each `selectorProfiles.<id>` declares `maximumAggregateBytes` and one exact
`fields` map of 1 through 16 deployment-defined fields. Field names are opaque
to Rust. A profile is not an identity type and possession of its values is not
authority.

| Field type | Required declaration |
|---|---|
| `string` | `minimumBytes`, `maximumBytes` |
| `date` | Canonical `YYYY-MM-DD` |
| `integer` | Inclusive `minimum`, `maximum` within the safe integer bound |
| `boolean` | No additional keys |
| `controlled-code` | `codelist`, `codelistVersion`, `maximumBytes` |

Alternative sufficient field sets and sets with an extra disambiguator are
different named profiles. Rust does no case folding, Unicode normalization,
transliteration, phonetics, tokenization, name-order parsing, partial-date
matching, fuzzy scoring, or candidate selection.

### Authority profiles

An authority profile has a `kind` of `statutory`, `organizational`, `consent`,
`delegated`, or `explicit-request`, non-empty `requesterTags`, and grants.
Each grant binds one exact `requirement`, `purpose`,
`audienceFrom: authenticated-requester`, an optional `responseFormats` list,
and the complete subject-role set. A grant's `responseFormats` follows the same
closed rule as the bundle-level list: 1 through 3 unique entries that must
include `signed-jws`, defaulting to `[signed-jws]` when omitted. Unsigned output
and the SD-JWT VC serialization each require both the bundle and the one
complete matched grant to permit them, so a production grant that says nothing
permits only signed JWS.

A grant's optional `subjectBindingModes` is a separate permission from
`responseFormats`: it is a unique list of at most 2 entries drawn from
`audience-scoped` and `holder-bound`, and omission and `[]` both mean
`audience-scoped` only. Permission to serialize a response is never permission
to issue under a binding mode, so widening a grant to `sd-jwt-vc` grants it no
holder-bound issuance; the grant must name `holder-bound` itself. Both halves
are read from the same one matched grant, because permissions are never unioned
across grants, and a request that fails either half receives the same single
denial without learning which half failed.

Every grant subject fixes `role`, `selectorProfile`, and one `valueOrigin`:

- `request` requires values in the closed public request and prohibits
  `valueClaims`;
- `authenticated-context` requires an exact field-to-verified-claim
  `valueClaims` map and rejects caller values; and
- `authenticated-grant` requires the same exact map, rejects caller values,
  and additionally requires the configured grant id and grant authority. The
  authenticated authority value must equal the matched authority-profile id.

Claim paths are resolved only from the strictly verified access token. A
caller-supplied grant reference, selector, consent reference, or approval value
cannot create authority. The runtime authorizes the principal, optional actor,
requirement revision, purpose, audience, authority profile, and every
role/profile/origin tuple as one decision before credentials or source access.

A profile matches only when every tag in its `requesterTags` is present in the
verified claim, so adding a tag narrows the profile. A request whose verified
token carries an actor claim matches only a profile whose `kind` is
`delegated`, so `kind` is an authorization condition and not only an audit
label. Access is per requester
class rather than per client identity: two clients carrying the same tags have
the same access, and differentiated requirements, purposes, or `valueClaims`
are expressed by issuing different tags. To bind purpose to the token issuer
instead of the caller's choice, give each purpose its own tag and its own
profile. Exactly one authority path may match a request; two profiles covering
the same requirement, purpose, and subject tuple are denied at request time and
are not rejected at startup.

### Requirements and concepts

Each requirement declares these fields:

| Key | Required | Meaning |
|---|---|---|
| `id`, `kind` | yes | Stable requirement URI and one of `criterion`, `information-requirement`, or `constraint`. |
| `subjectBinding` | no | `audience-scoped` or `holder-bound`. Omission means `audience-scoped`, and an omitted key stays out of the projected configuration, so declaring the mode on one requirement moves no other requirement's `configurationRevision`. See the holder-bound rules below. |
| `acquisition` | yes | One of the three closed shapes below. None permits response-led routing. |
| `purposes` | yes | Closed purpose codes that authority grants may select. |
| `subjectRoles` | yes | Complete role set, `cardinality: one`, and permitted selector profile ids. Public subject array order is not semantic; roles are resolved uniquely and canonicalized to declaration order. |
| `referenceFrameworks`, `evidenceType` | yes | Governed legal/procedural framework URIs and the exact Evidence Type URI. |
| `observationTimezone` | no | Valid IANA timezone used for `legal_local_date` and `legal_local_time`. Omission uses UTC. Declare it explicitly whenever local legal time can affect a result. |
| `validitySeconds` | yes | Positive assertion lifetime no greater than the signing maximum. |
| `derivation` | yes | Script, optional minimized `selectorInputs`, and closed typed parameters. |
| `concepts` | yes | 1 through 16 exact outputs, each with `id`, `form`, `required`, and closed form-specific `constraints`. |
| `fixtures` | conditional | Bundle-relative sanitized project fixture referenced by exactly one requirement. It may be omitted only under `assuranceProfile: local`; production and evidence-grade require it and complete coverage. |
| `disclosureGuard.families` | yes | Non-empty reviewed disclosure-family URI set. Reuse across enabled requirements is rejected; distinct labels still require human combined-disclosure review. |
| `existenceDisclosure` | yes | Exactly `collapse-unresolved` in Version 1. |

`acquisition.kind` selects one of three closed shapes:

| `kind` | Other keys | Call ceiling |
|---|---|---|
| `single` | `source` | One. |
| `search-then-fetch` | `search`, `fetch` (one source id) | Two. |
| `search-then-fetch-set` | `search`, `fetch` (2 through 4 members), `maximumAcquisitionMilliseconds` | One plus the declared member count. |

`search-then-fetch-set` is a gated kind. It serves only where this bundle names
it under `acquisitionCapabilities` and the operator separately names it under
the runtime file's `acquisitionCapabilities`; a bundle missing either half is
refused before the listener binds. Each `fetch[]` member declares its own
`source` and a `factInputs` allowlist of 1 through 16 validated search fact
names, which is the only search-derived data that member receives through any
channel, including the body its preparation builds. Members must be distinct
from each other and from the search source, and each fact name must be a
required fact of the search source's fact schema. Members are called in
declared order after the search resolves to a unique schema-valid match, and
derivation receives the union of the stage FactSets, whose names startup proved
disjoint. `maximumAcquisitionMilliseconds` is 1 through 30,000 and bounds the
whole acquisition, including the transitions between stages; exceeding it fails
the requirement as a dependency failure and never cancels a durable audit
append.

Supported concept forms are `boolean`, `controlled-code`,
`controlled-category`, `bounded-integer`, `bounded-decimal`, `date-bucket`,
`time-bucket`, `audience-scoped-entity-reference`, `controlled-code-list`,
`entity-reference-list`, and `reviewed-structured-value`. Constraint keys use
bundle camelCase, including `codelistVersion`, `maximumBytes`, `categoryScheme`,
`schemeVersion`, `maximumScale`, `bucketScheme`, `minimumItems`, `maximumItems`,
`maximumSerializedBytes`, and `unique`, with the exact set determined by the
selected form. Codelist declarations and reviewed structured schemas are
bundle-relative, closed, versioned artifacts validated at startup.

A requirement whose `subjectBinding` is `holder-bound` derives its subject
bindings under the holder key the request presents rather than under the
authenticated audience, so its assertions are scoped to no relying party. Three
rules follow, and each is checked at bundle load, before the listener binds,
with a cause that names no configured value:

- the mode permits only the SD-JWT VC serialization, so the requirement must be
  reachable under a bundle `responseFormats` list and at least one grant whose
  own `responseFormats` include `sd-jwt-vc`. The restriction is per
  requirement: `signed-jws` stays mandatory at bundle and grant scope, and the
  rest of the deployment is unaffected;
- at least one grant covering the requirement must name `holder-bound` in
  `subjectBindingModes`, since format permission alone grants nothing; and
- the requirement's concepts may not use the `audience-scoped-entity-reference`
  or `entity-reference-list` forms. Both are references an audience resolves,
  and there is no audience here to resolve them.

At request time a holder-bound requirement additionally needs the request to
carry a holder key. That is answered only after authorization and the format
gate have both passed, so an unauthorized requester learns nothing about which
requirements exist or which binding mode each one carries.

`observed_at` is a runtime-supplied instant normalized to UTC. Rust resolves
the legal local date and time from `observationTimezone`; without the optional
field it uses UTC. Fixtures supply only `observed_at`, never derived local
values, so timezone boundary behavior uses the production path.

Derivation parameters are limited to bounded strings, safe integers, booleans,
typed canonical decimals shaped as `{type: decimal, value: "..."}`, and arrays
of typed decimal bucket boundaries. Adapter parameters use their separately
closed JSON Schema and the narrower conversion described in
[`ADAPTER-API.md`](../ADAPTER-API.md#inputs). Neither parameter map may contain
secrets or runtime authority.

### Source

A source declares one `transport`, and that tag decides the rest of the object.
Version 1 defines two, and they are peers. `http-json` reaches a fixed HTTPS
origin over the network. `sqlite-extract` runs one reviewed SQL statement
against a read-only SQLite extract file mounted beside the process. A key
belonging to the other transport is an unknown key rather than an ignored one,
so `baseUrl` on a `sqlite-extract` source fails startup instead of being
skipped.

Every source carries the same keys whichever transport it names:

| Key | Required | Meaning |
|---|---|---|
| `transport` | yes | `http-json` or `sqlite-extract`. Selects which further keys the source declares. |
| `posture` | yes | `source-derived`, `field-projected`, or `record-transformed`, describing what crosses the source boundary. |
| `request` | yes | One fixed request plan, shaped by the transport. |
| `responseSchema` | yes | Bundle-relative closed JSON Schema for the projected source response. Checked before `extract/2` runs. |
| `extractScript` | yes | Bundle-relative Rhai script implementing `extract/2`. |
| `factSchema` | yes | Bundle-relative closed JSON Schema for match facts. |

Choosing a transport is a choice about where the authoritative data sits and
what the deployment can promise about it. `http-json` reads the authority live,
so the answer is as current as the provider's own API, and the deployment
carries an origin, a credential, a TLS trust decision, and a network failure
mode. `sqlite-extract` reads a published snapshot, so the deployment carries a
file and a declared staleness tolerance and no credential at all, and the answer
is exactly as current as the snapshot states it is. Nothing after the request
differs: both transports run the same projection, the same response schema
check, the same `extract/2`, and the same fact schema.

`responseSchema` states the shape the adapter was reviewed against, so the
script never has to prove it by hand. A response outside that shape is a
source-protocol failure and no script runs. Two rules differ from the fact and
adapter-parameter roles, because the projected tree is not what the source
returned:

- A response schema may require fewer members than it declares properties.
  Projection drops a selected leaf the record did not carry, and a page decided
  ambiguous is never read record by record, so a record on that page need not
  be complete.
- A response schema node may write its type as the pair `[T, "null"]`. A source
  that reports an explicit null where it holds no value has that null carried
  through projection verbatim; the script reads it with `is_missing`, exactly as
  it reads an absent leaf. This is the only union the subset admits.

What stays with the script is what a shape cannot state: how a reported total
agrees with the records returned, page-count arithmetic, uniqueness across
fields, and which values must agree with the closed adapter parameters.

### HTTP source

```yaml
sources:
  source-a:
    transport: http-json
    baseUrl: https://registry.gov.example
    posture: record-transformed
    tlsTrustProfile: government-internal-pki
    authentication:
      kind: static-authorization
      tokenRef: secret:file/source-token
    request: {}
    responseSchema: schemas/source-a-response.schema.yaml
    extractScript: adapters/source-a-extract.rhai
    factSchema: schemas/source-a-facts.schema.yaml
```

Beyond the shared keys, an `http-json` source declares:

| Key | Required | Meaning |
|---|---|---|
| `baseUrl` | yes | Fixed HTTPS origin, except for the `kind: none` local loopback boundary below. No path, query, fragment, user information, wildcard, or runtime substitution. |
| `tlsTrustProfile` | no | Logical profile name bound by `runtime.yaml`. Omission uses configured system roots only. |
| `authentication` | yes | One closed source-authentication profile below. `kind: none` is restricted to explicit local authoring at a numeric-loopback origin. |
| `unresolvedProblem` | no | Exact source-neutral `{status: 404, type: absolute HTTPS URI, code: bounded problem id}` tuple. Only an exact six-member `application/problem+json` response becomes explicit unresolved; omission leaves every 404 a dependency failure. Incompatible with `batch`. |
| `batch` | no | Reviewed one-call optimization for the multi-subject request-batch route. It is fixed-path-only and requires both bundle and runtime `source-batch` capability. |

Its `request` is the fixed evidence-data request plan in
[Request](#request).

`unresolvedProblem` does not teach Evidence a provider protocol. It declares
one exact tuple for this source. The response must have status 404, exactly one
`Content-Type: application/problem+json`, and exactly the six Problem Details
members `type`, `title`, `status`, `detail`, `code`, and `traceId`; duplicate,
missing, extra, mistyped, mismatched, or oversized bodies remain dependency
failures. The body is discarded before projection or Rhai. A singular or
search-stage outcome becomes Evidence unavailable under the neutral audit
decision `unresolved`; the same outcome from a fetch or member after unique
search is a dependency failure.

### Source authentication

All secret references are logical. Rust resolves them only after authorization,
durable access audit, and complete request-parts validation. No secret is passed
to Rhai.

```yaml
# No outbound credential, for local authoring only
authentication:
  kind: none

# HTTP Basic
authentication:
  kind: basic
  usernameRef: secret:file/source-username
  passwordRef: secret:file/source-password

# Authorization: Bearer <secret>
authentication:
  kind: static-authorization
  tokenRef: secret:file/source-token

# Authorization: Token <secret>, for a source that names another scheme
authentication:
  kind: static-authorization
  tokenRef: secret:file/source-token
  scheme: Token

# A provider-specific API-key header
authentication:
  kind: static-api-key
  headerName: X-API-Key
  valueRef: secret:file/source-api-key

# OAuth 2.0 client credentials, client-secret form
authentication:
  kind: oauth2-client-credentials
  tokenEndpoint: https://auth.registry.gov.example/token
  clientIdRef: secret:file/source-client-id
  clientSecretRef: secret:file/source-client-secret
  scope: recordsearch
  credentialPlacement: basic-header
  maximumCacheSeconds: 300

# OAuth 2.0 client credentials, private_key_jwt form
authentication:
  kind: oauth2-client-credentials
  tokenEndpoint: https://auth.registry.gov.example/token
  clientIdRef: secret:file/source-client-id
  clientAssertionKeyRef: secret:file/source-client-key
  # Only for a server that expects an identifier it is not reached at; the
  # default is tokenEndpoint. Distinct from the audience below, which is a
  # token-request parameter rather than a claim in the signed assertion.
  clientAssertionAudience: https://auth.registry.gov.example/
  scope: recordsearch
  audience: https://api.registry.gov.example/
  maximumCacheSeconds: 300
```

`kind: none` is accepted only when the bundle declares
`assuranceProfile: local` and `baseUrl` is an exact canonical
`http://<numeric-loopback>:<non-zero-port>` origin. It accepts no other
members, cannot use `tlsTrustProfile`, and sends no `Authorization` or other
authentication header. Hostnames such as `localhost`, omitted or noncanonical
ports, user information, paths, queries, fragments, HTTPS origins, and
non-loopback addresses are rejected. Production and evidence-grade bundles
reject this kind.

`static-authorization` sends `Authorization: Bearer <secret>` unless `scheme`
names another one. RFC 9110 section 11.1 leaves the scheme to the origin, so a
source expecting `Token`, `SSWS`, or another provider scheme states it here; the
value is validated as an HTTP token of at most 32 bytes. `static-api-key` cannot
serve those sources, because its `headerName` denylist refuses `Authorization`.

`static-api-key.headerName` cannot be `Authorization`, `Host`, `Cookie`,
`Set-Cookie`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, a
hop-by-hop header, forwarding/proxy header, or tracing header. Names are
validated as HTTP field names. Secret values are bounded and reject controls,
CR, and LF.

An OAuth source declares exactly one client authentication form.
`clientSecretRef` selects the client-secret form and requires
`credentialPlacement`; `clientAssertionKeyRef` selects `private_key_jwt` and
admits neither. The referenced key file holds a private JWK, and the runtime
signs a short-lived assertion under the algorithm that key declares: SMART on
FHIR Backend Services names ES384 and RS384, and requires this form rather than
a client secret. RFC 7523 section 2.2 fixes the client-assertion type, so it is
not configurable, and the assertion lifetime is fixed rather than governed. A
key the runtime cannot read fails the request before any token call.

`clientAssertionAudience` is the assertion's `aud` claim, and it defaults to
`tokenEndpoint` exactly as the bundle spells it, which is the value SMART on
FHIR Backend Services requires.
State it only for a server that expects an identifier it is not reached at: one
behind a proxy, or one naming its issuer. RFC 7523 section 3 asks only that the
value identify the authorization server, says the token endpoint URL MAY be
used, and leaves the string to out-of-band agreement, so no relationship to
`tokenEndpoint` is imposed and the value is not a URL to the runtime. Section 3
has the server compare it by Simple String Comparison, so it is signed byte for
byte: a default port or trailing slash written here survives into the claim. It
is admitted only beside `clientAssertionKeyRef`, because a shared secret carries
no claim to put it in, and it names who may accept the assertion, never where
the token request is sent. Register one assertion key per authorization server:
a key registered at two servers is what lets an audience meant for one be
presented to the other.

OAuth `credentialPlacement` is one of `basic-header` or `form-body`. RFC 6749
section 2.3.1 requires the client identifier and secret to travel in the
Authorization header or the request body and never in the request URI, so
Version 1 offers no query-string placement and no credential can reach a token
URL log. Token redirects are denied and token responses are bounded. The token
request is credential bootstrap, not a second evidence-data lookup.

`audience` is sent as a token-request parameter only when the bundle states it.
An authorization server that scopes a token to a named API needs it; without it
it returns a token the source will reject. It is not
`clientAssertionAudience`: this one is a form field of the token request, that
one is a claim inside the signed assertion, and a server may want both, neither,
or different values for each.

RFC 6749 section 5.1 makes `expires_in` recommended rather than required, so a
compliant provider may return only `access_token` and `token_type`. A token
response omitting `expires_in` is a credential failure unless
`assumedLifetimeSeconds` states the lifetime to credit. The runtime never
infers a lifetime from the token, and the credited lifetime is still clamped by
`maximumCacheSeconds`.

Secret files are byte strings, not base64 fields. Do not base64-encode the
audit or subject-binding key unless those encoded ASCII bytes are intentionally
the key. Generate independent random values of at least 32 bytes and store the
raw bytes in their owner-only files. Source usernames, passwords, tokens,
client ids, and client secrets use their provider-defined lexical form and the
runtime's generic secret bounds. A `clientAssertionKeyRef` file instead holds
the JSON private JWK itself, including its `alg` and `kid`.

For inbound access tokens, `tokenTypes: [at+jwt]` requires a protected JWT
header with `typ: at+jwt`; `application/at+jwt` requires that exact alternative.
A sanitized shape for the reference projects is:

```json
{"alg":"ES256","kid":"issuer-owned-key-id","typ":"at+jwt"}
{"iss":"https://identity.example","aud":"registry-evidence","iat":1999999700,"exp":2000000000,"sub":"service-client","evidence_tags":["approved-requester"],"evidence_audience":"https://consumer.example"}
```

These are decoded shapes, not usable tokens. The configured issuer, audience,
algorithm, token type, principal claim, requester-tag claim, and evidence
audience claim must all match. Grant-derived selectors additionally require
the configured grant id and authority claims.

### Request

This is the `request` an `http-json` source declares. A `sqlite-extract`
source declares the statement request in
[Statement request](#statement-request) instead.

```yaml
request:
  method: POST
  path: /v1/search
  fixedHeaders:
    - {name: Accept, value: application/fhir+json}
    - {name: X-API-Version, value: "2026-01"}
  selectorInputs:
    - role: subject
      alternatives:
        - {profile: record-reference-v1, fields: [record_reference]}
  prepareScript: adapters/source-a-prepare.rhai
  adapterParameters: {resultLimit: 2}
  adapterParametersSchema: schemas/source-a-parameters.schema.yaml
  preparationLimits:
    query: forbidden
    jsonBody: required
    maximumJsonDepth: 12
    maximumCollectionItems: 32
    maximumStringBytes: 512
    maximumNormalizedBytes: 8192
  projection:
    - /total
    - /results/*/status
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
```

| Key | Required | Meaning |
|---|---|---|
| `method` | yes | Fixed `GET` or `POST`. |
| `path` | conditional | Fixed absolute path. Exactly one of `path` or `pathTemplate` is required. |
| `pathTemplate` | conditional | Fixed absolute path with complete-segment placeholders resolved by Rust. |
| `pathBindings` | with template | Closed tagged placeholder bindings from an authorized selector, or on fetch only from a scalar prior fact. |
| `fixedHeaders` | no | Ordered non-secret constants. Names are unique after ASCII case folding. |
| `selectorInputs` | yes | Exact minimized authorized selector alternatives visible to `prepare`; an empty array is valid only for a fetch source. |
| `prepareScript` | yes | Bundle-relative Rhai script implementing `prepare/2`. |
| `adapterParameters` | yes | Closed non-secret JSON parameters shared by preparation and extraction. `{}` is valid. |
| `adapterParametersSchema` | yes | Closed bundle-relative JSON Schema for those parameters. |
| `preparationLimits` | yes | Per-channel policy and stricter output bounds. |
| `projection` | yes | Non-empty Rust-enforced response allowlist defined by `ADAPTER-API.md`. |
| `redirects` | yes | Exactly `deny` in Version 1. |
| `timeoutMilliseconds` | yes | Positive source-request timeout within the global ceiling. |
| `maximumResponseBytes` | yes | Positive pre-projection response limit within the global ceiling. |
| `concurrencyLimit` | yes | Positive per-source request concurrency limit. |

Fixed headers cannot set authentication, host/routing, cookies, body framing,
content length/type, connection, forwarding, proxy, or tracing headers. Rust
sets `Content-Type: application/json` when a JSON body is present and owns all
authentication headers. Scripts cannot add, remove, or change a header.

Query components in `RequestParts` are lexical strings even if a provider
interprets them as numbers or booleans. Write query constants as `"2"` and
`"true"`. JSON body parameters retain JSON types, so body constants may be `2`
and `true`. Rust performs no implicit conversion.

### Path templates

Use a path template only when the provider lacks a safe query/body lookup:

```yaml
request:
  method: GET
  pathTemplate: /api/records/{record_reference}
  pathBindings:
    record_reference:
      from: selector
      role: subject
      profile: record-reference-v1
      field: record_reference
```

Each placeholder occupies one complete path segment and has exactly one tagged
binding. Rust reads `from: selector` directly from an already validated and
authorized selector. On a fetch source, `from: prior-fact` may instead name a
scalar property required by the search fact schema. Scripts do not choose path
binding origins or return path values. A value must be non-empty bounded
UTF-8 and cannot contain `/`, `\`, `%`, controls, `.` or `..`. Rust
percent-encodes it exactly once. Templates cannot contain a scheme, authority,
query, fragment, empty segment, or dot segment. Exact expanded-path fixtures
are required.

### Preparation limits

These are the preparation limits of an `http-json` request, whose output
channels are a query string and a JSON body. A statement request has neither,
so it bounds its own two-key preparation in
[Statement request](#statement-request).

`query` and `jsonBody` are independently `required`, `allowed`, or `forbidden`.
The remaining keys are optional stricter limits beneath the ABI hard ceilings:

| Key | Bounds |
|---|---|
| `maximumQueryPairs` | How many query pairs `prepare` returns. |
| `maximumQueryNameBytes` | Each query-pair name, measured before percent-encoding. |
| `maximumQueryValueBytes` | Each query-pair value, measured before percent-encoding. |
| `maximumJsonDepth` | Nesting depth of the JSON body. |
| `maximumCollectionItems` | Entries in each JSON body array and members in each JSON body object. |
| `maximumStringBytes` | Every string `prepare` returns: query names and values, and JSON body strings and object member names. |
| `maximumNormalizedBytes` | Serialized size of the query pairs and body together. |

`maximumStringBytes` applies to query names and values in addition to
`maximumQueryNameBytes` and `maximumQueryValueBytes`, so the smaller of the two
applicable bounds is the effective one. A returned value exceeding any bound
fails preparation, and no source request is made.

At least one output channel must be usable. `required` means non-empty. For a
JSON body, JSON `null` is absent; an empty object or array is present.

### Optional HTTP source batch

An `http-json` source whose ordinary request uses `path` may declare one
optimized call for a complete multi-subject request batch:

```yaml
acquisitionCapabilities: [source-batch]
sources:
  source-a:
    transport: http-json
    # ordinary baseUrl, posture, authentication, request, and schemas omitted
    batch:
      maximumItems: 16
      prepareScript: adapters/source-a-batch-prepare.rhai
      extractScript: adapters/source-a-batch-extract.rhai
      responseSchema: schemas/source-a-batch-response.schema.yaml
      projection: [/results/*/slot, /results/*/outcome, /results/*/facts]
```

| Key | Required | Meaning |
|---|---|---|
| `maximumItems` | yes | Integer 1 through 16. A larger outer request uses ordinary sequential execution from the start and is not split. |
| `prepareScript` | yes | Bundle-relative script implementing `prepare_batch(items, {parameters})`. |
| `extractScript` | yes | Bundle-relative script implementing `extract_batch(response, {parameters, slots})`. |
| `responseSchema` | yes | Closed schema applied after the batch projection and before batch extraction. |
| `projection` | yes | Non-empty extended JSON Pointer allowlist under the ordinary projection and 65,536-byte input bounds. |

This block carries no transport authority. It reuses the ordinary method,
origin, fixed path, authentication, headers, TLS trust, redirect denial,
timeout, response-byte limit, concurrency semaphore, adapter parameters, and
preparation limits. A batch block beside a path template, or without both
capability gates, is a startup error. Omitting the block on a path-template,
SQLite, or multi-stage path, or exceeding `maximumItems`, selects sequential
execution before any source I/O. Once an optimized attempt begins, no error
retries as sequential fanout.

`prepare_batch` receives ordered exact `{slot, selectors}` maps. `slot` is an
opaque Rust integer; `selectors` is the ordinary minimized source selector
object for that item. `extract_batch` returns exact `{slot, result}` maps where
`result` is the ordinary closed lookup union. Rust permits output reordering but
requires every supplied slot exactly once. Missing, duplicate, extra, negative,
non-integer, or out-of-range slots abort the outer request.

### Extract source

An extract is a published snapshot, not a live authoritative read. The
deployment answers from it because the publisher stated what it holds and when,
and the runtime carries that statement rather than inferring one.

Every extract carries the reserved `evidence_extract` metadata table, with the
columns `published_at`, `publisher`, and `extract_id` and exactly one row. A
file without that table, with any other row count, or with a value the runtime
cannot read is refused at startup, so a mis-published extract stops the process
rather than answering a request from it. The three values reach the statement
result as `publishedAt`, `publisher`, and `extractId` under `/extract`, and a
projection selects them the way it selects a row value.

The published instant is read from that table and never from the file's
modification time. An mtime records when a byte range last landed on this host.
That is an artifact of the filesystem the file was copied across, not a
statement by the publisher about the data inside.

`maximumExtractAgeSeconds` is bundle-declared because staleness tolerance is a
property of the concept being asserted rather than of the deployment. A snapshot
a month old is irrelevant to adult status, because a date of birth does not
change once recorded. It is material to professional licence status, because a
licence can be revoked on any day. The bundle is where that judgement was
reviewed, so the bundle is where it is written. The bound is inclusive and is
checked against the evaluation instant before any row is read.

```yaml
sources:
  source-b:
    transport: sqlite-extract
    # Only this aggregate crosses the source boundary.
    posture: source-derived
    extractProfile: reference-extract
    maximumExtractAgeSeconds: 604800
    request:
      statement: queries/source-b-lookup.sql
      columns:
        - {name: match_count, type: integer}
      selectorInputs:
        - role: subject
          alternatives:
            - {profile: record-reference-v1, fields: [record_reference]}
      parameterBindings:
        record_reference:
          kind: selector
          role: subject
          profile: record-reference-v1
          field: record_reference
      projection:
        - /rows/*/match_count
        - /extract/publishedAt
      maximumRows: 1
      maximumCellBytes: 256
      maximumStatementSteps: 100000
      timeoutMilliseconds: 2000
      maximumResponseBytes: 8192
      concurrencyLimit: 8
    responseSchema: schemas/source-b-response.schema.yaml
    extractScript: adapters/source-b-extract.rhai
    factSchema: schemas/source-b-facts.schema.yaml
```

with `queries/source-b-lookup.sql`:

```sql
SELECT COUNT(*) AS match_count
FROM records
WHERE reference = :record_reference;
```

and the operator's binding in `runtime.yaml`:

```yaml
sourceExtracts:
  reference-extract:
    path: /var/lib/registry-evidence/extracts/reference-2026-08-01.sqlite
```

That is the common case, and it declares no `prepareScript` and no
`preparationLimits`. It needs neither: `parameterBindings` already states where
every parameter comes from, so Rust resolves the authorized selector field and
binds the value with no script standing between the selector and the statement.

Beyond the shared keys, a `sqlite-extract` source declares:

| Key | Required | Meaning |
|---|---|---|
| `extractProfile` | yes | Logical extract name bound by `runtime.yaml` under `sourceExtracts`. The bundle never names a filesystem location. |
| `maximumExtractAgeSeconds` | yes | 1 through 2,592,000 seconds. |

The bound file must be a regular, non-symlink, read-only file, and read-only is
a correctness requirement rather than hygiene. The runtime opens the extract
with SQLite's `immutable=1`, which tells SQLite the bytes will not change while
the connection is open and lets it skip locking and journal replay. That flag is
sound only because the read-only check passed. A file the process or anything
else can still write makes the promise false, and an immutable connection over a
file that changes is undefined behaviour rather than a stale read, because
SQLite is entitled to trust pages it has already cached. Publish a new extract
as a new file, mount it read-only, and restart. Startup digests each bound file
into the runtime digest, so a replacement shows up in the digest instead of
passing silently.

Digesting the file and opening it are not the same moment: the bundle, the
kernel, and the audit log are read in between. Startup therefore checks once
more, after the connections are open, that the bound path still names the file
it digested, and refuses to start if it does not. A refresh that lands mid
startup fails the deployment instead of answering from bytes the runtime
revision does not name. That narrows the window rather than closing it, so
publishing to a new path and restarting remains the supported workflow.

Startup opens one connection for each `concurrencyLimit` permit, reads the
metadata, and runs the statement against the real extract. A statement whose
result columns disagree with `columns`, a parameter no binding supplies, and a
binding the statement never names all fail before the listener binds.
`evidencectl build` and `evidencectl fixtures run` reach this same statement
check earlier, without a mounted extract, through `evidence bundle-check`: an
internal Evidencectl seam hidden from `evidence --help`, not a command an
adopter runs directly. It settles that the artifact holds exactly one
statement, that the statement parses, and that the authorizer accepts it. It
cannot settle columns, parameters, metadata, or age, because only the extract
can. That check never reports a false failure, only an incomplete pass.

### Statement request

This is the `request` a `sqlite-extract` source declares.

| Key | Required | Meaning |
|---|---|---|
| `statement` | yes | Bundle-relative `queries/*.sql` artifact holding exactly one statement, hash-identified and reviewed with the bundle. |
| `columns` | yes | 1 through 64 declared result columns in result order. Names are unique, and each `type` is `string`, `integer`, `number`, or `boolean`. |
| `selectorInputs` | yes | Exact minimized authorized selector alternatives the bindings may draw on. `[]` is valid for a statement that binds no selector. |
| `parameterBindings` | no | At most 64 bindings, keyed by the parameter name the statement uses, each stating its one origin. Omission and `{}` are the same. |
| `prepareScript` | no | Bundle-relative Rhai script implementing `prepare/2`. Declared together with `preparationLimits`, and with at least one `prepared` binding, or not at all. |
| `adapterParameters` | no | Closed non-secret JSON constants, at most 64, read by the extraction script. |
| `adapterParametersSchema` | with parameters | Closed bundle-relative JSON Schema for those parameters, required as soon as `adapterParameters` is non-empty. |
| `preparationLimits` | with script | `maximumParameters` 1 through 64, never below the declared `prepared` binding count, and `maximumParameterValueBytes` 1 through 4,096. |
| `projection` | yes | 1 through 64 unique pointers of 2 through 256 bytes each, over `/rows` and `/extract`, using the allowlist defined by `ADAPTER-API.md`. It must preserve every declared row column; it may not narrow the SQL select list after execution. |
| `maximumRows` | yes | 1 through 256 rows. A statement matching more broadly than intended fails here rather than moving a bulk result into the runtime. |
| `maximumCellBytes` | yes | 1 through 65,536 bytes for one returned value. |
| `maximumStatementSteps` | yes | 1 through 1,000,000 virtual-machine steps. |
| `timeoutMilliseconds` | yes | 1 through 30,000 milliseconds. One absolute deadline covers concurrency admission, blocking-worker queueing, and statement execution. |
| `maximumResponseBytes` | yes | 1 through 1,048,576 bytes for the assembled result before projection. |
| `concurrencyLimit` | yes | 1 through 256 statements held against this extract at once. |

`maximumStatementSteps` and `timeoutMilliseconds` bound different things. The
timeout is one elapsed-time deadline across admission, blocking-worker queueing,
and execution. The step budget bounds work itself, so a statement that scans
more than the author expected is stopped on a fast host as well as a slow one.
Set both, and keep the outer request and acquisition ceilings no shorter than
the source work they admit.

`maximumCellBytes`, `maximumResponseBytes`, and `concurrencyLimit` are one
process-capacity decision, not independent validation knobs. Set them
conservatively against both publisher capacity and the Evidence process memory
budget.

Each `parameterBindings` entry is keyed by the parameter name as the statement
writes it, without its sigil, and Rust accepts `:name`, `@name`, and `$name`.
Positional parameters have no name to bind, so `?` reads as an undeclared
parameter and fails. Each entry is a closed tagged binding whose `kind` states
the one origin its value comes from.

A `kind: selector` binding is filled from an authorized selector field and from
nothing else, so a preparation script cannot stand in for an authorized value:

| Key | Required | Meaning |
|---|---|---|
| `kind` | yes | Exactly `selector`. |
| `role` | yes | Subject role the value comes from, which `selectorInputs` must declare. |
| `profile` | yes | Selector profile the value comes from, which must be an alternative that role declares. |
| `field` | yes | Exact field of that profile whose resolved value Rust binds. |

A `kind: prepared` binding is filled by `prepareScript` and by nothing else,
which is how a value no selector holds, such as a normalized reference or a
derived bound, reaches the statement:

| Key | Required | Meaning |
|---|---|---|
| `kind` | yes | Exactly `prepared`. The entry names no selector, because naming one would give the parameter a second origin. |

A parameter has one origin and exactly one, so reading the declared bindings is
enough to know where every value the statement binds came from. Four request-time
failures hold that line, each naming the statement artifact: the script returned
a value for a `selector` parameter, the script returned a name no binding
declares, the script returned the reserved `evidence_now` name, and the script
returned no value for a declared `prepared` parameter.

A `prepareScript` and a `prepared` binding exist for each other, and startup
refuses either half alone. A script with nothing prepared to fill could only ever
return a name the source refuses, and a `prepared` parameter with no script could
never be filled at all. `maximumParameters` is refused below the declared
`prepared` count for the same reason: a script allowed to return fewer parameters
than the source declares prepared can never fill them all.

A value reaches the statement only as a bound parameter. Nothing concatenates,
interpolates, or substitutes into the statement text, and a string, integer, and
boolean bind as SQLite text, integer, and integer 0 or 1 respectively. A null in
the extract is admitted for any declared column type; every other type mismatch
is a source-protocol failure rather than a coercion.

### Statement SQL

The statement is a reviewed, hash-identified bundle artifact, so it is allowed
to be a real query. Joins, `GROUP BY`, common table expressions, and window
functions are all in scope. Pushing aggregation down into SQL is a
minimum-disclosure win rather than a shortcut: `SELECT COUNT(*)` moves one
number across the source boundary, where fetching 500 rows so the extraction
script can count them moves 500 records. Declare the aggregate as the only
column, project it, and the script never observes a record at all.

That aggregate is `source-derived` on the same terms as an aggregate returned
by an API: it is the only fact that crossed the source boundary. Rhai may still
map it to the asserted concept.

Everything else is refused by the authorizer while the statement is prepared,
before a row is read: every write and every DDL statement, `ATTACH`, `DETACH`,
every `PRAGMA`, extension loading, transaction and savepoint control, and any
action the authorizer does not recognize. A file holding more than one statement
is refused, so a second statement cannot ride in behind a `;`.

These functions are denied by name:

```text
changes            current_date       current_time       current_timestamp
date               datetime           julianday          last_insert_rowid
load_extension     random             randomblob         sqlite_offset
strftime           time               timediff           total_changes
unixepoch
```

The time functions in that list are denied for one reason: the deployment has
exactly one clock, and it is the runtime's evaluation instant. Where the
statement names the reserved parameter `evidence_now`, Rust binds that instant
as fixed-width RFC 3339 UTC text in whole seconds, the same rendering the
assertion reports. A direct lexical comparison is correct only when the stored
column is restricted to that exact `YYYY-MM-DDTHH:MM:SSZ` form. General RFC
3339 text may contain fractional seconds, and a value such as
`2026-08-08T03:00:00.500Z` does not sort chronologically against the shorter
whole-second form. A bundle cannot bind the reserved name itself; startup
rejects a `parameterBindings` entry that uses it. One clock is
what makes a pinned fixture run reproduce exactly: the same extract and the
same pinned instant give the same rows on every run and on every host.

### Building an extract

An extract is an ordinary SQLite file, which is why the transport reads one. A
deployment whose authoritative data lives elsewhere converts it with tooling it
already has, and each of these is one command:

| Source | Path |
|---|---|
| CSV, Parquet, XLSX | DuckDB, reading the file and writing through `ATTACH '<file>' (TYPE sqlite)` |
| CSV, JSON | `sqlite-utils insert` |
| PostgreSQL, MySQL, SQL Server, Oracle | `db-to-sqlite`, or DuckDB's database scanners writing through the same `ATTACH` |
| An existing SQLite database | `sqlite3` with `.dump`, or `VACUUM INTO` for a consistent copy |

Publish the result the way the deployment publishes any reviewed artifact: add
the `evidence_extract` row, make the file read-only, and give it a name that
identifies the snapshot. Selecting only the columns an assertion needs at
conversion time is worth doing, because a column that is not in the extract
cannot be disclosed by any later mistake.

Publish one whole file. The immutable open that lets the runtime trust the
snapshot is also an open that skips SQLite's sidecars, so committed rows sitting
in a `-wal` would be read straight past, and a `-journal` left behind by a writer
that died mid-transaction would be read as though the rows it never committed
were real. Startup refuses an extract with either file beside it. `VACUUM INTO`
and `.dump` both produce a checkpointed single file, so a deployment following
the table above is already there; copying a directory, or globbing
`registry.db*`, is what lands in the refusal. Copying the main file alone out of
a database that is still being written leaves nothing beside it to find, which is
why this is an obligation on the publisher and not only a check.

The supported publication handoff is deliberately explicit because
`evidencectl` does not create, convert, approve, or publish extracts:

1. Build a new file on the publisher side. Do not edit the file currently
   mounted by Evidence.
2. Select only the columns the reviewed statements need. Where a statement
   compares timestamp text lexically with `evidence_now`, write the exact
   whole-second UTC form `YYYY-MM-DDTHH:MM:SSZ`.
3. Insert exactly one `evidence_extract` row with the publisher's publication
   instant, publisher identifier, and snapshot identifier.
4. Checkpoint into one main file with no `-wal` or `-journal`, using `VACUUM
   INTO`, or replay a `.dump` SQL script into a newly created database and then
   validate the resulting file and absence of sidecars. An equivalent
   publisher-controlled export is also valid.
5. Run the deployment project's fixtures against the same schema and statement
   contract. A source claiming `source-derived` must return only the narrow fact
   it declares, such as an aggregate rather than the records behind it.
6. Transfer the new file under a new versioned path, make it non-writable to the
   Evidence identity, update only the matching `runtime.yaml` binding, and
   restart. Never replace the bytes behind an open immutable connection.
7. Run `evidence check --require-runtime-dependencies` against the exact runtime
   and mounted extract. The check refuses an extract that is already older than
   its source permits. Then run every referenced fixture, real startup, and
   `/ready` before routing traffic.
   Retain the runtime revision and governed extract profile in the deployment
   record. Do not copy publisher-controlled metadata values into logs, audit,
   or error tickets.

### Requirement derivation selector inputs

`requirements[].derivation.selectorInputs` is optional. Omission means the
derivation receives an empty selector map. When present, every alternative must
be an exact subset of the selected requirement's declared subject roles and
profiles. This is independent of `request.selectorInputs`.

Rust supplies only that minimized map to `derive/3`. A relationship requirement
can retrieve a child record with a request-derived selector while comparing a
candidate reference obtained from an authenticated grant. The preparation
script never sees the candidate, and the derivation never sees the child's
lookup selector unless it explicitly declares it.

## Referenced bundle artifacts

All referenced paths are bundle-relative and captured in the immutable bundle
revision. Scripts end in `.rhai` and live under `adapters/` or `derivations/`.
Statements end in `.sql` and live under `queries/`; a statement is reviewed,
bounded, executable text, so it is bounded like a script rather than like a data
file. Parameter, fact, and reviewed-value schemas
are closed JSON Schema 2020-12 documents; fact and reviewed-value schemas close
every reachable object and bound every reachable string, array, and number.
Fixtures use the exact contract in [`FIXTURES.md`](FIXTURES.md).

Codelists under `codelists/` use one of two closed YAML shapes:

```yaml
# Exact code set
id: urn:gov:example:codelist:status
version: '1'
codes: [active, inactive]

# Exact source-to-output mapping
id: urn:gov:example:codelist:region-map
version: '1'
entries: {SOURCE-A: REGION-NORTH, SOURCE-B: REGION-SOUTH}
allowed_outputs: [REGION-NORTH, REGION-SOUTH]
```

Each document has 1 through 4,096 unique bounded codes. A mapping output must
appear in `allowed_outputs`. Referencing configuration repeats the exact
artifact version and startup rejects a mismatch. Active and temporarily
published service keys live under `public-keys/` as exact public P-256 JWK JSON
files. Private signing material is never a bundle artifact.

## Runtime configuration

`runtime.yaml` contains only process-local bindings:

```yaml
version: 1
bundleDirectory: /etc/registry-evidence/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: /run/secrets/registry-evidence
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles:
    government-internal-pki:
      caBundleFile: /etc/registry-evidence/ca/government-internal.pem
sourceExtracts:
  reference-extract:
    path: /var/lib/registry-evidence/extracts/reference-2026-08-01.sqlite
```

| Key | Required | Meaning and Version 1 bounds |
|---|---|---|
| `version` | yes | Literal integer `1`. |
| `bundleDirectory` | yes | Absolute path to the single governed bundle directory. No alternate, overlay, or fallback bundle exists. |
| `listener.bindHost` | yes | Numeric listener address, 2 through 64 bytes. Under the default `private-address` exposure, only loopback, RFC 1918 private IPv4, or RFC 4193 unique-local IPv6 is accepted. Under explicit `container-private`, unspecified IPv4 or IPv6 wildcard is also accepted. Hostnames, concrete public addresses, and multicast are always rejected. |
| `listener.networkExposure` | no | `private-address` by default. `container-private` permits a wildcard bind only when the operator confines the container network and terminates TLS upstream. It does not enable direct public exposure. |
| `listener.port` | yes | TCP port 1 through 65535. |
| `listener.tlsTermination` | yes | Literal `operator-controlled-upstream`. |
| `listener.trustProxyIdentityHeaders` | yes | Literal `false`; proxy headers never supply authenticated identity or authority. |
| `listener.maximumRequestBytes` | yes | 1,024 through 1,048,576 bytes. |
| `listener.maximumConcurrentRequests` | yes | 1 through 4,096. |
| `listener.requestTimeoutMilliseconds` | yes | 1 through 30,000 milliseconds for admission, concurrency queueing, and request-body collection. Once protected evaluation starts, this timer does not cancel it; source and OIDC boundaries have their own bounds, and the runtime preserves fail-closed audit and release ordering. |
| `listener.shutdownGraceMilliseconds` | yes | 1 through 120,000 milliseconds. |
| `metricsListener` | no | Optional operator-only telemetry listener serving `GET /metrics`, a binding separate from the evidence listener above and absent from the public evidence contract. Absence is the default and serves no metrics endpoint. `bindHost` accepts only loopback, RFC 1918 private IPv4, or RFC 4193 unique-local IPv6, and `bindHost`/`port` together must not repeat the evidence listener's exact binding. |
| `secretProviders.file.root` | yes | Absolute root for logical `secret:file/...` references. Only regular, non-symlink, single-link files owned by the service identity with exact mode `0400` or `0600` are accepted. |
| `signer` | yes | Closed runtime signer union. `production` and `evidence-grade` require a pinned Transit signer over a workload-local Unix socket. `local` requires `kind: local-jwk` with `privateKeyRef: secret:file/evidence-signing`. Startup validates provider controls and exact public-key agreement, then signs and verifies a challenge. |
| `auditStorage.path` | yes | Absolute keyed-JSONL audit path on operator-owned durable storage. |
| `auditStorage.maximumFileBytes` | yes | 1,048,576 through 1,099,511,627,776 bytes. Reaching the bound seals the active segment under an ascending sequence number and opens a fresh empty segment at the configured path for subsequent writes; sealed segments are never deleted. A write or sync failure, not rotation itself, is what fails closed. |
| `outboundTls.systemRoots` | yes | Literal `true`. |
| `outboundTls.trustProfiles` | yes | Closed map of at most 64 logical profile ids. It may be empty when no source names a private trust profile. |
| `outboundTls.trustProfiles.<id>.caBundleFile` | for each profile | Absolute path to one bounded PEM CA file. Profile names must exactly match bundle `tlsTrustProfile` references. |
| `sourceExtracts` | no | Closed map of at most 64 logical extract names. Omission binds none, which is what a runtime file for a bundle with no extract source says. |
| `sourceExtracts.<name>.path` | for each name | Absolute path to one read-only regular file. Names must exactly match bundle `extractProfile` references. |
| `acquisitionCapabilities` | no | Gated acquisition kinds and source optimizations this deployment enables, at most two entries: `search-then-fetch-set` and `source-batch`. Omission and `[]` both enable nothing, so a bundle carrying a source batch block or needing a gated kind is refused before the listener binds. |

`bundleDirectory`, secret roots, audit destinations, and CA files must be
absolute paths. The runtime rejects symlinks, insecure ownership/modes, missing
required logical bindings, mutable files, and files outside the configured
roots according to the operator contract.

Every deployment input this contract loads, `runtime.yaml` itself, the bundle
directory and each artifact inside it, a named CA bundle file, the secret
root, and a bound extract, must carry no write permission for anyone but its
owner, and the secret root must additionally carry no group or other
permission at all. `evidence check` and process startup both refuse a
non-conforming runtime file, bundle artifact, CA bundle file, or secret root
before the listener binds, with the message `an Evidence deployment input is
not immutable: artifact <name>: <cause>` (for example `the runtime file is
writable` for `runtime.yaml` itself, or `the secret root directory the
runtime file names is reachable by group or other`). A writable bound
extract instead fails a distinct check, `an Evidence bundle artifact is
invalid: the source extract the runtime file names is writable`. Startup
collapses each to its own fixed failure class; `evidence check` is what names
the artifact and cause either way. Write `runtime.yaml`, make it
non-writable (for example `chmod 400`), and run `evidence check` before
`evidence serve`.

A bundle source may name one `tlsTrustProfile`. The corresponding bounded PEM
file is loaded and validated at startup. Hostname verification and source-origin
checks remain mandatory. There is no `insecure`, `skipVerification`, or
`trustAll` setting. Changing a trust file requires restart and changes the
runtime digest.

A bundle source that reads an extract names one `extractProfile` and never a
filesystem location, so the operator decides where the file sits without
editing reviewed material. Each bound file must be a regular, non-symlink,
read-only file. Read-only is a correctness requirement rather than hygiene: the
statement executor opens the file as immutable, and an immutable connection
over a file that can change is undefined behaviour. Startup digests each file
without reading it into memory and folds that digest into the runtime digest,
so replacing an extract requires restart and changes the digest. Startup
refuses a profile the bundle names and the runtime does not bind, and a profile
the runtime binds and no source reads, naming the profile in each case.

Version 1 has no application-level HTTP proxy and ignores `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`. Deployments needing mediated egress
use network routing or a local sidecar while preserving end-to-end source TLS
verification. This avoids ambient environment state silently redirecting
credentials to another authority.

## Maintenance rules

- Keep scripts small and provider-shaped. Extraction, not Rust, validates
  provider count/collection consistency and maps it to the closed lookup union.
- Reuse one script across sources when the selector role and provider shape can
  be parameterized without adding a string expression language.
- Do not add a declarative uniqueness or response-mapping DSL. Reviewed Rhai is
  the escape hatch for API differences.
- Prefer literal map/array traversal. Dots in provider keys are literal. If a
  deployment must parameterize a nested path, pass a bounded array of literal
  segments and implement a bounded same-file helper.
- Keep one complete governed bundle and runtime target per environment. Never
  use overlays, symlinks, environment variables, or command arguments to
  override governed fields.
- Run every fixture before accepting either input and again before deploying a
  changed bundle, runtime file, script, schema, codelist, CA file, or secret
  binding.

## Authoring and production-build workflow

Treat an editable project like reviewed source code. The OpenAPI form of
`evidencectl new` creates empty authoring directories. The `--transport
sqlite-extract` form creates a source-neutral synthetic statement, source,
schemas, question, derivation, and fixture that can run immediately with
`evidencectl fixtures run --project <dir> --explain`. Both forms create
owner-only disposable local P-256 Evidence signing material plus distinct audit
and subject-binding masters. Neither creates deployment input or a real
extract. `evidencectl dev` creates session-scoped P-256 Mint, caller, and holder
keys automatically for HTTP-source local sessions.
While authoring, use only synthetic responses and selectors. Add the smallest
provider-shaped `prepare/2`, `extract/2`, and requirement `derive/3` scripts,
then add exact positive, legitimate-false, boundary, unresolved,
malformed-provider, transport-failure, and privacy-canary cases.

The compact local question format may omit `governance`. When it is present,
local development uses the declared requirement semantics but retains its
explicit local assurance and authentication. A production build requires that
block, stable concept identifiers, and exactly one project-relative
`fixtures/<name>.yaml` regular file for every question. It never derives or
invents requirement, framework, Evidence Type, concept, or disclosure-family
URIs.

The compact question may also declare `responseFormats: [signed-jws,
sd-jwt-vc]`. Omission means `[signed-jws]`; signed JWS is mandatory, entries are
unique, and no other format is accepted in this authoring surface. Local
development compiles the list into both the bundle ceiling and that question's
local grant. A reviewed structured answer with an `sdJwtVc` projection must
declare `sd-jwt-vc`; scalar and unprojected answers may declare it to use the
profile's one root disclosure. Production response-format authority still
comes only from the complete deployment-target governance and its exact
authority grants.

Create explicit `deployment-targets/<environment>/` directories containing
complete `governance.yaml` and `runtime.yaml` documents plus every governed
public JWK referenced by governance under `public-keys/`. `governance.yaml` is
closed, has `version: 1`, and supplies the existing bundle-shaped service,
issuer, authentication, audit, subject-binding, rate-limit, signing,
response-format, and authority-profile values. It may not contain selectors,
sources, or requirements, which the compiler obtains from the editable
project. It permits logical `secret:file/<name>` references only, never secret
values or absolute secret paths. `runtime.yaml` is the ordinary closed runtime
document; the build copies its bytes unchanged and the target host remains
authoritative for path, owner, permission, secret, private-CA, and Transit
validation. Staging and production are separate complete targets built from
the same reviewed source revision. They are not overlays and do not inherit
from each other. Ready-to-copy layouts and Transit proxy-policy examples are
under [`../../deployment-targets/`](../../deployment-targets/).

Run the create-only compiler with explicit target and output paths:

```sh
evidencectl build \
  --project <editable-project> \
  --target <editable-project>/deployment-targets/<environment> \
  --output <new-candidate-directory>
```

The compiler follows no authored symlink, accepts no reference outside allowed
project directories, rejects unreferenced generated artifacts, and removes only
its own failed private staging. It requires authenticated HTTPS for HTTP
sources and a governed extract profile for every SQLite source,
complete authority, resolved review markers, complete governance, governed
public keys, and complete fixtures. It delegates its internal bundle-only check
and every fixture to the real `evidence` binary without generating a temporary
signing key or other validation secret, and publishes nothing on failure. It
makes no identity-provider, source-data, or Mint call; opens no listener; and
writes no production audit event. The editable project and `.evidence` local
state remain unchanged.

The candidate contains `runtime.yaml` and `bundle/`, including only referenced
adapters, derivations, schemas, codelists, fixtures, and public keys. Given
identical authoring files, target governance, runtime bytes, and toolset
release, bundle bytes and revision are identical. The copied runtime is
environment-specific and has its own revision; it is not part of the bundle
revision or signed `configurationRevision`.

The bundle revision identifies the whole reviewed bundle and is what an operator
records at approval. A signed `configurationRevision` is narrower: it covers
only the configuration and artifacts one requirement depends on. Editing a
requirement, its source, one of its selector profiles, an authority grant naming
it, or any script, schema, codelist, or fixture file those reach changes that
requirement's revision. Retired public verification keys stay in every
requirement's closure, so key rollover still changes every revision. An edit
outside a requirement's closure leaves its revision unchanged, so it does not
force every relying party to re-review.

After approval, transfer the exact candidate, provision independent owner-only
secrets under the configured secret root, make bundle and runtime non-writable
to the service identity, and run the grouped handoff once whenever candidate
bytes, runtime bindings, trust files, or secrets change:

```sh
evidencectl doctor --project '<candidate>'
evidencectl fixtures run --project '<candidate>'
evidence --runtime '<candidate>/runtime.yaml' check --require-runtime-dependencies
evidence --runtime '<candidate>/runtime.yaml' serve
```

Then route only after `/ready`, retain one authorized synthetic-subject
response, verify it under independently prepared production policy and trusted
keys, and verify the audit chain. A provider API or governance change produces
a newly reviewed bundle revision and reruns the fixture matrix.

When no suitable OIDC issuer exists, author Mint separately and run
`mint check --config <mint.yaml>`. The optional
`evidencectl doctor --project <candidate> --mint-config <mint.yaml>` check is
read-only: it compares issuer, derived JWKS URI, audiences, allowed signing
algorithm, `at+jwt` admission, and configured principal, requester-tag,
evidence-audience, grant-id, grant-authority, and optional actor claim names.
It does not infer legal basis, create authority profiles, register callers, or
copy Mint configuration into the candidate. Mint's replay cache is memory-only
and clears on restart; Version 1 makes no multi-instance or high-availability
claim.

Docker Compose is a documented adapter rather than build output. It mounts the
candidate bundle unchanged and read-only; mounts a distinct container runtime,
secrets, and persistent audit storage separately; binds Evidence privately; and
keeps TLS and public routing operator-controlled. The Compose runtime has its
own revision while assertions continue to carry their unchanged per-requirement
configuration revisions.
When Mint shares that network, retain its public HTTPS issuer and JWKS URI;
internal plain-HTTP service names do not replace them.

After those checks, publish the static token-acquisition, legal context,
endpoint-trust, and verifier guidance for each approved consumer class using
the workflow in
[`OPERATOR-CONTRACT.md`](../../../OPERATOR-CONTRACT.md#discovery-of-available-evidence).
The consumer then calls authenticated `GET /v1/evidence-definitions` and uses
one returned complete requirement, purpose, concept, role, selector, and value
origin shape. The endpoint does not publish the whole bundle, source internals,
authority tags, secrets, selector values, or unrelated definitions. A change
to an offered contract changes that definition's returned
`configurationRevision` and needs a coordinated rollout with the relying parties
consuming that requirement; clients do not infer alternatives from runtime
errors.

## Complete key-path inventory

Every key path the frozen contracts define, in one machine-checked list. A
property is written `name`, an array item `name[]`, and a map value `name.*`.
A recursive definition, currently only nested adapter parameter values, appears
once at the point it re-enters itself. A key path only one alternative declares
still appears once, so the `sources.*` entries cover both transports together
and no single source writes all of them.

`products/evidence/scripts/check-config-key-paths.sh` fails when either block
and its contract disagree in either direction, so a key added to a contract
cannot ship without a line here, and a line here cannot outlive its key. The
blocks are generated. After changing a contract, run
`products/evidence/scripts/check-config-key-paths.sh --write`, review the diff,
and document the new keys in the prose above.

### `bundle/evidence.yaml`

<!-- evidence-bundle-key-paths:start -->
```text
acquisitionCapabilities
acquisitionCapabilities[]
assuranceProfile
audit
audit.failClosed
audit.format
audit.hashKeyVersion
audit.hashSecretRef
authentication
authentication.actorClaim
authentication.algorithms
authentication.algorithms[]
authentication.audiences
authentication.audiences[]
authentication.evidenceAudienceClaim
authentication.grantAuthorityClaim
authentication.grantIdClaim
authentication.issuer
authentication.jwksUri
authentication.kind
authentication.maximumTokenLifetimeSeconds
authentication.principalClaim
authentication.requesterTagsClaim
authentication.revokedKeyIds
authentication.revokedKeyIds[]
authentication.tokenTypes
authentication.tokenTypes[]
authorityProfiles
authorityProfiles.*
authorityProfiles.*.grants
authorityProfiles.*.grants[]
authorityProfiles.*.grants[].audienceFrom
authorityProfiles.*.grants[].purpose
authorityProfiles.*.grants[].requirement
authorityProfiles.*.grants[].responseFormats
authorityProfiles.*.grants[].responseFormats[]
authorityProfiles.*.grants[].subjectBindingModes
authorityProfiles.*.grants[].subjectBindingModes[]
authorityProfiles.*.grants[].subjects
authorityProfiles.*.grants[].subjects[]
authorityProfiles.*.grants[].subjects[].role
authorityProfiles.*.grants[].subjects[].selectorProfile
authorityProfiles.*.grants[].subjects[].valueClaims
authorityProfiles.*.grants[].subjects[].valueClaims.*
authorityProfiles.*.grants[].subjects[].valueOrigin
authorityProfiles.*.kind
authorityProfiles.*.requesterTags
authorityProfiles.*.requesterTags[]
holderBoundBatchMaxSize
issuer
issuer.id
publication
publication.description
publication.endpointUrl
publication.jurisdictions
publication.jurisdictions[]
publication.operatorId
publication.publisherId
publication.serviceId
publication.title
rateLimits
rateLimits.burstPerPrincipal
rateLimits.failedSelectorAttemptsPerPrincipalAuthorityPerMinute
rateLimits.requestsPerPrincipalPerMinute
requirements
requirements[]
requirements[].acquisition
requirements[].acquisition.fetch
requirements[].acquisition.fetch[]
requirements[].acquisition.fetch[].factInputs
requirements[].acquisition.fetch[].factInputs[]
requirements[].acquisition.fetch[].source
requirements[].acquisition.kind
requirements[].acquisition.maximumAcquisitionMilliseconds
requirements[].acquisition.search
requirements[].acquisition.source
requirements[].concepts
requirements[].concepts[]
requirements[].concepts[].constraints
requirements[].concepts[].constraints.bucketScheme
requirements[].concepts[].constraints.categoryScheme
requirements[].concepts[].constraints.codelist
requirements[].concepts[].constraints.codelistVersion
requirements[].concepts[].constraints.maximum
requirements[].concepts[].constraints.maximumBytes
requirements[].concepts[].constraints.maximumItems
requirements[].concepts[].constraints.maximumScale
requirements[].concepts[].constraints.maximumSerializedBytes
requirements[].concepts[].constraints.minimum
requirements[].concepts[].constraints.minimumItems
requirements[].concepts[].constraints.schema
requirements[].concepts[].constraints.schemeVersion
requirements[].concepts[].constraints.unique
requirements[].concepts[].form
requirements[].concepts[].handle
requirements[].concepts[].id
requirements[].concepts[].required
requirements[].concepts[].sdJwtVc
requirements[].concepts[].sdJwtVc.claim
requirements[].concepts[].sdJwtVc.disclosure
requirements[].derivation
requirements[].derivation.parameters
requirements[].derivation.parameters.*
requirements[].derivation.parameters.*.type
requirements[].derivation.parameters.*.value
requirements[].derivation.parameters.*[]
requirements[].derivation.parameters.*[].code
requirements[].derivation.parameters.*[].maximumExclusive
requirements[].derivation.parameters.*[].maximumExclusive.type
requirements[].derivation.parameters.*[].maximumExclusive.value
requirements[].derivation.parameters.*[].minimumInclusive
requirements[].derivation.parameters.*[].minimumInclusive.type
requirements[].derivation.parameters.*[].minimumInclusive.value
requirements[].derivation.script
requirements[].derivation.selectorInputs
requirements[].derivation.selectorInputs[]
requirements[].derivation.selectorInputs[].alternatives
requirements[].derivation.selectorInputs[].alternatives[]
requirements[].derivation.selectorInputs[].alternatives[].fields
requirements[].derivation.selectorInputs[].alternatives[].fields[]
requirements[].derivation.selectorInputs[].alternatives[].profile
requirements[].derivation.selectorInputs[].role
requirements[].disclosureGuard
requirements[].disclosureGuard.families
requirements[].disclosureGuard.families[]
requirements[].evidenceType
requirements[].existenceDisclosure
requirements[].fixtures
requirements[].handle
requirements[].id
requirements[].kind
requirements[].observationTimezone
requirements[].purposes
requirements[].purposes[]
requirements[].referenceFrameworks
requirements[].referenceFrameworks[]
requirements[].subjectBinding
requirements[].subjectRoles
requirements[].subjectRoles[]
requirements[].subjectRoles[].cardinality
requirements[].subjectRoles[].role
requirements[].subjectRoles[].selectorProfiles
requirements[].subjectRoles[].selectorProfiles[]
requirements[].validitySeconds
responseFormats
responseFormats[]
selectorProfiles
selectorProfiles.*
selectorProfiles.*.fields
selectorProfiles.*.fields.*
selectorProfiles.*.fields.*.codelist
selectorProfiles.*.fields.*.codelistVersion
selectorProfiles.*.fields.*.maximum
selectorProfiles.*.fields.*.maximumBytes
selectorProfiles.*.fields.*.minimum
selectorProfiles.*.fields.*.minimumBytes
selectorProfiles.*.fields.*.type
selectorProfiles.*.maximumAggregateBytes
service
service.providerId
service.publicOrigin
service.trustDomain
signing
signing.activePublicJwkFile
signing.algorithm
signing.format
signing.jwksPath
signing.maximumAssertionValiditySeconds
signing.publishedPublicJwkFiles
signing.publishedPublicJwkFiles[]
signing.revokedKeyIds
signing.revokedKeyIds[]
signing.verifierClockSkewSeconds
sources
sources.*
sources.*.authentication
sources.*.authentication.assumedLifetimeSeconds
sources.*.authentication.audience
sources.*.authentication.clientAssertionAudience
sources.*.authentication.clientAssertionKeyRef
sources.*.authentication.clientIdRef
sources.*.authentication.clientSecretRef
sources.*.authentication.credentialPlacement
sources.*.authentication.headerName
sources.*.authentication.kind
sources.*.authentication.maximumCacheSeconds
sources.*.authentication.passwordRef
sources.*.authentication.scheme
sources.*.authentication.scope
sources.*.authentication.tokenEndpoint
sources.*.authentication.tokenRef
sources.*.authentication.usernameRef
sources.*.authentication.valueRef
sources.*.baseUrl
sources.*.batch
sources.*.batch.extractScript
sources.*.batch.maximumItems
sources.*.batch.prepareScript
sources.*.batch.projection
sources.*.batch.projection[]
sources.*.batch.responseSchema
sources.*.extractProfile
sources.*.extractScript
sources.*.factSchema
sources.*.maximumExtractAgeSeconds
sources.*.posture
sources.*.request
sources.*.request.adapterParameters
sources.*.request.adapterParameters.*
sources.*.request.adapterParameters.*.*
sources.*.request.adapterParameters.*[]
sources.*.request.adapterParametersSchema
sources.*.request.columns
sources.*.request.columns[]
sources.*.request.columns[].name
sources.*.request.columns[].type
sources.*.request.concurrencyLimit
sources.*.request.fixedHeaders
sources.*.request.fixedHeaders[]
sources.*.request.fixedHeaders[].name
sources.*.request.fixedHeaders[].value
sources.*.request.maximumCellBytes
sources.*.request.maximumResponseBytes
sources.*.request.maximumRows
sources.*.request.maximumStatementSteps
sources.*.request.method
sources.*.request.parameterBindings
sources.*.request.parameterBindings.*
sources.*.request.parameterBindings.*.field
sources.*.request.parameterBindings.*.kind
sources.*.request.parameterBindings.*.profile
sources.*.request.parameterBindings.*.role
sources.*.request.path
sources.*.request.pathBindings
sources.*.request.pathBindings.*
sources.*.request.pathBindings.*.field
sources.*.request.pathBindings.*.from
sources.*.request.pathBindings.*.profile
sources.*.request.pathBindings.*.role
sources.*.request.pathTemplate
sources.*.request.preparationLimits
sources.*.request.preparationLimits.jsonBody
sources.*.request.preparationLimits.maximumCollectionItems
sources.*.request.preparationLimits.maximumJsonDepth
sources.*.request.preparationLimits.maximumNormalizedBytes
sources.*.request.preparationLimits.maximumParameterValueBytes
sources.*.request.preparationLimits.maximumParameters
sources.*.request.preparationLimits.maximumQueryNameBytes
sources.*.request.preparationLimits.maximumQueryPairs
sources.*.request.preparationLimits.maximumQueryValueBytes
sources.*.request.preparationLimits.maximumStringBytes
sources.*.request.preparationLimits.query
sources.*.request.prepareScript
sources.*.request.projection
sources.*.request.projection[]
sources.*.request.redirects
sources.*.request.selectorInputs
sources.*.request.selectorInputs[]
sources.*.request.selectorInputs[].alternatives
sources.*.request.selectorInputs[].alternatives[]
sources.*.request.selectorInputs[].alternatives[].fields
sources.*.request.selectorInputs[].alternatives[].fields[]
sources.*.request.selectorInputs[].alternatives[].profile
sources.*.request.selectorInputs[].role
sources.*.request.statement
sources.*.request.timeoutMilliseconds
sources.*.responseSchema
sources.*.tlsTrustProfile
sources.*.transport
sources.*.unresolvedProblem
sources.*.unresolvedProblem.code
sources.*.unresolvedProblem.status
sources.*.unresolvedProblem.type
subjectBinding
subjectBinding.keyVersion
subjectBinding.secretRef
version
```
<!-- evidence-bundle-key-paths:end -->

### `runtime.yaml`

<!-- evidence-runtime-key-paths:start -->
```text
acquisitionCapabilities
acquisitionCapabilities[]
auditStorage
auditStorage.maximumFileBytes
auditStorage.path
bundleDirectory
listener
listener.bindHost
listener.maximumConcurrentRequests
listener.maximumRequestBytes
listener.networkExposure
listener.port
listener.requestTimeoutMilliseconds
listener.shutdownGraceMilliseconds
listener.tlsTermination
listener.trustProxyIdentityHeaders
metricsListener
metricsListener.bindHost
metricsListener.port
outboundTls
outboundTls.systemRoots
outboundTls.trustProfiles
outboundTls.trustProfiles.*
outboundTls.trustProfiles.*.caBundleFile
secretProviders
secretProviders.file
secretProviders.file.root
signer
signer.keyName
signer.keyVersion
signer.kind
signer.mount
signer.privateKeyRef
signer.timeoutMilliseconds
signer.unixSocketPath
sourceExtracts
sourceExtracts.*
sourceExtracts.*.path
version
```
<!-- evidence-runtime-key-paths:end -->
