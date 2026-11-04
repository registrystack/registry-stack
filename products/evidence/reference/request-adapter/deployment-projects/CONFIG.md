# Evidence Version 1 configuration reference

Status: Implemented Version 1 configuration contract

Evidence captures its closed inputs before serving:

1. `bundle/evidence.yaml` and its referenced package files define governed
   assertion behavior and source contracts.
2. `runtime.yaml` binds that package to one process, filesystem, listener, audit
   destination, secret mount, signer transport and pinned version, and local
   TLS trust files.
3. A normalized project package requires the separately activated target
   authority selected by `runtime.authority`. The runtime validates its project,
   target, exact package digest and complete grant ceilings, then retains one
   immutable snapshot for the process lifetime.

The package and runtime file are reviewed, validated completely before readiness,
mounted read-only, and immutable for the process lifetime. Authority activation
prepares a controlled restart; it does not reload a serving process. Evidence
verifies the package and computes its stable digest at startup; audit events carry that
digest in the frozen `bundleRevision` field. Runtime configuration is not an override layer. It cannot
change a source origin, request, credential kind, requirement, authority,
selector, disclosure rule, rate limit, signing policy, or audit fail-closed
policy.

Unknown keys are rejected at every level. All names below are exact and
case-sensitive unless the field explicitly says otherwise.

Every URL member (`service.publicOrigin`, `publication.endpointUrl`,
`authentication.oidc.issuer`, `authentication.oidc.jwksSource.uri`, and each
source or source connection `baseUrl`) is an absolute `http` or `https` URL
with a host, no user information, and at most 2048 characters, the shared URL
type the schemas name `Url`. The narrower rules each member states below then
apply. `package.expectedDigest` is the shared digest type `Digest`: `sha256:`
followed by 64 lowercase hex digits.

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
evidencectl package <project> --target <target> --output <candidate>
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

Decide compatibility before binding an Adapter pack. A live provider must:

- expose a bounded lookup at a fixed origin over HTTPS, except numeric loopback
  HTTP used only by deterministic local tests;
- accept one fixed `GET` or `POST` and return JSON with media type
  `application/json` or `application/graphql-response+json`;
- let one response distinguish zero, one, and multiple matches, either through
  a trustworthy total count plus at most one minimized result, or through a
  caller-controlled hard result limit of at least two;
- fit a closed Adapter route whose complete endpoint set, operation graph,
  bounded retries, and final facts are reviewable before startup;
- support a query/body/path lookup narrow enough that Evidence does not fetch
  a broad candidate set; and
- provide the complete facts and relationship-set completeness needed by the
  requirement, or expose a governed intermediary that does.

An unbounded array without a trustworthy count or hard result limit is not
adaptable. Neither is a provider that requires broad retrieval and local
candidate selection. Use or build a governed bounded-lookup facade rather than
weakening the no-matcher boundary. A snapshot provider may instead use a pinned
SQLite route when it can publish immutable data and authoritative publication
metadata; runtime then binds the reviewed route to one captured read-only
extract.

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
| `apiVersion` | yes | Names the bundle grammar. The value is `id.registrystack.org/formats/evidence/bundle/v1`; the runtime refuses any other value at startup. |
| `kind` | yes | Names the document type. The value is `EvidenceBundle`. |
| `project` | normalized packages | Stable EvidenceProject identifier. The package carries an empty `authorityProfiles` map, and each definition declares complete grant and representation ceilings. Target authority is activated separately for this project and exact package digest. |
| `assuranceProfile` | yes | Explicitly `local`, `production`, or `evidence-grade`. Runtime configuration cannot override it. |
| `service` | yes | Evidence provider identity and trust domain. |
| `issuer` | yes | Issuer identity placed in evidence. |
| `authentication` | yes | Closed inbound OIDC access-token verification policy. |
| `audit` | yes | Audit pseudonymization key reference and version. Every audit gate is fail closed; the audit destination is runtime-owned. |
| `subjectBinding` | yes | Subject-binding key reference/version. The key is the same whichever binding mode a requirement selects; the modes are domain-separated inside the derivation. |
| `rateLimits` | yes | Governed anti-enumeration and request limits. |
| `signing` | yes | Evidence/JWS format, algorithm, key references, validity, JWKS path, and rollover policy. |
| `responseFormats` | no | Response formats the whole deployment permits. Omission means `[signed-jws]`. Declare it explicitly in production bundles. |
| `maximumHolderBoundBatchSize` | no | Ceiling of 1 through 16 on how many assertions one holder-bound release may carry. Omission means 1, so a bundle written before batch release cannot serve a batch. |
| `selectorProfiles` | yes | Closed caller/grant/context selector shapes. |
| `sourceConnections` | no | Reviewed non-secret endpoint, authentication-authority, client-identity, and trust policy for each named source connection. Runtime material must match it exactly. |
| `sources` | yes | Digest-pinned Adapter pack and Evidence route bindings, authorized selector-to-input projections, acquisition posture, and facts schema. |
| `authorityProfiles` | yes | Empty for normalized project packages. Otherwise the compiled bundle authority profiles. Normalized runtime authority comes only from the activated target snapshot. |
| `requirements` | yes | Evidence semantics, source, derivation, concepts, fixtures, and disclosure family. |

A bundle written with the earlier `version: 1` header is refused before
anything else is read, with the envelope that replaced it named. No old
spelling is read as an alias.

The key of every id-keyed map in the bundle is a local identifier: a lowercase
letter, then up to 63 lowercase letters, digits, `_`, or `-`. That holds for
`selectorProfiles`, `sourceConnections`, `sources`, and `authorityProfiles`,
for a selector profile's `fields`, for a source's `pathBindings` and the
placeholders its `path` names, for a grant subject's `valueClaims`, and
for a requirement's `derivation.parameters`. A key with a dot, or one longer
than 64 characters, is refused at the key. Two kinds of key are another
party's spelling and keep it. The names in `adapterParameters` and in a
statement's `parameterBindings` are what the script or the statement reads: a
letter or `_`, then up to 127 letters, digits, `.`, `_`, or `-`. A key of
`authentication.oidc.assertionIssuers` is a client identifier as its issuer
writes it: 1 through 128 bytes with no control character.

`local` is an authoring profile. A local requirement may omit `fixtures` while
the provider contract is still being written. This does not disable any other
runtime boundary: the bundle and runtime remain immutable, inbound
authentication and authorization remain required, source requests remain fixed
and bounded, signing and both audit gates remain fail-closed, and assertions
are visibly marked `local`. A supervised local issuer may use only the exact
canonical issuer origin `http://127.0.0.1:<non-zero-port>`, and its JWKS must
be served from that exact origin at an absolute path with no query or fragment;
other authentication URLs remain HTTPS unless the local bundle sets
`authentication.oidc.allowInsecureHttp: true`. The route is the issuer's to
choose; the origin is not.

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
| `issuer.uri` | yes | Legal issuer URI placed in evidence. Governance must authorize the provider to act for it. The key was `issuer.id`; a bundle that still writes `id` there is refused with `config.removed-key`. |
| `authentication.oidc` | yes | The one OpenID Connect issuer whose access tokens this deployment accepts, and the rules a token from it must satisfy. Evidence accepts no other inbound credential. |
| `authentication.oidc.issuer`, `authentication.oidc.jwksSource` | yes | Exact HTTPS token issuer and the fixed JWKS endpoint, written `jwksSource: {type: uri, uri: <JWKS URL>}`. `uri` is the only key-source type Evidence accepts; discovery and static key sets are refused. Path-based issuers are supported. The fixed JWKS endpoint is declared by the operator, so it inherits the declared issuer's allowance on any origin: it may resolve to a public, private, or loopback address. Cloud-metadata and link-local destinations remain prohibited, DNS is pinned for each fetch, and ambient proxies and redirects are disabled. Evidence never follows a JWKS URI from a discovery document, so the stricter rule for discovered cross-origin endpoints does not arise. |
| `authentication.oidc.allowInsecureHttp` | no | Permits plain HTTP to the issuer and the JWKS endpoint beyond loopback, under the `local` assurance profile only. Omission is false. `production` and `evidence-grade` bundles require HTTPS for both even when it is set: such a bundle that sets it to `true` is refused with a message naming the key, and so is one that writes a plain HTTP issuer or JWKS URI. When it is in force the runtime logs a warning at startup. |
| `authentication.oidc.audience` | yes | The one exact audience an inbound token must carry. It is also the resource the deployment advertises in its protected-resource metadata. |
| `authentication.oidc.tokenTypes` | yes | Non-empty allowlist containing only `at+jwt` and/or `application/at+jwt`. |
| `authentication.oidc.algorithms` | yes | Non-empty allowlist containing only `EdDSA`, `ES256`, and/or `RS256`. No algorithm fallback is permitted. |
| `authentication.oidc.principalClaim` | yes | The only claim used for the principal. Its absence denies; `client_id`, `azp`, request data, and proxy headers are not fallbacks. |
| `authentication.oidc.requesterTagsClaim` | yes | Claim containing the requester tags matched against an authority profile. |
| `authentication.oidc.evidenceAudienceClaim` | yes | Claim containing the exact evidence audience. The public request cannot choose another audience. |
| `authentication.oidc.claims` | no | Direct claim-name mapping for shared actor, purpose, grant id, authority, source issuer, client, resource, expiration, bounds, and approver claims. Omission uses the documented `registry_*` names. The names must be distinct from each other, Evidence product claims, and registered authentication claims. `registry_assertion_issuer` is deliberately not among them, and is reserved against being used as one of these names: the issuer derives it from the verified subject token rather than any deployment minting it, so there is no foreign vocabulary to adapt to, and a name changed at one end only would leave `authentication.oidc.assertionIssuers` reading a claim the token does not carry, which applies no rule rather than refusing. |
| `authentication.oidc.maximumTokenLifetimeSeconds` | yes | Positive maximum accepted `exp - iat`, up to 86,400 seconds. Its presence requires `iat`, `exp > iat`, and an interval within the maximum. |
| `authentication.oidc.revokedKeyIds` | yes | Explicit emergency denylist, including an empty list. It is checked before cached JWKS key selection. |
| `authentication.oidc.allowedClients` | yes | Machine-client admission every bundle decides, matched against the verified token's `client_id`/`azp` and never `sub`. The keyword `unrestricted` admits every client the issuer vouched for; a list admits exactly the clients it names and must be non-empty, unique, and bounded (at most 32 entries of 1..=128 bytes). Omission and an empty list are refused. A bundle with a task-grant authority profile must list its clients. Audience plus static issuer-governed attributes alone cannot establish that a client was granted this resource's permission, which is what `requiredScopes` closes. |
| `authentication.oidc.assertionIssuers` | no | Per-client assertion-authority admission for a token carrying the platform verifier's `registry_assertion_issuer` claim, keyed by the client the token's `client_id`/`azp` names and naming the issuers that client may present the claim as. Omission applies no rule, so a claim-bearing token is admitted regardless of its value. A stated map must be non-empty and bounded (at most 32 client keys of 1..=128 bytes), and each client's issuer list must be non-empty, unique, and bounded (at most 8 entries of 1..=512 bytes). A token carrying no such claim is never affected by this admission. |
| `authentication.oidc.requiredScopes` | yes | Scope gate every bundle decides, read from the verified token's scope set after signature verification and before any authority claim is read. The keyword `unrestricted` applies no scope gate; a list names the scopes every inbound token must carry and must be non-empty, unique RFC 6749 scope-tokens (at most 32 entries of 1..=256 bytes). Omission and an empty list are refused. A missing scope is never inferred from tags, principal, roles, `sub`, or request fields. |
| `authentication.oidc.actorClaim` | no | Optional verified actor claim. Omission does not enable a fallback actor source. |
| `authentication.oidc.tlsTrustProfile` | no | Logical profile name bound by `runtime.yaml` to a private CA file trusted beside the system roots for the `jwksSource.uri` connection alone. Omission uses system roots only. Refused when `jwksSource.uri` is a local HTTP origin. |

A bundle that still writes the access-token rules directly under
`authentication` (`authentication.kind`, `authentication.issuer`,
`authentication.audiences`, `authentication.jwksUri`, and the rest), or that
writes `authentication.oidc.audiences` or `authentication.oidc.jwksUri`, is
refused at startup. The refusal names the key that replaced it; no old
spelling is read as an alias.

### Audit, subject binding, rates, and signing

| Section | Required fields and rule |
|---|---|
| `audit` | `hashKeyRef` and positive `hashKeyVersion`, both required. The referenced master contains at least 32 raw secret bytes; Rust derives the audit pseudonym key from it, and `hashKeyVersion` is stamped into every audit pseudonym so pseudonyms under different key material stay distinguishable. Every audit gate is fail closed whatever this section says. The runtime file owns the audit destination. |
| `subjectBinding` | `secretRef` and positive `keyVersion`. The referenced master contains at least 32 raw secret bytes, uses a distinct reference, and must resolve to bytes distinct from the audit master. Rust derives purpose-scoped bindings over the complete canonical role/profile/value bundle, never per-field hashes. The remaining scope input is the requirement's binding mode: the authenticated audience for an audience-scoped requirement, the presented holder key thumbprint for a holder-bound one. The two derivations are domain-separated, so one mode's binding can never be read as the other's. |
| `rateLimits` | Positive `requestsPerPrincipalPerMinute`, `burstPerPrincipal`, and `failedSelectorAttemptsPerPrincipalAuthorityPerMinute`. A request batch costs one token per item, up to sixteen for any audience-scoped requirement, and a holder-bound release one per holder key, up to `maximumHolderBoundBatchSize` when `sd-jwt-vc-batch` is enabled. A cost above `burstPerPrincipal` can never be admitted and is refused as `evidence.invalid-request` without `Retry-After`. `evidence check` and `evidencectl doctor` warn when the burst is below the largest such cost; set it to at least that cost unless capping batches is intended. Raw selector values never become rate-limit labels. |
| `signing` | Exact keys are `format: flattened-jws-json`, `algorithm: ES256`, `activePublicJwkFile`, optional `certificateChainFile`, `publishedPublicJwkFiles`, `revokedKeyIds`, fixed `jwksPath`, `maximumAssertionValiditySeconds`, and `verifierClockSkewSeconds`. Every exact public EC P-256 JWK has a 43-character RFC 7638 thumbprint `kid`; active, published, and revoked sets are disjoint. `certificateChainFile` names `public-keys/<kid>.chain.pem` for the active key's thumbprint: a PEM chain, leaf first, of at most three certificates whose leaf certifies the signing key and which is valid at startup. It puts `x5c` in SD-JWT VC issuer headers and on the active key's JWKS entry; omitted, neither carries `x5c`. Missing signing material fails readiness; there is no unsigned fallback. |
| `responseFormats` | Closed unique list of 1 through 3 entries drawn from `signed-jws`, `unsigned-json`, and `sd-jwt-vc`. `signed-jws` must always be present; a bundle that omits it is rejected at startup. Every other format additionally requires the matched grant to permit it, and signing material must still be ready even for an unsigned response. |

`audit.hashKeyRef` replaced `audit.hashSecretRef`, which is refused at startup
with its replacement named.

Every secret reference in the bundle uses one of two forms. `secret:file/<name>`
resolves to a file beneath the runtime's `secretProviders.file.root`.
`secret:env/<NAME>` resolves to a process environment variable, and only when
the runtime enables `secretProviders.environment`; otherwise startup refuses the
bundle. Either way the bundle carries a logical name, never the secret value.

The bundle is parsed as written: a `${...}` environment expression in any bundle
key or string value is refused at startup, naming the field and never the
expression. Substitution applies to `runtime.yaml` only, so the reviewed bundle
is the one that runs.

### Selector profiles

Each `selectorProfiles.<id>` declares `maximumAggregateBytes` and one exact
`fields` map of 1 through 16 deployment-defined fields. Field names are opaque
to Rust. A profile is not an identity type and possession of its values is not
authority.

| Field type | Required declaration |
|---|---|
| `string` | `minimumBytes`, `maximumBytes` |
| `date` | Canonical `YYYY-MM-DD` |
| `uuid` | Exactly 36 ASCII characters: lowercase hexadecimal groups of 8-4-4-4-12 separated by hyphens; uppercase is refused, without normalization |
| `integer` | Inclusive `minimum`, `maximum` within the safe integer bound |
| `boolean` | No additional keys |
| `controlled-code` | `codelist`, `codelistVersion`, `maximumBytes` |

Alternative sufficient field sets and sets with an extra disambiguator are
different named profiles. Rust does no case folding, Unicode normalization,
transliteration, phonetics, tokenization, name-order parsing, partial-date
matching, fuzzy scoring, or candidate selection.

### Target authority and activation

A normalized project compiles its authored `EvidenceTargetAuthority` into an
`EvidenceCompiledTargetAuthority` document with
`apiVersion: id.registrystack.org/formats/evidence/compiled-target-authority/v1alpha1`.
The compiled document names `target`, `project`, and `accessProfiles`; its grants
reference exact Requirement URIs after local definition names are resolved.
Authors do not supply trusted revision or digest values.

Activation validates each complete grant against the package's authority kind,
actor kind, value origin, audience, purpose, subject-role selector profiles,
representation and binding ceilings. A normalized access profile must explicitly
name an allowed `actorKind`. A dynamic
`audienceFrom: authenticated-requester` is checked against the definition's
allowed audiences on every request. Neither development identities nor caller
selectors weaken these rules.

The activation store contains one bounded `authority-state.json` holding the
ordered history and active compiled snapshot. Activation derives
`authorityRevision` with a dedicated digest domain and `authorityDigest` from
canonical document bytes, binds the exact package digest, and commits the state
under a single-writer lock with file and directory synchronization. Repeating
an exact activation is refused as already active. Each activation writes an
audit request entry before it takes that lock and a response entry after it
commits or refuses; refusals never touch the store. Invalid documents and prepared temporary
files cannot replace the committed state. If the command cannot confirm a
commit, inspect the committed history before retrying.

Startup captures the committed snapshot once. A later activation applies at a
controlled restart; an admitted operation uses the same captured authority
through every source call and release gate. Authorized audit records carry
`authorityRevision` and `effectiveGrantDigest` together, binding the activated
grants with their package ceilings. These identities do not replace current
authenticated task-grant checks, signing, or durable release audit.

### Authority profiles

An optional `actorKind` binds the authority profile to `human`, `agent`, or
`service` in the verified token. An agent without a task grant must use a profile
that explicitly declares `actorKind: agent`; profiles without that binding do
not grant standing agent authority. A present but invalid task grant never falls
back to a standing profile.

An authority profile has a `kind` of `statutory`, `organizational`, `consent`,
`delegated`, or `explicit-request`, non-empty `requesterTags`, and grants.
Each grant binds one exact `requirement`, `purpose`,
`audienceFrom: authenticated-requester`, an optional `responseFormats` list,
and the complete subject-role set. A grant's `responseFormats` contains 1 through
4 unique entries from `signed-jws`, `unsigned-json`, `sd-jwt-vc`, and
`sd-jwt-vc-batch`, defaulting to `[signed-jws]` when omitted. The package keeps
signed JWS enabled, while a holder-bound grant can permit only the SD-JWT forms
its binding supports. A response requires the package, definition ceiling, one
complete matched grant, and binding mode to permit its representation. A grant
that says nothing permits only signed JWS.

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
  and additionally requires the complete shared task-grant claims. The actor
  must be an agent. The signed principal, original client and resource, trusted
  source issuer, purpose, Evidence requirement bound, and effective
  token/grant deadline must all match. A malformed or mismatched present grant
  cannot fall back to a standing profile.

An authority profile containing an `authenticated-grant` subject must declare
nonempty `requesterClients` and one exact `grantSourceIssuer`. Every requester
client must also appear in `authentication.oidc.allowedClients`.

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
| `question` | no | Human-facing presentation, 1 through 2,048 bytes when present. It does not change the definition behavior revision. |
| `grantCeiling` | normalized packages | Nonempty unique `authorities`, `actorKinds`, `valueOrigins`, and `audiences` lists. These constrain every target grant alongside the purposes, subjects/selectors, representations and binding declared here. |
| `representations` | normalized packages | Definition-specific format ceiling. Each format must fit this definition's subject binding and package response formats; target grants may narrow it. |
| `handle` | yes | Stable local authoring, inspection and generated-code name. Public requests use the exact Requirement URI and reject this handle as a wire substitute. |
| `uri`, `kind` | yes | Stable requirement URI and one of `criterion`, `information-requirement`, or `constraint`. Two requirements with the same `uri` are refused with `config.duplicate-id` at the second one's `uri`. The key was `id`; a bundle that still writes `id` there is refused with `config.removed-key`. |
| `subjectBinding` | no | `audience-scoped` or `holder-bound`. Omission means `audience-scoped`, and an omitted key stays out of the projected configuration, so declaring the mode on one requirement moves no other requirement's `configurationRevision`. See the holder-bound rules below. |
| `acquisition` | yes | One of the three closed shapes below. None permits response-led routing. |
| `purposes` | yes | Closed purpose codes that authority grants may select. |
| `subjectRoles` | yes | Complete role set, `cardinality: one`, and permitted selector profile ids. Public subject array order is not semantic; roles are resolved uniquely and canonicalized to declaration order. |
| `referenceFrameworks`, `evidenceType` | yes | Governed legal/procedural framework URIs and the exact Evidence Type URI. |
| `observationTimezone` | no | Valid IANA timezone used for `legal_local_date` and `legal_local_time`. Omission uses UTC. Declare it explicitly whenever local legal time can affect a result. |
| `validitySeconds` | yes | Positive assertion lifetime no greater than the signing maximum. |
| `derivation` | yes | Script, optional minimized `selectorInputs`, and closed typed parameters. |
| `concepts` | yes | 1 through 16 exact outputs, each with `handle`, `uri`, `type`, `required`, and closed form-specific `constraints`. `uri` is the stable concept URI the assertion names as `providesValueFor`. The key was `id`; a concept that still writes `id` is refused with `config.removed-key`. `type` names the concept's value form, the tag that fixes which `constraints` keys apply. The key was `form`; a concept that still writes `form` is refused with `config.removed-key`. |
| `fixtures` | conditional | Bundle-relative sanitized project fixture referenced by exactly one requirement. It may be omitted only under `assuranceProfile: local`; production and evidence-grade require it and complete coverage. |
| `disclosureGuard.families` | yes | Non-empty reviewed disclosure-family URI set. Reuse across enabled requirements is rejected; distinct labels still require human combined-disclosure review. |
| `existenceDisclosure` | yes | Exactly `collapse-unresolved` in Version 1. |

`acquisition` is a closed object with `source: <id>`, an optional
`holderPresented: {source: <id>, selectorProfiles: [<profile id>, ...]}`, or
both. Each source id names one pack-route binding from `sources`. The route
contains the complete reviewed sequence of provider operations, so the
requirement cannot choose a route from caller data or extend the operation
budget. With both channels, the request's selector profile selects exactly one
of them with no fallback: a profile listed in `holderPresented.selectorProfiles`
acquires only through `holderPresented.source`, any other only through `source`.
`source` may be omitted only when `selectorProfiles` lists every selector
profile the subject roles allow. `holderPresented.source` must name a Source
whose pack route reaches the `wallet-presentation-v1` host protocol, and
`source` must not. `selectorProfiles` is non-empty (at most 16), unique, and
limited to profiles the subject roles allow. A requirement with `holderPresented`
must offer only the signed JWS representation (`signed-jws`; unsigned JSON and SD-JWT VC are refused), and a grant has no `channels`
member. Each refusal names its member, for example
`/requirements/0/acquisition/holderPresented/source`.

Supported concept forms, written as the concept's `type`, are `boolean`, `controlled-code`,
`controlled-category`, `bounded-identifier`, `bounded-integer`, `bounded-decimal`, `date-bucket`,
`time-bucket`, `audience-scoped-entity-reference`, `controlled-code-list`,
`entity-reference-list`, and `reviewed-structured-value`. Constraint keys use
bundle camelCase, including `codelistVersion`, `minimumBytes`, `maximumBytes`, `prefix`, `categoryScheme`,
`schemeVersion`, `maximumScale`, `bucketScheme`, `minimumItems`, `maximumItems`,
`maximumSerializedBytes`, and `unique`, with the exact set determined by the
selected form. Codelist declarations and reviewed structured schemas are
bundle-relative, closed, versioned artifacts validated at startup.
`bounded-identifier` discloses a source-owned JSON string whose exact governed
ASCII `prefix` ends in `.`, `_`, `-`, `:`, `/`, or `#`. A nonempty suffix starts
with an ASCII letter or digit and then contains only ASCII letters, digits,
`.`, `_`, or `-`. `minimumBytes` and `maximumBytes` bound the complete value;
`maximumBytes` is at most 1024 and must leave room after the prefix.

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

### Pack-owned provider protocols

HTTP, GraphQL, SQLite, and product-specific protocol behavior belongs to the
digest-pinned Adapter pack. A pack endpoint fixes its component, wire
authentication kind, attempt and response bounds, and operation ids. Evidence
adds only the reviewed connection policy and matching runtime material.

A signed Evidence source uses the built-in `signed-evidence-v1` host protocol
on an authenticated HTTP endpoint. Its digest-pinned configuration contains
one reviewed Evidence definitions contract, trusted public JWKs, revoked key
ids, assertion-lifetime ceiling, and clock skew. The route must send a closed
`POST /v1/evidence` request with no query and a selector-only JSON body. Rust
creates a fresh nonce, requests the signed JWS media type, validates status
and canonical response headers, verifies the exact response bytes, and exposes
only the closed `values` projection to later route steps. Signed bytes, keys,
nonces, subject bindings, and assertion metadata never reach scripts.

The protocol refuses an endpoint whose authentication kind is `none`.
Upstream failure, unavailable evidence, signature failure, expiry, nonce or
audience mismatch, and schema failure remain dependency failures. They never
become `no-match`, and no unverified value reaches derivation.

### Adapter pack source example

```yaml
sources:
  source-a:
    pack:
      id: civil-registry
      version: 1.0.0
      digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      artifactPrefix: adapter-packs/civil-registry/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    route: evidence-by-reference
    connection: shared-read
    inputs:
      recordReference:
        selector:
          role: subject
          profile: record-reference-v1
          field: reference
    posture: record-transformed
    factSchema: schemas/source-a-facts.schema.yaml
```

Each source is a thin governed binding to an Adapter pack route:

| Key | Required | Meaning |
|---|---|---|
| `pack` | yes | Exact Adapter pack `id`, `version`, `digest`, and package-relative captured `artifactPrefix`. The pack file digest and every pinned artifact are verified before compilation. |
| `route` | yes | Evidence route id declared by the pinned pack. The route contract fixes its input schema, facts schema, and acquisition posture. |
| `connection` | yes | Governed `sourceConnections` owner and matching runtime resource id. SQLite-only and no-send routes still use a named empty owner, which grants no network authority. |
| `inputs` | when the route declares inputs | Named route inputs, each projected from one authorized selector `role`, `profile`, and `field`. Caller values cannot select another input or endpoint. |
| `posture` | yes | `source-derived`, `field-projected`, or `record-transformed`, never stronger than the digest-pinned route contract. A project projection requires `record-transformed`. |
| `factSchema` | yes | Bundle-relative final facts schema under `schemas/`. It equals the pinned route facts schema when no projection is selected; a project projection instead validates its output against this versioned, closed schema. |
| `projection` | no | Governed `{script, entrypoint, digest}` for a project-owned Rhai projection of already-matched native facts. The script is under `derivations/`, its exact SHA-256 pin is checked, and it retains the acquisition deadline. It cannot change acquisition or lookup classification. |

The pack owns the closed HTTP, GraphQL, SQLite, extraction, and response-
validation steps. Evidence does not compile a second inline request language
from the bundle.

### Governed source connection policy

`sourceConnections` reviews non-secret endpoint authority. Secret references
and operational limits are deliberately absent:

```yaml
sourceConnections:
  shared-read:
    endpoints:
      - endpoint: records
        baseUrl: https://registry.gov.example
        tlsTrustProfile: government-internal-pki
        clientIdentity: forbidden
        authentication:
          type: oauth2-private-key-jwt
          tokenEndpoint: https://identity.gov.example/token
          clientAssertionAudience: https://identity.gov.example/client-auth
          audience: https://registry.gov.example
          resource: https://registry.gov.example
```

Each connection contains a unique endpoint-policy list. An empty list is valid
for a SQLite-only or no-send route and grants no HTTP authority.

| Connection key | Required | Meaning |
|---|---|---|
| `endpoints[].endpoint` | yes | Exact endpoint id in the pinned pack. A reachable HTTP or GraphQL endpoint must match exactly one policy. |
| `endpoints[].baseUrl` | yes | Exact normalized destination URL, including any reviewed base path. Runtime must repeat it exactly. |
| `endpoints[].tlsTrustProfile` | no | Logical private trust profile the runtime must bind. Omission uses system roots. |
| `endpoints[].clientIdentity` | yes | `required` requires an mTLS identity in the runtime binding; `forbidden` refuses one. |
| `endpoints[].authentication` | yes | Reviewed authentication kind. Static kinds carry only `type`; OAuth policies additionally pin the non-secret token endpoint, scope, audience, resource, assertion audience, and credential placement that apply. |

One connection name in one process shares endpoint resources, admission
permits, and OAuth cache state across every source program that reaches it.
Different names remain isolated even when their destinations or credentials
match. No facts or authorization decisions are shared. Cancellation and
timeouts release permits and refresh locks. The concurrency limit is per
process, so the fleet maximum is the per-process endpoint limit multiplied by
the number of replicas.

For file-secret changes and immediate token replacement, follow
[Source credential rotation](SOURCE-CREDENTIAL-ROTATION.md).

### Source authentication

Authentication has three agreeing owners. The Adapter pack endpoint fixes the
wire kind and, for static authorization or API keys, the scheme or header name.
The governed connection policy repeats the kind and pins non-secret OAuth
authority. The runtime endpoint binding supplies matching secret references
and token-cache bounds. Startup refuses any disagreement before a source call.

Static governed policies carry only their type:

```yaml
authentication:
  type: basic
```

The closed static types are `none`, `basic`, `static-authorization`, and
`static-api-key`. A `none` policy grants no credential. A signed Evidence host
protocol refuses `none`, because it requires an authenticated source identity.
For static authorization and API keys, the pack endpoint owns the reviewed
scheme or header name. Runtime supplies only the secret:

```yaml
# Basic
credential:
  type: basic
  usernameRef: secret:file/source-username
  passwordRef: secret:file/source-password

# The pack endpoint owns the Authorization scheme.
credential:
  type: static-authorization
  tokenRef: secret:file/source-token

# The pack endpoint owns the API-key header name.
credential:
  type: static-api-key
  valueRef: secret:file/source-api-key
```

OAuth policy pins the authorization server and request semantics without
containing a client id, secret, or private key:

```yaml
authentication:
  type: oauth2-client-credentials
  tokenEndpoint: https://auth.registry.gov.example/token
  scope: recordsearch
  audience: https://api.registry.gov.example/
  resource: https://api.registry.gov.example/
  credentialPlacement: basic-header
```

The runtime repeats every non-secret member exactly and adds secret references:

```yaml
credential:
  type: oauth2-client-credentials
  tokenEndpoint: https://auth.registry.gov.example/token
  clientIdRef: secret:file/source-client-id
  clientSecretRef: secret:file/source-client-secret
  scope: recordsearch
  audience: https://api.registry.gov.example/
  resource: https://api.registry.gov.example/
  credentialPlacement: basic-header
  maximumCacheSeconds: 300
```

`oauth2-private-key-jwt` follows the same split. Its policy may additionally
pin `clientAssertionAudience`; its runtime credential supplies `clientIdRef`
and `clientAssertionKeyRef`. Omission uses the exact token endpoint as the
assertion audience. State another audience only when the authorization server
expects a different exact identifier, such as an issuer behind a proxy.

OAuth `credentialPlacement` is `basic-header` or `form-body`. Client secrets
never travel in a query string. `audience` is a token-request parameter, while
`clientAssertionAudience` is a claim inside the private-key assertion.
`resource` is the optional RFC 8707 resource indicator. The runtime derives
none of them from caller data, scripts, responses, or destination URLs.

If a token response omits `expires_in`, the runtime credential must state
`assumedLifetimeSeconds` or the response is refused. Credited lifetime remains
bounded by `maximumCacheSeconds`. Token redirects are denied and response bytes
are bounded. Token acquisition is credential bootstrap, not another Evidence
data operation.

All secret references are logical. Rust resolves them only after authorization,
durable access intent, and complete request-shape validation. No secret reaches
Adapter scripts. Username, password, token, client-id, and client-secret files
contain their provider-defined byte strings. A `clientAssertionKeyRef` file
contains the private JWK, including `alg` and `kid`.

### Adapter route execution

The digest-pinned Adapter pack owns the complete acquisition program:
endpoint selection, HTTP or GraphQL request construction, SQLite statements,
bounded retries, response transformation, schema validation, and the final
closed lookup result. Evidence supplies only the source binding's authorized
named inputs and the finite runtime acquisition budget. Neither caller data
nor runtime configuration can add a route step, endpoint, request, or schema.

Every referenced pack artifact is captured under the source's `artifactPrefix`
and verified against its digest before compilation. This includes scripts,
query files, OpenAPI, SQLite statements, host-protocol configuration, Evidence
input and facts schemas, and nested `validateSchema` references. Remote schema
resolution is unavailable. A missing, extra-authority, or digest-mismatched
artifact refuses the bundle before any credential or source operation.

An HTTP or GraphQL step may reach only an endpoint covered by exactly one
policy in the source's governed connection. A SQLite-only or no-send route
uses an empty endpoint-policy list and receives no network authority. SQLite
statements are pinned pack artifacts; `runtime.yaml` supplies the named
immutable extract file under `sourceExtracts` without supplying SQL.

The route returns exactly one closed lookup outcome: `matched` with facts,
`no-match`, `ambiguous`, or `unresolved`. Use `no-match` when the source
answers that no such subject exists. Use `unresolved` only when the reviewed
source explicitly states that the facts cannot currently be resolved, such as
the declared source-neutral Problem Details 404 of an HTTP JSON source. Like
`no-match` and `ambiguous`, it carries no facts. Dependency, transport,
authentication, budget, schema, and script failures never collapse into
`no-match`. The engine holds this at pack compilation: an Evidence route may
not catch or handle an `upstream` class, `breaker.open`, `throttle.rejected`,
`script` or `validation` with `doCatch` or with an `onException` clause that
carries steps, `handled` or `continued`, and its `circuitBreaker` may not
declare `onFallback`, `ignoreException` or `recordException`. Retry-only
`onException` clauses stay available. To answer a declared status such as 404
as `no-match`, catch `upstream.http` with an `onWhen` status test. The
`registry-lookup-v1` host protocol needs no handler: it verifies its declared
Problem Details 404 and hands the route an `unresolved` body. Matched facts are validated against the
pinned route facts schema before any optional project projection. Without a
projection the bundle `factSchema` is semantically identical. With a projection,
its output must validate against the bundle's versioned final facts schema.
Both schemas and the script remain governed; failures release no derived result.
No-match, ambiguous and unresolved outcomes bypass the projection unchanged.

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
are closed JSON Schema 2020-12 documents: the root and every object set
`additionalProperties: false`, references stay inside the document, and the
document stays within its size bounds. Pack route fact schemas are private
derivation input and do not bound string length or array size individually
(one acquisition reads at most the `sourceAcquisition` response budget, 1 MiB
by default). Reviewed-value schemas keep the
stricter grammar: an exact required property set, with every reachable string,
array, and number bounded, because they shape what a response may disclose.
Fixtures use the exact contract in [`FIXTURES.md`](FIXTURES.md).

Codelists under `codelists/` open with the `apiVersion` and `kind` envelope,
name their form with `type`, and use one of two closed YAML shapes:

```yaml
# Exact code set
apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1
kind: EvidenceCodelist
uri: urn:gov:example:codelist:status
version: '1'
type: code-list
codes: [active, inactive]
```

```yaml
# Exact source-to-output mapping
apiVersion: id.registrystack.org/formats/evidence/codelist/v1alpha1
kind: EvidenceCodelist
uri: urn:gov:example:codelist:region-map
version: '1'
type: mapping
entries: {SOURCE-A: REGION-NORTH, SOURCE-B: REGION-SOUTH}
allowedOutputs: [REGION-NORTH, REGION-SOUTH]
```

`uri` is the absolute URI other configuration cites, written exactly as its
issuer gives it: at most 512 characters, with no whitespace and no control
character. A file without the envelope is refused with the two lines
named; the members `id` and `allowed_outputs` are refused as removed keys
naming `uri` and `allowedOutputs`. Each document has 1 through 4,096 unique
bounded codes. A mapping output must appear in `allowedOutputs`. Referencing configuration repeats the exact
artifact version and startup rejects a mismatch. Active and temporarily
published service keys live under `public-keys/` as exact public P-256 JWK JSON
files. Private signing material is never a bundle artifact.

## Runtime configuration

`runtime.yaml` contains only process-local bindings:

```yaml
apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
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
  type: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  attemptTimeoutMilliseconds: 2000
audit:
  destination: file
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  rotateBytes: 104857600
  retentionDays: 90
outboundTls:
  systemRoots: true
  trustProfiles: {}
sourceConnections:
  shared-read:
    id: shared-read
    endpoints:
      - endpoint: records
        baseUrl: https://registry.gov.example
        credential:
          type: oauth2-private-key-jwt
          tokenEndpoint: https://identity.gov.example/token
          clientIdRef: secret:file/workload-client-id
          clientAssertionKeyRef: secret:file/workload-client-key
          clientAssertionAudience: https://identity.gov.example/client-auth
          audience: https://registry.gov.example
          resource: https://registry.gov.example
          maximumCacheSeconds: 60
        attemptTimeoutMilliseconds: 5000
        maximumResponseBytes: 1048576
        maximumConcurrency: 8
        tlsTrustProfile: government-internal-pki
    outboundTls:
      trustProfiles:
        government-internal-pki:
          caBundleFile: /etc/registry-evidence/ca/government-internal.pem
    allowedPrivateCidrs: []
sourceAcquisition:
  maximumDataOperations: 5
  acquisitionDeadlineMilliseconds: 30000
  maximumResponseBytes: 1048576
```

An authored `EvidenceTarget` lists its reviewed private trust profiles once
under `outboundTls.trustProfiles`. Compilation scopes that inventory into the
runtime owners shown above. For an accepted target, root `outboundTls` contains
only profiles selected by root authentication, while each
`sourceConnections.<name>.outboundTls` contains only profiles selected by that
connection's endpoints. A missing selection remains missing and is refused at
runtime; compilation never copies an unrelated profile into a scope to satisfy
it. An inventory entry selected nowhere is refused when the target is read,
with `evidence.target.trust-profile-unused` at
`target.yaml:/outboundTls/trustProfiles/<id>`: name it from an endpoint
`tlsTrustProfile` or from `authentication.oidc.tlsTrustProfile`, or delete it.

| Key | Required | Meaning and Version 1 bounds |
|---|---|---|
| `apiVersion` | yes | Literal `id.registrystack.org/formats/evidence/runtime/v1alpha1`. Names the grammar the document is written in. The earlier value `registry.registrystack.org/evidence-runtime/v1alpha1` is refused as `config.retired-api-version` with this one named. |
| `kind` | yes | Literal `EvidenceRuntimeConfig`. Together with `apiVersion` it tells an Evidence runtime file apart from another product's runtime configuration. |
| `package.root` | yes | Absolute path to the single governed package directory. No alternate, overlay, or fallback package exists. |
| `authority.root`, `authority.target` | normalized packages | Absolute owned activation-store directory and exact governed target identifier. Startup requires a committed authority snapshot for this project, target and package digest. Activation prepares the next controlled restart. |
| `package.expectedDigest` | no | The `sha256:` package digest the operator approved. When set, startup is refused unless the package at `package.root` computes exactly this digest. Omission still verifies and loads the package found there. |
| `listener.bind` | yes | Numeric socket address written `host:port`, with an IPv6 host in brackets (`[addr]:port`). Port `0` is refused. Under the default `private-address` exposure, the host must be loopback, RFC 1918 private IPv4, or RFC 4193 unique-local IPv6. Under explicit `container-private`, the unspecified IPv4 or IPv6 wildcard is also accepted. Hostnames, concrete public addresses, and multicast are always rejected. |
| `listener.networkExposure` | no | `private-address` by default. `container-private` permits a wildcard bind only when the operator confines the container network and terminates TLS upstream. It does not enable direct public exposure. |
| `listener.tlsTermination` | yes | Literal `operator-controlled-upstream`. |
| `listener.trustProxyIdentityHeaders` | yes | Literal `false`; proxy headers never supply authenticated identity or authority. |
| `listener.maximumRequestBytes` | yes | 1,024 through 1,048,576 bytes. |
| `listener.maximumConcurrentRequests` | yes | 1 through 4,096. |
| `listener.requestTimeoutMilliseconds` | yes | 1 through 30,000 milliseconds for admission, concurrency queueing, and request-body collection. Once protected evaluation starts, this timer does not cancel it; source and OIDC boundaries have their own bounds, and the runtime preserves fail-closed audit and release ordering. |
| `listener.shutdownGraceMilliseconds` | yes | 1 through 120,000 milliseconds. |
| `metricsListener` | no | Optional operator-only telemetry listener serving `GET /metrics`, a binding separate from the evidence listener above and absent from the public evidence contract. Absence is the default and serves no metrics endpoint. `metricsListener.bind` is a `host:port` socket address whose host must be loopback, RFC 1918 private IPv4, or RFC 4193 unique-local IPv6; port `0` is refused, and it must not repeat the evidence listener's binding. |
| `secretProviders` | yes | The providers a secret reference may resolve through, at least one. A bundle reference naming a provider this section does not enable is refused at startup. |
| `secretProviders.file.root` | when the file provider is used | Absolute root for logical `secret:file/...` references. Only regular, non-symlink, single-link files owned by the service identity with exact mode `0400` or `0600` are accepted. |
| `secretProviders.environment` | no | Written `environment: {}`, with no settings. Enables `secret:env/NAME` references, read from the process environment. Absence means no reference may name the environment. Use it where the platform injects secrets as environment variables; the file provider keeps its ownership and mode checks, which the environment cannot offer. Once enabled, any reference in the reviewed bundle, a source credential included, may name any variable in the process environment, so give the process a dedicated environment holding only the secrets this deployment needs, and review each `secret:env/NAME` reference as part of the bundle. A bundle cannot enable a provider itself. |
| `signer` | yes | Closed runtime signer union. `production` and `evidence-grade` require a pinned Transit signer over a workload-local Unix socket. `local` requires `type: local-jwk` with `privateKeyRef: secret:file/evidence-signing`. Startup validates provider controls and exact public-key agreement, then signs and verifies a challenge. |
| `audit` | yes | Where this process writes its audit entries through the shared platform audit writer, one JSON line per entry with the members `schema`, `eventId`, `time`, `phase`, `correlation`, and `record`. Entries are not chained; ship them to append-only storage for tamper evidence. Every audit gate is fail closed on either destination. |
| `audit.destination` | no | `file` by default, or `stdout`. `file` appends each entry durably (the append returns only after `fsync`) under a single-writer lock at `<path>.lock`, so a second process on the same path fails startup. `stdout` writes each entry as one line on standard output for a collector that owns durability, rotation, and retention; `check --require-audit-under` refuses it, and local audit inspection cannot read it. |
| `audit.path` | for `file` | Absolute path to the active append-only JSON Lines audit file on operator-owned durable storage. The writer reserves `<path>.<sequence>` (eight digits), `<path>.lock`, `<path>.seq`, which records the next sequence across restarts, and `<path>.seq.tmp`, so no other audit stream's path may be one of those names. Refused for `stdout`. |
| `audit.rotateBytes` | no | 1,048,576 through 4,294,967,295 bytes; 104,857,600 (100 MiB) by default. Reaching it seals the active file under an ascending sequence number and opens a fresh one at `path`. A write or sync failure, not rotation itself, is what fails closed. Refused for `stdout`. |
| `audit.retentionDays` | no | 1 through 36,500 days; 90 by default. When the writer opens or rotates, sealed files last modified longer ago than this are deleted; the active file never is. Refused for `stdout`. |
| `outboundTls.systemRoots` | yes | Literal `true`. |
| `outboundTls.trustProfiles` | yes | For an accepted target, root-authentication trust profiles only, as a closed map of at most 64 logical profile ids. Each id is a local identifier: a lowercase letter, then up to 63 lowercase letters, digits, `_`, or `-`. It is empty when root authentication names no private trust profile; source profiles live in their connection-local maps below. |
| `outboundTls.trustProfiles.<id>.caBundleFile` | for each profile | Absolute path to one bounded PEM CA file. Profile names must exactly match bundle `tlsTrustProfile` references. |
| `sourceConnections` | for every governed connection | Process-local endpoint and credential material. Every governed connection name must appear once, no extra runtime name is accepted, and each value's `id` must equal its map key. |
| `sourceConnections.<name>.endpoints` | yes | Runtime endpoint bindings keyed by the pack endpoint id. Every reached HTTP or GraphQL endpoint must match exactly one governed endpoint policy in id, base URL, trust profile, client-identity posture, authentication kind, and non-secret OAuth authority. An empty list is valid only where the reached program needs no network endpoint. |
| `sourceConnections.<name>.endpoints[].credential` | when the governed authentication is not `none` | Secret-bearing runtime credential. Its type and non-secret OAuth settings must exactly match the governed policy. Credential references are resolved only after authorization, durable access intent, and request-shape validation. |
| `sourceConnections.<name>.endpoints[].attemptTimeoutMilliseconds` | no | Finite positive timeout for one endpoint attempt. It does not extend the acquisition deadline or a smaller pack ceiling. |
| `sourceConnections.<name>.endpoints[].maximumResponseBytes` | no | 1 through 1,048,576 bytes for one response. The effective bound is also constrained by the pack and `sourceAcquisition.maximumResponseBytes`. |
| `sourceConnections.<name>.endpoints[].maximumConcurrency` | no | 1 through 256, default 8. The same connection name shares its capacity across programs in one process; different names remain isolated. Replicas do not share a distributed permit, so the fleet can place this limit multiplied by the replica count in flight. |
| `sourceConnections.<name>.endpoints[].tlsTrustProfile` | when the governed policy names one | Exact logical trust profile repeated from the governed policy and bound under this connection's `outboundTls.trustProfiles`. |
| `sourceConnections.<name>.endpoints[].mtlsIdentity` | when `clientIdentity` is `required` | Certificate and private-key secret references. It is refused when the governed policy says `forbidden`. |
| `sourceConnections.<name>.outboundTls.trustProfiles` | when a governed endpoint names a private trust profile | Connection-local map containing only the logical ids selected by that connection's endpoints, each bound to a bounded CA bundle file and captured once at startup. Extra and missing profiles are refused. |
| `sourceConnections.<name>.allowedPrivateCidrs` | no | Additional private CIDR authority for this connection. Omission or `[]` grants none. Numeric loopback development endpoints use their separate loopback rule and do not require `127.0.0.0/8` here. |
| `sourceAcquisition.maximumDataOperations` | no | Finite positive data-operation budget for one pack-route acquisition, default 5. Token acquisition and credential refresh follow their own bounded accounting. |
| `sourceAcquisition.acquisitionDeadlineMilliseconds` | no | Finite positive elapsed-time budget for one acquisition, default 30,000 milliseconds. It includes endpoint admission and data operations and cannot be extended by an endpoint attempt timeout. |
| `sourceAcquisition.maximumResponseBytes` | no | Finite positive aggregate response-byte budget for one acquisition, default 1,048,576 bytes. Per-endpoint and pack response ceilings still apply. |
| `sourceExtracts` | no | Closed map of at most 64 logical extract names, each a local identifier of the same grammar. Omission binds none, which is what a runtime file for a bundle with no extract source says. |
| `sourceExtracts.<name>.path` | for each name | Absolute path to one read-only regular file. Names must exactly match bundle `extractProfile` references. |

You own the `sourceAcquisition` budget. The runtime accepts any positive value
for each of the three members and sets no upper limit, so a typo such as an
extra zero is accepted and widens what one request may spend on the source.
Raise a member above its default only for a route that needs it, and keep each
value near what the heaviest reviewed route uses:

- `maximumDataOperations`: the most data calls that route makes, plus a small
  margin. A search followed by a fetch is 2; 5 covers most routes, and a value
  above about 64 deserves a second look.
- `acquisitionDeadlineMilliseconds`: below the time your callers wait, because
  the acquisition and the release append share it. Stay at the 30,000
  default unless a slow source needs more; a value above about 600,000 (ten
  minutes) is almost certainly a mistake.
- `maximumResponseBytes`: the total of the largest responses that route reads,
  and no more. The 1 MiB default matches the per-endpoint ceiling; a value above
  about 16 MiB is unusual.

Each acquisition's audit record captures the effective values as
`executionBounds`, so you can review what a deployment ran with.

A runtime file written in the earlier grammar is refused before anything else
is read, with the replacement named: `version` gives way to `apiVersion` and
`kind`, `bundleDirectory` to `package.root`, and `listener.bindHost` with
`listener.port` (and the same pair under `metricsListener`) to one `bind`
address. No old spelling is read as an alias.

A string value may carry `${NAME}` or `${NAME:-default}`, substituted from the
process environment after the document is parsed. Substitution is refused
inside a secret reference and anywhere under `secretProviders`, so an
environment variable can move a path or an address but can never choose which
secret a field names. The runtime captures the substituted document once at
startup, so a changed variable takes effect only after restart.

`package.root`, secret roots, audit destinations, and CA files must be
absolute paths. The runtime rejects symlinks, insecure ownership/modes, missing
required logical bindings, mutable files, and files outside the configured
roots according to the operator contract.

Every immutable deployment input this contract loads, `runtime.yaml` itself,
the bundle directory and each artifact inside it, a named CA bundle file, and
a bound extract, must carry no write permission for anyone. The secret root
follows its own rule: it must carry no group or other permission at all
(`0700` or tighter), and owner write is accepted, since the operator
provisions and rotates the secret files inside it; those files keep their own
exact `0400` or `0600` mode.

A read-only mount satisfies the write-permission rule on its own. When
`statvfs` reports `ST_RDONLY` for the filesystem holding an input, that input's
mode bits are accepted as written, because nothing can write through that mount
whatever the bits say. The exemption covers every input the write-permission
rule names, `runtime.yaml`, the bundle directory and each artifact inside it, a
named CA bundle file, and a bound extract, and it covers only that rule. The
secret root and the secret files inside it are judged on their mode bits alone,
`0700` or tighter for the root and exactly `0400` or `0600` for each file, on a
read-only mount as on any other, because those modes bound who may read a
secret rather than who may write it.

`evidence check --require-runtime-dependencies` refuses a non-conforming
runtime file, bundle artifact, CA bundle file, or secret root on the target
host. Freezing is a property of that host, so the offline `evidence check`
leaves it to this form. Each fault is one diagnostic with exit `1`: a writable
input reports `evidence.deployment.not-immutable` with the file it names, for
example `runtime.yaml` and the cause `the runtime file is writable`, and a
writable bound extract reports the distinct `evidence.deployment.invalid-input`
with the cause `the source extract the runtime file names is writable`. The CA
bundle and secret root checks are not bound to an artifact, so their
diagnostics name the package instead and carry a bare cause, for example `the
secret root directory the runtime file names is reachable by group or other`.
Process startup (`evidence serve`) refuses the same non-conforming inputs
before the listener binds but collapses every cause to `runtime bundle
initialization failed`, naming neither the artifact nor the cause. Write
`runtime.yaml`, make it non-writable (for example `chmod 400`), and run
`evidence check --require-runtime-dependencies` before `evidence serve` so a
fault surfaces with its artifact and cause instead of only as `runtime bundle
initialization failed`.

A bundle source may name one `tlsTrustProfile`, and so may
`authentication.oidc` for the connection that fetches the access-token issuer's
key set from `jwksSource.uri`. The corresponding bounded PEM file is loaded and validated at
startup and is trusted beside the system roots, only for the connection of the
source or issuer that names it. A source and the issuer may name the same
profile. Hostname verification and source-origin checks remain mandatory.
There is no `insecure`, `skipVerification`, or `trustAll` setting, and the
issuer needs no process-wide trust store change such as `SSL_CERT_FILE`.
Changing a trust file requires restart before the new bytes can be used.

A bundle source that reads an extract names one `extractProfile` and never a
filesystem location, so the operator decides where the file sits without
editing reviewed material. Each bound file must be a regular, non-symlink,
read-only file. Read-only is a correctness requirement rather than hygiene: the
statement executor opens the file as immutable, and an immutable connection
over a file that can change is undefined behaviour. Startup digests each file
without reading it into memory and retains that content digest with the opened
extract, so replacing an extract requires restart. Startup
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

Treat the editable `EvidenceProject` as reviewed source code.
It contains `evidence.yaml`, owned Adapter packs, derivation Functions, schemas,
codelists, and sanitized fixtures.
The OpenAPI form of `evidencectl init` retains a provider description for pack
authoring, and `source suggest` emits an incomplete pack and Source binding for
review.
The SQLite form creates a source-neutral synthetic project that can run through
`evidencectl test` immediately.
Use only synthetic responses and selectors while authoring.
Do not author `bundle/evidence.yaml` or a runtime file; `evidencectl package`
compiles those deployment artifacts from the normalized project and target.

Keep each environment in one complete target directory containing:

- `target.yaml`, an `EvidenceTarget` that binds the project, connection
  endpoints, non-secret authentication policy, secret references, signer,
  audit destination, process paths, and package installation root;
- the `EvidenceTargetAuthority` file that `target.yaml` names, normally
  `authority.yaml`, with complete identity profiles and grants for that target;
  and
- every public signing JWK that `target.yaml` names under `public-keys/`.

Secret values and private keys remain outside the authored project and target.
Use separate complete targets for staging and production, built from the same
reviewed project revision.
Do not use overlays or edit a staging candidate into a production candidate.
The ready-to-copy layout and Transit proxy-policy examples are under
[`../../deployment-targets/`](../../deployment-targets/).

Use `evidencectl` and `evidence` from the same release or immutable development
candidate.
The tooling refuses a version mismatch before it delegates compilation or
fixture evaluation.
Check the normalized project, complete target, and fixture behavior before
packaging:

```sh
evidencectl check '<editable-project>' \
  --target '<deployment-target>/target.yaml' \
  --production \
  --deny-warnings
evidencectl test '<editable-project>' \
  --target '<deployment-target>/target.yaml' \
  --deny-warnings
```

These commands make no identity-provider or source-data request and resolve no
deployment secret.
The production check requires an explicit `production` or `evidence-grade`
target, complete public inputs, resolved review markers, and complete authority.
The fixture run compiles the selected pack routes and replays only their
sanitized exchanges.
If either command refuses, correct the named project or target field and rerun
it before creating a candidate.

Run the create-only compiler with explicit target and output paths:

```sh
evidencectl package '<editable-project>' \
  --target '<deployment-target>/target.yaml' \
  --output '<new-candidate-directory>'
```

The output directory must not already exist and must remain outside the
editable project.
Packaging captures one project snapshot, follows no authored symlink, includes
only referenced artifacts, delegates static bundle validation and every fixture
to the matching `evidence` binary, and publishes the candidate atomically.
A refusal publishes no new candidate; correct the reported input and choose a
new output directory for the next attempt.

The candidate contains the immutable bundle closure at
`<new-candidate-directory>/bundle/SHA256SUMS`, the operator runtime at
`<new-candidate-directory>/runtime.yaml`, and the separately compiled target
authority at `<new-candidate-directory>/compiled-authority.yaml`.
Given identical authoring files, target, and toolset release, the bundle bytes
and digest are identical.
The target's environment-specific runtime bindings are outside the bundle
digest and each signed `configurationRevision`.

The package digest identifies the whole reviewed package and is what an operator
records at approval. A signed `configurationRevision` is narrower: it covers
only the configuration and artifacts one requirement depends on. Editing a
requirement, its source, one of its selector profiles, an authority grant naming
it, or any script, schema, codelist, or fixture file those reach changes that
requirement's revision. The public verification keys and
`signing.revokedKeyIds` are in no requirement's closure: which keys are
published, which one signs, and which are revoked is trust a relying party
takes from the JWKS and its verification policy's denylist, so publishing,
activating, retiring, or revoking a key changes the package digest but no
requirement's revision. `authentication.revokedKeyIds` is in no requirement's
closure either: it decides which caller tokens are accepted, not what an
assertion means, so revoking an identity-provider key changes the package
digest but no requirement's revision. Every other `authentication` member
stays in every requirement's closure. An edit
outside a requirement's closure leaves its revision unchanged, so it does not
force every relying party to re-review.

After approval, install the exact candidate `bundle/` at the `package.root`
recorded in the emitted runtime.
Provision the referenced owner-only secrets, private trust files, extract files,
and signer transport at the paths that runtime names.
Make the installed bundle, runtime, and other immutable inputs non-writable to
the service identity.

Activate the candidate's compiled authority, then run the target-host preflight
against that same runtime:

```sh
evidence authority activate \
  --runtime-config '/absolute/path/to/<new-candidate-directory>/runtime.yaml' \
  --document '/absolute/path/to/<new-candidate-directory>/compiled-authority.yaml'
evidencectl doctor \
  --runtime-config '/absolute/path/to/<new-candidate-directory>/runtime.yaml'
evidence check \
  --runtime-config '/absolute/path/to/<new-candidate-directory>/runtime.yaml' \
  --require-runtime-dependencies
```

Authority activation commits a snapshot for the exact project, target, package
digest, and grant ceilings.
Doctor and `evidence check --require-runtime-dependencies` prove the installed
package, secret material, extracts, audit destination, signer, source
credentials, and issuer key access without opening the public listener or
requesting an assertion.
If startup later reports only `runtime bundle initialization failed`, rerun
these preflights to obtain the value-free artifact and cause before retrying.

Start the service with the runtime that passed preflight:

```sh
evidence serve \
  --runtime-config '/absolute/path/to/<new-candidate-directory>/runtime.yaml'
```

Route traffic only after `/ready` succeeds.
Retain one authorized synthetic-subject response, verify it under independently
prepared production policy and trusted keys, and confirm the audit entries
reached the operator's append-only store.
A provider API, target, authority, or governed project change produces a new
candidate and reruns the check, fixture, activation, and preflight sequence.

Configure an OIDC issuer independently and register each workload with the exact
resource, scopes, client identity, and public key required by its approved
journey. Match the bundle's issuer, JWKS URI, audience, allowed algorithms,
accepted token types, and principal, requester-tag, Evidence-audience, grant,
and optional actor claim mappings. The maintained local tooling uses stock
ThunderID. Deployment inspection does not register callers, decide authority,
or provision an issuer; verify the configured issuer-to-resource journey as
part of the handoff.

Docker Compose is a documented adapter rather than build output. It mounts the
approved package unchanged and read-only; mounts a distinct container runtime,
secrets, and persistent audit storage separately; binds Evidence privately; and
keeps TLS and public routing operator-controlled. The Compose runtime remains
outside the package while assertions continue to carry their per-requirement
configuration revisions.
Retain the configured issuer's public HTTPS identity and JWKS URI when services
share a network; internal plain-HTTP service names do not replace them.

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

`acquisitionCapabilities` is retired. It stays in both blocks because, for one
release, both files accept an empty list (`acquisitionCapabilities: []`) and
ignore it, so a 0.44.0 file still loads; any capability is refused. Delete the
member.

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
apiVersion
assuranceProfile
audit
audit.hashKeyRef
audit.hashKeyVersion
authentication
authentication.oidc
authentication.oidc.actorClaim
authentication.oidc.algorithms
authentication.oidc.algorithms[]
authentication.oidc.allowInsecureHttp
authentication.oidc.allowedClients
authentication.oidc.allowedClients[]
authentication.oidc.assertionIssuers
authentication.oidc.assertionIssuers.*
authentication.oidc.assertionIssuers.*[]
authentication.oidc.audience
authentication.oidc.claims
authentication.oidc.claims.actorKind
authentication.oidc.claims.approver
authentication.oidc.claims.grantBounds
authentication.oidc.claims.grantClient
authentication.oidc.claims.grantExp
authentication.oidc.claims.grantId
authentication.oidc.claims.grantResource
authentication.oidc.claims.grantSourceIssuer
authentication.oidc.claims.purpose
authentication.oidc.evidenceAudienceClaim
authentication.oidc.issuer
authentication.oidc.jwksSource
authentication.oidc.jwksSource.type
authentication.oidc.jwksSource.uri
authentication.oidc.maximumTokenLifetimeSeconds
authentication.oidc.principalClaim
authentication.oidc.requesterTagsClaim
authentication.oidc.requiredScopes
authentication.oidc.requiredScopes[]
authentication.oidc.revokedKeyIds
authentication.oidc.revokedKeyIds[]
authentication.oidc.tlsTrustProfile
authentication.oidc.tokenTypes
authentication.oidc.tokenTypes[]
authorityProfiles
authorityProfiles.*
authorityProfiles.*.actorKind
authorityProfiles.*.grantSourceIssuer
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
authorityProfiles.*.requesterClients
authorityProfiles.*.requesterClients[]
authorityProfiles.*.requesterTags
authorityProfiles.*.requesterTags[]
issuer
issuer.uri
kind
maximumHolderBoundBatchSize
project
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
requirements[].acquisition.holderPresented
requirements[].acquisition.holderPresented.selectorProfiles
requirements[].acquisition.holderPresented.selectorProfiles[]
requirements[].acquisition.holderPresented.source
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
requirements[].concepts[].constraints.minimumBytes
requirements[].concepts[].constraints.minimumItems
requirements[].concepts[].constraints.prefix
requirements[].concepts[].constraints.schema
requirements[].concepts[].constraints.schemeVersion
requirements[].concepts[].constraints.unique
requirements[].concepts[].handle
requirements[].concepts[].required
requirements[].concepts[].sdJwtVc
requirements[].concepts[].sdJwtVc.claim
requirements[].concepts[].sdJwtVc.disclosure
requirements[].concepts[].type
requirements[].concepts[].uri
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
requirements[].grantCeiling
requirements[].grantCeiling.actorKinds
requirements[].grantCeiling.actorKinds[]
requirements[].grantCeiling.audiences
requirements[].grantCeiling.audiences[]
requirements[].grantCeiling.authorities
requirements[].grantCeiling.authorities[]
requirements[].grantCeiling.valueOrigins
requirements[].grantCeiling.valueOrigins[]
requirements[].handle
requirements[].kind
requirements[].observationTimezone
requirements[].purposes
requirements[].purposes[]
requirements[].question
requirements[].referenceFrameworks
requirements[].referenceFrameworks[]
requirements[].representations
requirements[].representations[]
requirements[].subjectBinding
requirements[].subjectRoles
requirements[].subjectRoles[]
requirements[].subjectRoles[].cardinality
requirements[].subjectRoles[].role
requirements[].subjectRoles[].selectorProfiles
requirements[].subjectRoles[].selectorProfiles[]
requirements[].uri
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
signing.certificateChainFile
signing.format
signing.jwksPath
signing.maximumAssertionValiditySeconds
signing.publishedPublicJwkFiles
signing.publishedPublicJwkFiles[]
signing.revokedKeyIds
signing.revokedKeyIds[]
signing.verifierClockSkewSeconds
sourceConnections
sourceConnections.*
sourceConnections.*.endpoints
sourceConnections.*.endpoints[]
sourceConnections.*.endpoints[].authentication
sourceConnections.*.endpoints[].authentication.audience
sourceConnections.*.endpoints[].authentication.clientAssertionAudience
sourceConnections.*.endpoints[].authentication.credentialPlacement
sourceConnections.*.endpoints[].authentication.resource
sourceConnections.*.endpoints[].authentication.scope
sourceConnections.*.endpoints[].authentication.tokenEndpoint
sourceConnections.*.endpoints[].authentication.type
sourceConnections.*.endpoints[].baseUrl
sourceConnections.*.endpoints[].clientIdentity
sourceConnections.*.endpoints[].endpoint
sourceConnections.*.endpoints[].tlsTrustProfile
sources
sources.*
sources.*.connection
sources.*.factSchema
sources.*.inputs
sources.*.inputs.*
sources.*.inputs.*.selector
sources.*.inputs.*.selector.field
sources.*.inputs.*.selector.profile
sources.*.inputs.*.selector.role
sources.*.pack
sources.*.pack.artifactPrefix
sources.*.pack.digest
sources.*.pack.id
sources.*.pack.version
sources.*.posture
sources.*.projection
sources.*.projection.digest
sources.*.projection.entrypoint
sources.*.projection.script
sources.*.route
subjectBinding
subjectBinding.keyVersion
subjectBinding.secretRef
```
<!-- evidence-bundle-key-paths:end -->

### `runtime.yaml`

<!-- evidence-runtime-key-paths:start -->
```text
acquisitionCapabilities
apiVersion
audit
audit.destination
audit.path
audit.retentionDays
audit.rotateBytes
authority
authority.root
authority.target
kind
listener
listener.bind
listener.maximumConcurrentRequests
listener.maximumRequestBytes
listener.networkExposure
listener.requestTimeoutMilliseconds
listener.shutdownGraceMilliseconds
listener.tlsTermination
listener.trustProxyIdentityHeaders
metricsListener
metricsListener.bind
outboundTls
outboundTls.systemRoots
outboundTls.trustProfiles
outboundTls.trustProfiles.*
outboundTls.trustProfiles.*.caBundleFile
package
package.expectedDigest
package.root
secretProviders
secretProviders.environment
secretProviders.file
secretProviders.file.root
signer
signer.attemptTimeoutMilliseconds
signer.keyName
signer.keyVersion
signer.mount
signer.privateKeyRef
signer.type
signer.unixSocketPath
sourceAcquisition
sourceAcquisition.acquisitionDeadlineMilliseconds
sourceAcquisition.maximumDataOperations
sourceAcquisition.maximumResponseBytes
sourceConnections
sourceConnections.*
sourceConnections.*.allowedPrivateCidrs
sourceConnections.*.allowedPrivateCidrs[]
sourceConnections.*.endpoints
sourceConnections.*.endpoints[]
sourceConnections.*.endpoints[].anonymousHttps
sourceConnections.*.endpoints[].attemptTimeoutMilliseconds
sourceConnections.*.endpoints[].baseUrl
sourceConnections.*.endpoints[].credential
sourceConnections.*.endpoints[].credential.assumedLifetimeSeconds
sourceConnections.*.endpoints[].credential.audience
sourceConnections.*.endpoints[].credential.clientAssertionAudience
sourceConnections.*.endpoints[].credential.clientAssertionKeyRef
sourceConnections.*.endpoints[].credential.clientIdRef
sourceConnections.*.endpoints[].credential.clientSecretRef
sourceConnections.*.endpoints[].credential.credentialPlacement
sourceConnections.*.endpoints[].credential.maximumCacheSeconds
sourceConnections.*.endpoints[].credential.passwordRef
sourceConnections.*.endpoints[].credential.resource
sourceConnections.*.endpoints[].credential.scope
sourceConnections.*.endpoints[].credential.tokenEndpoint
sourceConnections.*.endpoints[].credential.tokenRef
sourceConnections.*.endpoints[].credential.type
sourceConnections.*.endpoints[].credential.usernameRef
sourceConnections.*.endpoints[].credential.valueRef
sourceConnections.*.endpoints[].endpoint
sourceConnections.*.endpoints[].maximumConcurrency
sourceConnections.*.endpoints[].maximumResponseBytes
sourceConnections.*.endpoints[].mtlsIdentity
sourceConnections.*.endpoints[].mtlsIdentity.certificateRef
sourceConnections.*.endpoints[].mtlsIdentity.keyRef
sourceConnections.*.endpoints[].tlsTrustProfile
sourceConnections.*.id
sourceConnections.*.outboundTls
sourceConnections.*.outboundTls.trustProfiles
sourceConnections.*.outboundTls.trustProfiles.*
sourceConnections.*.outboundTls.trustProfiles.*.caBundleFile
sourceExtracts
sourceExtracts.*
sourceExtracts.*.path
```
<!-- evidence-runtime-key-paths:end -->
