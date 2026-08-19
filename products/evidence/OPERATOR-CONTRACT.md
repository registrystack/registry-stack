# Evidence Version 1 operator contract

Status: Partially implemented Version 1 operator contract

This document defines the supported native deployment and operator duties for
the Evidence Version 1 `evidence` binary.

## Supported deployment

The supported native deployment has:

- one `evidence` process in one operator-controlled trust domain;
- one reviewed, immutable governed evidence bundle and one closed operator
  runtime file, both mounted read-only at startup;
- one reviewed OIDC access-token profile with exactly one trusted issuer and
  exact audience, token type, and algorithm allowlists;
- one configured principal claim with no `client_id`, `azp`, header, or request
  fallback;
- reviewed requester and subject-authority mappings for named requirement
  revisions, purposes, audiences, roles, selector profiles, and value origins;
- fixed, bounded HTTP JSON source requests with fixed or tagged selector/prior-fact-bound paths,
  fixed non-secret headers, client-side response projection, denied redirects,
  logical private-CA trust profiles, and generic Basic, static Authorization
  header, static API-key, or OAuth 2.0 client-credentials authentication through
  secret references, the last authenticating by client secret or by private-key
  JWT assertion;
- optional credential-free source access only for `assuranceProfile: local`
  at a canonical numeric-loopback HTTP origin with an explicit non-zero port;
- fixed reviewed SQL statements over regular, checkpointed, read-only SQLite
  extracts bound by logical profile, with publisher metadata, bundle-declared
  maximum age, exact parameter and result contracts, and row, cell,
  statement-step, elapsed-time, response-size, and concurrency bounds;
- one active ES256/P-256 service signing key whose `kid` is its RFC 7638
  thumbprint, explicit published and revoked key sets, flattened JWS JSON
  success responses, and public key discovery at
  `/.well-known/evidence/jwks.json`;
- a non-exportable, pinned-version Vault/OpenBao Transit key reached through a
  workload-local Unix-socket proxy for production and evidence-grade serving;
- keyed JSONL audit on storage whose durability the operator has explicitly
  established;
- production HTTPS exposure, dependency timeouts, per-source concurrency
  limits, per-principal rate controls, and bounded failed-selector attempts.
- an optional governed public provider advertisement, generated and sealed as
  `catalog.jsonld`, served unchanged at `GET /catalog.jsonld`, and containing
  no requester entitlement or trust decision.

Multiple evidence definitions may be enabled only when they share the same
operator, deployment lifecycle, audit boundary, and failure domain. Mutually
distrustful issuers or customers require separate processes and bundles. The
authentication profile admits exactly one token issuer and one set of claim
names, so a second issuer, or one issuer whose clients carry the same authority
under different claim names, requires a second deployment even when the
operators trust each other. Evidence Version 1 has no application database and
persists no selector, source, evidence, or response data. An external durable
audit service may own its own storage.

A gateway may provide publication, protocol integration, routing, and
additional rate controls. Evidence still validates its configured identity
context and independently enforces requirement, purpose, subject authority,
selector, audience, disclosure, signing, and audit rules. Unsigned headers or
caller request fields never substitute for authenticated authority.

Version 1 accepts bearer tokens only. A token carrying a proof-of-possession
confirmation claim is denied rather than accepted as an ordinary bearer, because
Evidence validates no sender proof and accepting one would discard the
constraint the authorization server issued the token under. An authorization
server that binds tokens to DPoP keys or client certificates must issue Evidence
clients unbound tokens.

## Governed bundle and operator runtime

The operator supplies one atomic bundle containing the approved YAML,
preparation scripts, extraction scripts, derivation scripts, schemas, codelists,
mappings, and fixtures. A separate closed `runtime.yaml` binds the bundle to
one listener, bundle directory, secret root, audit destination, signer
transport and pinned version, and local TLS trust files. It also records which
gated acquisition kinds this deployment enables, which is a decision the
deployment withholds by default rather than one it grants. The runtime file
cannot override service identity, trust domain,
authentication, authority, sources, request policy, scripts, disclosure, rate
limits, signing policy, or audit fail-closed behavior. The two content hashes
identify the exact loaded inputs but are not trust decisions. The operator
establishes trust through review, distribution controls, read-only mounts, and
process replacement for every revision.

Every bundle explicitly declares `assuranceProfile: local`, `production`, or
`evidence-grade`. Local is the only authoring profile and may omit a
requirement's fixture reference. It changes no other runtime trust boundary and
is carried in discovery, signed assertions, SD-JWT VC responses, audit, and
verification policy. Production and evidence-grade require one captured,
complete fixture suite per requirement under the existing bundle validator.
There is no fixture receipt, certification command, or second serving path.

There is no runtime upload, editor, approval API, hot reload, merge, mutation,
governed-field override, or fallback bundle/runtime file. Startup and readiness
fail if either input is incomplete, inconsistent, mutable, uncompilable, unsafe
in combination, or cannot bind every
allowed role, selector profile, value origin, authority path, and source
placement.

Before deployment, the operator must review the entire simultaneously enabled
bundle as one disclosure surface. This review includes threshold ladders,
overlapping categories, increasingly precise regions, jurisdiction variants,
coexisting revisions, differing requester entitlements, and relationship
combinations. Rate controls and after-the-fact audit analysis do not make an
unsafe bundle safe.

### Production candidate handoff

`evidencectl build` compiles an editable project and one explicit production
target into a new candidate directory. It is a create-only authoring command,
not an approval, promotion, deployment, key-generation, caller-registration,
or service-start command. It runs the real `evidence` binary through its
bundle-only validation entry point and evaluates every referenced fixture
without generating a temporary signing key or other validation secret. It then
atomically publishes a candidate with a copied `runtime.yaml` and one closed
`bundle/`. The candidate contains no production private key, credential, token,
local request, audit entry, or source response.

The operator reviews and transfers the exact candidate, records its bundle
revision, and independently provisions the signing key, audit HMAC key,
subject-binding HMAC key, and source credentials below the runtime's secret
root. Secret ownership and mode requirements remain unchanged: each referenced
secret is a regular owner-only file accepted by the eventual service identity.
The bundle and runtime must be non-writable to that identity. The copied
runtime is target-specific; its revision and bound private-CA bytes are not the
bundle revision, and signed assertions continue to carry only a configuration
revision as `configurationRevision`. That value is scoped to the one requirement
the assertion answers, not to the whole deployment, so it is neither the runtime
revision nor the bundle revision.

Run the following grouped handoff after provisioning and whenever candidate
bytes, runtime bindings, trust files, or secrets change:

```sh
evidencectl doctor --project '<candidate>'
evidencectl fixtures run --project '<candidate>'
evidence --runtime '<candidate>/runtime.yaml' serve
```

`doctor` is advisory for local artifact posture; the real runtime remains the
authority for startup. Route traffic only after `/ready`. For one approved
synthetic deployment subject, retain the signed response, verify it against an
independently prepared `production` policy and trusted keys, and run
`evidence verify-audit` over the resulting audit chain.

An existing HTTPS OIDC issuer and Registry Mint are equal authentication
choices for Evidence. Mint is a separate process and separately authored
configuration. When used, the operator runs `mint check --config <mint.yaml>`
and the read-only paired check
`evidencectl doctor --project <candidate> --mint-config <mint.yaml>`. The
paired check compares only issuer, JWKS URI, audiences, signing algorithm,
token type, and configured principal, requester-tag, evidence-audience,
grant-id, grant-authority, and optional actor claim names. It does not decide
authority, register a client, copy Mint material, or issue a token.

Docker Compose remains a documented deployment adapter, never build output.
It mounts the approved candidate bundle unchanged and read-only, supplies a
separate container runtime file and owner-readable secret mounts, gives only
the audit path persistent writable storage, binds Evidence privately, and
keeps public TLS and routing operator-controlled. A Compose deployment with
Mint retains its public HTTPS issuer and JWKS URI: internal plain-HTTP service
names do not replace either value. Container images and their provenance are
operator responsibilities; Version 1 proves this journey with released bare
binaries, not generated containers or orchestrator manifests.

### Git-managed environments

Use one protected branch and complete named environment targets. The maintained
reference layout is under
[`reference/deployment-targets/`](reference/deployment-targets/):

```text
shared/
  evidence-project/
environments/
  local/
    evidence/{governance.yaml,runtime.yaml,public-keys/}
    mint/{mint.yaml,clients/,public-keys/}
  staging/
    evidence/{governance.yaml,runtime.yaml,public-keys/}
    mint/{mint.yaml,clients/,public-keys/}
    transit/{proxy-configs/,policies/}
  production/
    evidence/{governance.yaml,runtime.yaml,public-keys/}
    mint/{mint.yaml,clients/,public-keys/}
    transit/{proxy-configs/,policies/}
```

Shared Evidence questions, scripts, schemas, and fixtures are authored once.
Each environment target is nevertheless complete. It contains its own service
identity, issuer, endpoints, audiences, public keys, runtime paths, pinned
Transit versions, and logical secret references. There are no overlays,
environment branches, symlinks, runtime substitutions, or inherited defaults.
Promote a reviewed source revision, then build separate staging and production
candidates from their complete targets.

Git contains public JWKs and non-secret Transit proxy and policy configuration.
It never contains private JWKs, HMAC masters, provider tokens, auto-auth
credentials, access tokens, live responses, or real identifiers. A target
template uses conspicuous replacement values and is not deployable until those
values and public JWKs have been reviewed and replaced.

## Discovery of available evidence

Evidence Version 1 answers "what may this caller request?" with authenticated
`GET /v1/evidence-definitions`. Availability is requester-relative: the
definition must exist in the exact deployed bundle and exactly one authority
path must match the verified token, requirement, purpose, audience, complete
subject-role set, selector profiles, and value origins. The runtime never
publishes a global unauthenticated list of requester entitlements or invocable
definitions. Its separate public provider advertisement contains only closed
service facts for external indexing.

Discovery uses five separately trusted surfaces:

| Artifact | Purpose | What it does not do |
|---|---|---|
| RFC 9728 protected-resource metadata | Binds the exact configured public Evidence origin to one authorization-server issuer, the Evidence JWKS location, and header-only bearer transport. | It contains no requester-scoped definition or entitlement data and does not replace HTTPS or an out-of-band trust pin. |
| Generated Evidence OpenAPI | Describes `GET /v1/evidence-definitions`, `POST /v1/evidence`, `POST /v1/evidence/batch`, operational routes, envelopes, media types, and safe problems. | It contains no deployment definitions or entitlements. |
| Public provider advertisement | Serves the exact packaged `catalog.jsonld` bytes at `GET /catalog.jsonld`, with public service identity and one distinct binding for each exact Evidence Type and compatible response profile. | It contains no requester-specific request shape, entitlement, source configuration, credential, or trust decision. |
| Authenticated definition response | Lists the exact complete request shapes available to this verified token at this bundle revision, each with the configuration revision an assertion for that one requirement carries. | It performs no provider access, does not grant authority, and is not a global catalog. |
| Static onboarding material | Gives an approved consumer token-acquisition instructions, human descriptions, legal context, endpoint trust, and verifier policy through the existing API catalog, developer portal, configuration repository, or bilateral process. | It is not accepted by the runtime and grants no authority. |
| Evidence JWKS | Publishes the active and retained public verification keys. | It is not a trust anchor and contains no definition or entitlement metadata. |

Each item in `definitions` is one complete invocable combination, not a
cartesian product for the client to assemble. It contains:

- one stable complete-definition handle, the requirement's own configuration
  revision, and its effective response formats;
- requirement and Evidence Type identifiers, under the document's effective
  audience, legal issuer, and technical provider;
- one allowed purpose;
- stable output handles, concept identifiers, required or optional status,
  value forms, and any list cardinality and uniqueness constraints;
- complete subject roles, cardinality, selector profile, and value origin; and
- safe selector field types and bounds. A controlled-code field exposes its
  governed scheme identifier and version, never the bundle file path or code
  values.

The endpoint omits a request shape unless its token-owned context or grant
selector values are present and valid. If no authority path matches, the
response has an empty `definitions` array. If multiple authority paths match
the same shape, that shape is omitted because `POST /v1/evidence` would deny it
as ambiguous. Discovery consumes the same per-principal request-rate budget as
evidence creation. It performs no source credential resolution, source call,
signing, or evidence-data audit write. The operation accepts no query
parameters or request body; callers cannot filter it into a definition oracle.

Human-readable titles, descriptions, legal references, examples, and support
contacts remain static onboarding documentation. The runtime response and that
documentation must not include source origins or identifiers, source paths,
response projections, scripts, adapter parameters, secret references,
internal requester-tag values, authority-profile identifiers, selector values,
codelist values, or unrelated definitions. Possessing discovery metadata does
not authorize its recipient; the identity provider must issue the configured
claims, and Evidence re-authenticates and re-authorizes every evidence request.
The public provider advertisement supports indexing and coarse service
matching only. Its `serviceId` identifies the native service, while each
derived `bindingId` keeps one Evidence Type and compatible response profile
correlated. A client still uses authenticated definition discovery to learn an
invocable request shape for its verified token.

The publication workflow is:

1. Review the complete bundle and its combined disclosure surface.
2. Run `evidence check` and every referenced fixture, and record the exact
   governed bundle revision.
3. Run the production `evidencectl build` flow, which generates and seals
   `catalog.jsonld`, then publish the generic OpenAPI, provider advertisement,
   and static onboarding material. Configure token issuance and verifier trust
   through the same governed process.
4. Obtain a token, call `GET /v1/evidence-definitions`, and bind each returned
   `configurationRevision` to the requirement it is published under. A relying
   party pins the requirements it consumes, not the deployment.
5. Construct requests only from one returned complete shape. Do not combine
   subjects, profiles, purposes, or fields across items.
6. On a relevant bundle or trust change, update onboarding material and
   coordinate rollout with the relying parties whose requirements changed
   revision. Clients observe a new revision through authenticated discovery,
   not by probing problem responses.

Version one does not implement a searchable, mutable, or federated catalog
inside Evidence, a registration editor, or a `describe` CLI command. An
external catalog may index the closed provider advertisement. `/catalog.jsonld`,
`/health`, `/ready`, `/openapi.json`, public problems, and JWKS never reveal
requester entitlements, enabled request definitions, or selector profiles.

## Requester authority and purpose

Authorization keys off the requester tags in the configured claim, not off the
requester principal. The principal is used only for rate accounting and audit
pseudonyms and never decides access. Two clients presenting the same tags hold
the same access, so differentiated access is expressed by issuing different
tags. An authority profile matches only when every one of its declared tags is
present, and exactly one authority path may match a request: zero paths and two
or more paths both deny. Startup validation does not detect two paths covering
the same requirement, purpose, and subject tuple, so the operator owns that
review.

The request declares its purpose and any purpose the matched grant does not
carry is rejected. Within the granted set the caller still chooses, so a
declared purpose is an authorized selection rather than an identity-provider
attestation. Where the purpose must be attributable to the token issuer, issue
a distinct requester tag per purpose and give each tag an authority profile
granting only that purpose. Purpose is then bound to a verified claim with no
change to Evidence.

Purpose is enforced rather than advisory in either arrangement. An unauthorized
purpose is denied before credential acquisition and source contact, purpose is
an input to every subject binding and audit pseudonym so one subject is not
linkable across purposes, and purpose is inside the signed payload where a
verifier rejects an assertion whose purpose does not match its expected policy.

Purpose does not narrow disclosure. A requirement returns the same concepts and
disclosure forms for every purpose that may invoke it. A purpose that justifies
only a coarser answer needs its own requirement and its own place in the
combined disclosure review.

Native rate controls are uniform. The configured request, burst, and
failed-selector limits are single values applied to every principal, and the
request-rate scope deliberately excludes purpose, audience, and requirement so
a caller cannot multiply its budget by varying them. Per-client quotas are a
gateway responsibility.

`POST /v1/evidence/batch` charges the request bucket once with cost equal to
its complete item count. The debit is atomic: capacity for all items is
reserved or the whole request returns `evidence.rate_limited` and charges nothing.
Authentication occurs once and all items use one evaluation instant. Every
item is validated and authorized before any credential is resolved or source
is contacted.

Rate limits are tracked per process, in in-process memory, never shared across
replicas. Running N instances behind a load balancer therefore multiplies
every configured limit by N; this matters most for the failed-selector budget,
since that budget is the selector-enumeration defense rather than merely a
throughput knob. A restart also resets every budget to full, because buckets
are keyed on an in-memory monotonic clock rather than persisted. Tracked keys
are bounded at 100,000; a new principal beyond that ceiling is refused with a
capacity error until entries age out of the prune window. Reaching it requires
100,000 distinct authenticated principals within the window, so treat it as a
capacity ceiling worth alerting on rather than a practical denial-of-service
vector.

The listener request timeout bounds admission, concurrency queueing, and body
collection. It is not a total evaluation deadline. Once a protected evaluation
starts, Evidence lets it finish under the separately bounded OIDC and source
operations so cancellation cannot bypass required audit or signed-response
release ordering.

## Response formats

The singular Evidence operation releases one stateless assertion.
`responseFormats` decides which serializations may carry it, and the closed values are `signed-jws`,
`unsigned-json`, and `sd-jwt-vc`. Both the immutable bundle and every authority
grant declare the list, both default to `[signed-jws]` alone, and both must
keep `signed-jws` enabled. Startup rejects a duplicate or unknown value and
rejects any list that drops the signed default.

The two lists are intersected and never unioned. A format is releasable only
where the bundle and the one complete matched grant both name it, so enabling a
format bundle-wide grants nothing by itself, and a grant cannot widen beyond the
bundle. Requesting a format outside the intersection is refused with the
ordinary `evidence.denied` problem before credential acquisition and source
access, and the refusal does not reveal which layer withheld it. An `Accept`
that names no known format at all, or that is duplicated, combined,
parameterized, or weighted, returns `format.unsupported` with HTTP
406, also before source access.

```yaml
# the immutable bundle: the ceiling
responseFormats: [signed-jws, sd-jwt-vc]

# the grant: the actual authority, never wider than the bundle
- requirement: urn:example:requirement:adult-status:v1
  purpose: eligibility
  audienceFrom: authenticated-requester
  responseFormats: [signed-jws, sd-jwt-vc]
```

The requester selects among enabled formats with an exact `Accept`:
`application/jose+json` (or a missing `Accept`, or `*/*`) for the signed
default, `application/vnd.registrystack.evidence-unsigned+json` for the visibly
unsigned envelope, `application/dc+sd-jwt` for the SD-JWT VC. Selection never
changes evaluation, disclosure, or audit obligations. Each release records its
own `responseProtection` in the disclosure-release audit event, with the closed
values `signed`, `unsigned`, and `sd-jwt-vc`; `signingKeyId` is present for the
two cryptographically protected modes and forbidden for unsigned output.

Enabling `sd-jwt-vc` adds a serialization, not a credential lifecycle. There is
no issuance session, holder binding ceremony, status list, revocation, or
presentation verification, and `/.well-known/jwt-vc-issuer` publishes no
per-requester or per-requirement information. The `vct` claim is the
requirement's declared `isConformantTo` identifier, so the credential type is a
governed bundle decision rather than a client choice. The subject identifier
stays the audience-scoped pseudonym, so the same person requested for a
different audience yields a different identifier and the credential is not a
general-purpose multi-verifier credential.

A request may carry an optional `holderKey`, which is echoed into the `cnf`
claim and is meaningful only for the SD-JWT VC format. Only a public EC P-256
JWK is accepted; an unacceptable key is rejected as a malformed request
alongside the nonce check, before authentication, credential acquisition, and
source access. The key never reaches authorization, selectors, Rhai, sources,
audit, or the signed-JWS payload. Evidence issues no key-binding JWT, requires
none, and verifies none, so `cnf` is an unverified caller-supplied
convenience for whatever presentation layer the operator runs elsewhere.

Signing failure remains fail-closed for every protected format. A deployment
that cannot sign returns a safe transient failure and never downgrades an
SD-JWT VC request to unsigned output or to the signed default.
[The SD-JWT VC demo](SD-JWT-VC-DEMO.md) exercises this whole path locally.

The multi-subject request-batch route has a separate exact media type,
`application/vnd.registrystack.evidence.request-batch+json`, and does not
participate in the singular response-format intersection. It accepts one to
sixteen ordered audience-scoped subject sets under one requirement and purpose,
with a canonical pairwise-distinct nonce per item. Its only available result is
a flattened signed JWS. Every condition the singular evaluation contract
exposes as unavailable may appear as `evidence_not_available`; mixed and
all-unavailable envelopes are successful `200` responses. Any other failure
aborts the outer request with the existing safe Problem Details and no partial
release. The exact envelope is capped at 1 MiB.

This is not the holder-bound issuance batch. Holder-bound batching stays on
`POST /v1/evidence`, receives several holder keys for one subject evaluation,
and uses `application/vnd.registrystack.evidence.batch+json`. The request-batch
route accepts no holder keys and cannot emit SD-JWT VC or its issuance
container.

## Secrets and keys

Source credentials and local-authoring private signing material are supplied
only through the supported secret-reference mechanism. Production and
evidence-grade private signing material remains inside Vault/OpenBao Transit
and is reached through a workload-local Unix-socket proxy. Provider tokens and
auto-auth credentials stay in the proxy boundary and never enter Evidence.
Secret material does not appear in bundle YAML values, Rhai, command arguments,
environment dumps, logs, audit, errors, snapshots, or generated contracts.
Private JWK parsing uses an explicit ES256/P-256 allowlist. Missing or failed
signing is fail-closed and never releases an unsigned success response.

The operator commits one active public JWK and zero or more additionally
published public JWKs. Every key is exact ES256/P-256 public material and its
43-character `kid` is derived as its RFC 7638 thumbprint, never configured
separately. Active and published identifiers are disjoint from
`revokedKeyIds`. The JWKS contains only the active and published keys. During
planned rotation, retain the predecessor for at least the maximum assertion
validity plus allowed clock skew. Emergency revocation removes it immediately,
and denylisting takes precedence over a cached key set. The JWKS is discovery,
not a trust anchor. Verifiers obtain
the provider identity and JWKS location through governed configuration, pin
that trust, allowlist the expected algorithm, and resolve `kid` only within the
trusted key set. They never follow a message-provided remote key URL.

A valid signature proves that the technical provider controlling the key signed
the exact payload. It does not prove the source fact is true, confer legal
notarization, create a qualified electronic signature, or create a holder
credential. Governance establishes the provider's authority to act for the
named legal issuer.

### Service signing-key rotation

Planned rotation is an overlap, switch, drain sequence:

1. Create the next non-exportable Transit key version and export only its
   public key.
2. Commit that exact JWK under `public-keys/<thumbprint>.jwk.json` and add its
   path to `publishedPublicJwkFiles`.
3. Deploy and restart every replica so all of them publish both keys.
4. Wait at least the relying clients' maximum metadata-cache interval before
   activating the next key. The progressive client caps that interval at 600
   seconds. This ensures a client that refreshed immediately before publication
   can learn the next key before Evidence signs with it.
5. Keep the named Transit key's minimum signing version low enough for both
   pinned application versions. The ordinary Vault/OpenBao ACL grants the
   named key path, not a request-body key version.
6. Move the next path to `activePublicJwkFile`, keep the predecessor in
   `publishedPublicJwkFiles`, pin `signer.keyVersion` to the next version, and
   deploy and restart.
7. After `maximumAssertionValiditySeconds + verifierClockSkewSeconds`, remove
   the predecessor public key and raise the Transit key's minimum signing
   version, or otherwise disable the predecessor provider-side.

The full overlap therefore accounts for both metadata-cache propagation before
the switch and the maximum assertion lifetime plus clock skew after the switch.

Emergency rotation has no overlap guarantee. First disable provider signing
authority for the compromised version. Then remove its public JWK, add its
thumbprint to `revokedKeyIds`, activate a replacement or leave the service
unavailable, and restart every issuer and verifier that consumes the key set.
If the compromised key issued Mint access tokens, add that Mint identifier to
Evidence authentication `revokedKeyIds` in the same incident rollout. This
shortens availability when necessary and is intentionally stronger than the
ordinary validity window.

## Source and selector controls

Each subject role admits only named selector profiles from the trusted bundle.
Each profile has one exact deployment-defined scalar field set, byte and
aggregate bounds, permitted value origin, and fixed source placement.
Alternative sufficient inputs and additional disambiguators are separate named
profiles. A national identifier is optional and possession of any selector
value never creates authority.

The authoritative provider owns record lookup. Evidence accepts only
`match`, `no_match`, or `ambiguous`; only `match` carries facts. Evidence does
not fetch broad candidates, follow pages, score candidates, choose a provider
record, or expose counts, records, confidence, near-match hints, or per-field
diagnostics. A reviewed deterministic derivation may compare its explicitly
declared authorized selector fields with complete facts from one uniquely
resolved authoritative record. When count plus one minimized result is unavailable, the fixed
request may retrieve at most two minimally projected results solely to detect
ambiguity.

Every source declares its acquisition posture. A single requirement inherits
its source posture. A requirement that acquires from more than one source
takes the weakest posture among them:

| Posture | Operator claim |
|---|---|
| `source-derived` | Full acquisition and disclosure minimization |
| `field-projected` | Strong acquisition and disclosure minimization |
| `record-transformed` | Disclosure minimization only |

The operator must not describe a `record-transformed` integration as full
lifecycle minimization. Rust applies every source's extended JSON Pointer
projection after bounded JSON parsing and before extraction, but the posture
describes the pre-projection wire response. The fixed request mock must prove
provider-specific field selection where claimed. A provider whose wire response
cannot be closed at that boundary must use `record-transformed`, even when
local projection and Rhai emit only narrow facts.

A statement returning one aggregate is `source-derived` on the same terms as an
API returning that aggregate, because the narrow fact is what crossed the source
boundary. A later derivation may map that fact to the asserted concept without
changing the acquisition posture.

Bundle-fixed headers cannot set authentication, routing, cookies, framing,
forwarding, proxy, or tracing fields. Tagged path placeholders occupy complete
segments and Rust expands them directly from already authorized selectors or,
only for a fixed fetch, a scalar property in the validated search FactSet.
Scripts render only query pairs and one JSON body and cannot select the binding
origin.

Each requirement declares exactly one acquisition kind. `single` and
`search-then-fetch` are the frozen Version 1 forms; `search-then-fetch` fixes
both source identifiers at startup, performs the fetch only after a unique
schema-valid search match, and has a hard two-call ceiling.

`search-then-fetch-set` is a gated kind added after that surface froze. It
widens the fixed fetch into two to four declared members, executed in the order
the bundle declares them, each receiving only the `factInputs` allowlist it
declares out of the validated search FactSet. Its ceiling is one plus the
member count, fixed by the bundle before any request is made, and it requires a
`maximumAcquisitionMilliseconds` between one and thirty seconds. Two gates open
it, and both are required: the bundle names the kind under
`acquisitionCapabilities`, and this file names it under
`acquisitionCapabilities` as well. Absent means enabled nothing, so a
deployment that never made this decision keeps serving exactly what it served
before. A bundle using the kind without the deployment's entry is refused
before the listener binds; `evidencectl doctor` names this file and the entry
to add.

No acquisition kind is a workflow surface: neither a response nor Rhai may
choose a source, origin, method, credentials, retry, or further call.

The optional `source-batch` capability reduces physical HTTP calls for the
multi-subject request-batch route. It is independently named in the bundle and
`runtime.yaml`, and the selected fixed-path `http-json` source must also carry a
`batch` block with `maximumItems`, batch preparation and extraction scripts, a
response schema, and a projection. A block without either gate fails startup.
An omitted block, a different transport, a path template, any multi-stage
acquisition, or an outer item count above the source ceiling selects ordinary
sequential execution in request order before I/O. Once an optimized attempt
starts, it never retries as sequential fanout.

The one optimized call reuses the ordinary method, origin, fixed path,
authentication, headers, TLS, redirect denial, timeout, maximum response bytes,
concurrency semaphore, and preparation limits. `prepare_batch` sees only opaque
integer slots paired with minimized selectors and closed parameters.
`extract_batch` sees only the validated projection, parameters, and slot list.
It must return an exact slot bijection over ordinary lookup results. Missing,
duplicate, extra, negative, or out-of-range slots abort the whole request.

A source may name a logical TLS trust profile. `runtime.yaml` binds it to one
bounded PEM CA file. Hostname and fixed-origin verification remain mandatory;
there is no insecure or trust-all mode. Version 1 ignores `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` and has no application-level proxy.

## Audit and operational data

After successful authentication, the configured audit sink must durably accept
a minimal authorization-refusal event before a generic `403` is returned. It
must durably accept one access-attempt event before each actual evidence-data
source read and the disclosure-release event after signing and before response
release. Any failure blocks the applicable action and returns a generic `503`
when an HTTP response remains possible.

Authorized-material audit events contain reviewed identifiers and decision
categories, never raw selector values, per-field selector hashes, source
values, prior facts, intermediate lookup identifiers, Supported Values,
credentials, tokens, or raw subject identifiers. When correlation is required,
one keyed, domain-separated, versioned pseudonym covers the complete canonical
role, selector-profile identifier, ordered field names, and selector value
bundle. It must not be globally stable across purposes or audiences.

After successful authentication, every authorization refusal writes one
standalone minimal native event before the generic `403` is returned. The event
contains only the operation and event identifiers, assurance profile, bundle
revision, scoped requester pseudonym, optional actor pseudonym, closed
`not-authorized` decision and safe error category, timestamp, and duration. It
omits the requested requirement, purpose, subjects, unmatched authority,
selector information, response protection, source, and evaluation material.
The requester and actor pseudonym scope binds the operator trust domain,
requested purpose, and authenticated audience, while those scope inputs remain
omitted from the event. This prevents a new cross-purpose or cross-audience
identifier. Request-rate accounting remains separately scoped to the principal,
so varying purpose cannot multiply or evade the request budget.
The audit sink must durably accept that event. If it cannot, Evidence returns
the generic `503` instead of the `403`. Authentication, malformed-request, and
invalid-selector failures remain operational-only and create no native audit
event.

Operational logs contain route templates, the public `trace_id`, the
server-minted audit operation identifier, duration,
status category, the public problem code, and safe internal error categories
only. The internal category is narrower than the public problem code but is
drawn from the same kind of fixed, closed set of service-chosen strings. It
names the internal step that failed, never what that step saw, and it carries
no counts. A record that was not found and a record that matched more than once
share one category, so the category is never a way to tell them apart. A
missing required fact and an inconsistent derivation input do keep separate
categories: separating those two is what lets an operator repair a deployment,
and the public problem code reports both as the same shape regardless. A
request that raises no failure logs a fixed placeholder in its place. Request
bodies, selector profile identifiers and values, source requests and responses,
authority grants, Rhai inputs, credentials, tokens, and disclosed values are
excluded from logs, metrics, traces, snapshots, panics, and errors. The public
trace identifier is a bounded correlation value, not an audit identity, and
caller `tracestate` is never echoed.

Audit and operational logging are separate channels and operators must not
confuse them. The audit chain is the accountability record: durable, complete,
tamper-evident, and it has no severity levels and no way to turn records off.
Every authorized evidence evaluation writes one access-attempt event durable
before each actual source read and the disclosure-release or terminal event
required by its outcome. Every authenticated authorization refusal writes one
minimal denial event before its response. Those gates are pinned by frozen
Version 1 security invariants and are not configurable. The `tracing` channel
is the operational and diagnostic record: it has levels, it is buffered and
lossy, and it is cheap. The rule for operators and integrators is:
accountability facts belong in the audit chain and never only in tracing, and
operational noise belongs in tracing and never in the audit chain. If an
adopter needs more detail than the frozen audit record carries, which some
regulators require, the correct shape is a separate operational log keyed by
the audit record's `eventId`, not a verbosity setting on the chain.

The refusal event uses the distinct
`registry.evidence.audit.authorization-refusal/v1` discriminator in the same
keyed envelope and chain as `registry.evidence.audit/v1`. Updated semantic
readers accept both closed shapes. Opaque keyed-chain verification remains
compatible because it does not interpret the event payload. Older Version 1
schema validators and local audit readers reject or cannot display the refusal
shape, so operators must update semantic audit readers and the service together
before routing traffic to the changed runtime.

The request-batch route adds
`registry.evidence.audit.request-batch/v1` to that same keyed chain. One access
event precedes every physical source call and names the bounded zero-based item
indices it carries. `itemGroups` partition those indices by identical authority
object and ordered pseudonymized subject set, so different grants and authority
kinds remain accountable without recording selectors. One terminal release
covers all item groups and every ordered outcome. It carries an evidence id per
available item and a signing key id only when at least one assertion was signed;
an all-unavailable release carries neither signing key use nor evidence ids.

Any other failure after authorization produces one value-free terminal failure
and no partial release. Request nonces, raw selectors, facts, source bodies,
response bodies, JWS protected headers, payloads, signatures, and signing
material are forbidden from every batch-native event. The service serializes
and size-checks the complete envelope, durably appends the release, and returns
the same bytes. Operators must update semantic audit readers to recognize all
three native discriminators before deploying the request-batch runtime.

The serving process writes those records as line-delimited JSON on standard
output, one per served request, and `EVIDENCE_LOG` selects verbosity with a
default of `info`. Offline commands print their own result and emit no
operational records. Every response, including responses to unrouted paths,
carries a W3C `traceparent` header. Evidence reuses a valid inbound trace
identifier or mints one, and returns it as `traceId` in a problem body. It
never exposes the server-minted audit operation identifier and never echoes
caller `tracestate`.

Telemetry is off by default. Setting `metricsListener` in `runtime.yaml` serves
`GET /metrics` in Prometheus text format on a second private binding, which must
differ from the evidence listener binding and is subject to the same
loopback-or-private-address rule. The evidence listener never serves `/metrics`,
and the metrics listener never serves evidence. Series carry only the registered
route template, request method, status category, and reviewed problem code, so
series cardinality is bounded by the deployed contract and cannot grow with
caller input. A path that matches no route is counted as `unmatched` and a
method outside the served set as `other`, so a caller cannot write a label
value. Operators should still reach this listener only from their own network,
since request rates per route are operational information. The series and
labels it publishes are in [Metrics reference](#metrics-reference).

The operator owns audit retention, backup, restore, access control, key
rotation, and chain verification for the selected durable sink. A deployment
profile may require more reviewed metadata or retention, but it cannot silently
weaken the native privacy contract.

The audit master feeds two HKDF-separated subkeys: one for chain integrity and
one for identifier pseudonyms. The subject-binding master is a separate secret
reference and must resolve to different bytes. This separation prevents a
pseudonym oracle or subject-binding use from becoming a chain-MAC oracle while
keeping the operator ceremony to two independent masters.

Exactly one Evidence process may write a given audit path. The sink takes an
exclusive OS advisory lock on `<auditStorage.path>.lock` at startup; a second
process pointed at the same path fails at startup with a sink-locked error
rather than starting and corrupting the chain. The reason is structural, not
defensive: the audit log is a keyed hash chain whose head is held in process
memory, so two concurrent writers would interleave records and destroy tamper
evidence. Deployment shape follows from this: one replica per audit path,
active/passive rather than active/active. Use a readiness probe and
restart-on-failure to recover from a crashed writer, never a second concurrent
replica.

At process startup the runtime recovers the chain head from the newest sealed
segment, if one exists, by reading only that segment's last record, then fully
verifies only the active segment from that head. Restart time is therefore
bounded by the active segment rather than by the volume of retained history:
it does not grow as sealed segments accumulate. The accepted tradeoff is that
corruption inside an already sealed segment is not detected at startup; only an
out-of-band verification pass over the whole audit directory, sealed segments
included, detects it. Steady-state appends and readiness probes validate the
active segment's pinned identity and fingerprint plus the expected tail and
length without rescanning the growing file. Any external replacement or
modification of the active segment or the lock file makes readiness and future
appends fail closed. Operators should run that out-of-band verification,
`evidence verify-audit`, covering every segment, during backup, restore, and
incident procedures, and on whatever cadence their audit retention policy
requires; it is what proves sealed history was not tampered with.

## Audit chain rotation and rollback

Audit-segment rotation, described later in this section, keeps one key and one
continuous epoch. Rotating the audit master is different and always starts a
new epoch:

1. Drain traffic and stop the sole writer.
2. Run `evidence verify-audit`; record the old chain head, bundle revision,
   runtime revision, path, and `hashKeyVersion` in the change record.
3. Archive the old runtime, audit-master secret under its governed secret
   controls, every segment, lock-file disposition, and recorded head together.
4. Generate a fresh independent audit master, increment `hashKeyVersion`, and
   select a fresh empty `auditStorage.path`. Do not rename or reuse the old
   active path.
5. Run `evidence check --require-runtime-dependencies` and the full handoff
   checks, start the new process, and
   route traffic only after readiness succeeds.

Never append a new audit master to an existing chain. Startup with replacement
master bytes against existing segments fails closed. Old and new epochs verify
independently with their archived runtime and master; neither is a continuation
of the other.

`auditStorage.maximumFileBytes` is a per-segment rotation threshold, not a
total ceiling on the chain. When an append would push the active segment past
it, the runtime seals the active segment and opens a new one at the configured
path, online, with no stop and no operator action. A deployment that reaches
the threshold keeps serving: the next append rotates and continues. Total disk
consumption is therefore unbounded, and retention, meaning how much sealed
history stays on disk and for how long, is entirely the operator's
responsibility; nothing in the runtime deletes or compacts a segment. The one
exception is a single record larger than `maximumFileBytes` on its own: that
record can never fit an empty segment, so it fails closed instead of rotating
forever looking for room it will never find.

Segments are named by where they sit in the chain, not by when they were made.
The active segment, the one still being appended to, is always at the
configured `<auditStorage.path>`. Each sealed segment is
`<auditStorage.path>.<sequence>`, where `<sequence>` is an ascending,
zero-padded, eight-digit number starting at 1, so `evidence.jsonl.00000001`
precedes `evidence.jsonl.00000002` in both chain order and lexical order.
`<auditStorage.path>.lock` is unchanged by any of this: it is the writer's
advisory lock file, never a segment, and carries no chain state.

The chain spans every seam between segments. The chain head lives in the
running process's memory and survives rotation, so the first record written
into a new active segment carries the previous segment's last record hash as
its `prev_hash`, exactly as if no rotation had happened. A sealed segment is
not an independently verifiable chain that starts at genesis; only the very
first segment a deployment ever writes does that. Verifying a sealed segment on
its own, without the head it continued from, cannot succeed and is not a
supported operation.

This makes the old stop-and-rename rotation procedure actively dangerous, and
it must not be used. Renaming the active file to an arbitrary name such as
`evidence-<utc-timestamp>.jsonl` moves it outside the
`<auditStorage.path>.<sequence>` namespace the runtime recognizes, so the
runtime never sees it as a segment of this chain. On restart, startup recovers
the head from the newest segment still named `<auditStorage.path>.<sequence>`,
which is now the segment before the one that got renamed away, and begins a new
active segment continuing from that older head. The renamed-away file and the
new active segment then both contain a record claiming the same predecessor: a
silent fork, not a rotation, and the two branches are never reconciled.

To archive sealed history, copy or hard-link sealed segments out to cold
storage, oldest sequence first, and never touch the active segment this way. A
sealed segment can be copied or hard-linked safely while the service keeps
running: the runtime opens the newest sealed segment exactly once, at startup,
to recover the chain head, and never reopens an older sealed segment
afterward. Do not rename a copy back into the `<auditStorage.path>.<sequence>`
namespace at a sequence that still has a segment on disk; that would collide
with, and could overwrite, real chain history. If a sealed segment is removed
from the audit directory once it has been archived elsewhere, record which
sequence was removed, its byte length, and its final record hash in the
operator change record. A removed segment leaves a gap in the sealed sequence,
and the offline verifier reports that gap explicitly rather than treating it as
silent history loss, but only if there is a record of what should be there to
compare against.

Prefer archiving older sealed segments and leaving the newest one in place. The
newest sealed segment is what a restart reads to recover the chain head, so
removing it changes what the next start believes the chain continued from. In
the ordinary case that is caught: the active segment's first record names a
predecessor the remaining sealed tail does not match, and startup refuses to
begin on a fork. In the one case where it is not caught, the newest sealed
segment and the active segment are both gone, startup recovers from an older
sealed tail and allocates the next sequence from what is still on disk, so a
future rotation can seal a different segment under a sequence number the
archived one already used. Restoring that archive afterward collides with live
history. If the newest sealed segment must be archived and removed, treat
restoring it as part of the same procedure rather than optional cleanup.

Out-of-band verification replays every segment across every seam. It is
`evidence verify-audit`, and it reads both the audit storage path and the hash
secret from the same runtime document and file secret provider the serving
process uses. The command takes no path and no secret flags of its own, only
the global `--runtime` (equivalently `REGISTRY_EVIDENCE_RUNTIME`), so it can
never be pointed at an audit chain the deployment does not own and never takes
a secret on a command line:

```
evidence --runtime /etc/registry-evidence/runtime.yaml verify-audit
```

A pass exits zero and prints `segments`, `records`, `sealed-sequence`, `head`,
and `active-segment`; `sealed-sequence` is the inclusive range of sealed
segment numbers, or `none` before the first rotation. The counts and the head
hash carry no request content, so the report is safe to capture into an
incident record. Any failure exits non-zero.

Run against a running service, the command verifies sealed history only and
says so in `active-segment`, because reading the active segment while a writer
may be mid-append would race the write and risk reporting a partially written
final record as corruption; that is expected and is not itself a finding. To
prove the active segment too, stop the service first, as under Rollback.
A gap in the sealed sequence, for example sequence 3 archived and removed while
1, 2, and 4 remain, is reported as a distinct missing-segment result naming the
absent sequence and stating that it is not corruption, so an operator can tell
deliberate archival apart from tampering. A genuine hash break, in the head
continuity between two adjacent sealed segments or within one segment's
records, is reported as chain verification failure and means exactly what it
always has. The same check is available to governed tooling built on the
runtime as the library call `verify_audit_chain`, which reports the equivalent
`first_sequence`, `last_sequence`, and `active_verified` fields directly.

Rollback divides into restoring sealed history and restoring the active
segment, and only the second needs the service stopped. If a sealed segment was
archived and removed and needs to come back, copy or hard-link it back to its
original `<auditStorage.path>.<sequence>` name, unmodified; this is safe to do
live, for the same reason archiving is, since the runtime does not reopen old
sealed segments after startup. Restore from a copy whose byte length and final
record hash match what was recorded when it was archived, and re-run the
offline verifier afterward to confirm the gap has closed. Restoring or
replacing the active segment is different, because the running writer pins that
file by identity and inode: any replacement underneath a live process is
rejected by the sink's own pinned-identity check, and readiness and the next
append both fail closed rather than continuing on a file the process no longer
recognizes. To do it safely, stop the service first, with SIGTERM, which is
what a service manager and a container runtime both send, or with Ctrl-C for an
interactive process; the server stops accepting connections, finishes the
evaluations already admitted, completes their audit writes, and exits
successfully, and `listener.shutdownGraceMilliseconds` is the operational
target for that drain rather than a cancellation boundary. Confirm the process
has exited, which is also what releases the exclusive advisory lock on
`<auditStorage.path>.lock`; that lock is why only one Evidence process can ever
write this chain, still held for the writer's whole life, and it is the
structural reason a second writer is refused rather than merely discouraged.
With the service stopped, replace the file at `<auditStorage.path>` with the
restored content, preserving owner and mode `0600`, and start the service
again. Startup recovers the head from the newest sealed segment's tail as
always and verifies only the restored active segment against it, which proves
the restored file continues the chain correctly but proves nothing about sealed
history; run `evidence verify-audit` over the whole audit directory before
restoring traffic if the incident could plausibly have touched a sealed segment
too, while the service is still stopped so the active segment is proven as
well. Never restore an active segment that a later process has already
appended to: its first record's `prev_hash` would no longer match the sealed
tail, and the runtime refuses to start on the resulting fork rather than
silently accepting it.

## Listener placement

The Evidence API listener defaults to `networkExposure: private-address`,
which accepts only a numeric loopback, RFC 1918 private IPv4, or RFC 4193
unique-local IPv6 binding. A container deployment may explicitly declare
`networkExposure: container-private` and bind `0.0.0.0` or `::`. That mode is
an operator assertion about the container network and upstream TLS boundary;
it does not enable public serving. Concrete public addresses, hostnames, and
multicast addresses remain invalid. The optional metrics listener does not
inherit this exception and remains private-address-only.

## Metrics reference

This section describes what a configured `metricsListener` serves. It is
operator material: the public evidence contract and the generated OpenAPI
document do not describe it, and a deployment that leaves `metricsListener`
absent serves none of it.

```yaml
metricsListener:
  bindHost: 127.0.0.1
  port: 9090
```

`bindHost` accepts a numeric loopback, RFC 1918 private IPv4, or RFC 4193
unique-local IPv6 address. Hostnames and unspecified, multicast, and public
addresses are rejected at startup, as is a `bindHost` and `port` pair that
repeats the evidence listener binding. Both listeners bind before either
serves, so a rejected telemetry binding fails startup rather than leaving a
service that reports healthy while publishing nothing. The two share one
lifecycle: the telemetry listener cannot outlive a failed evidence listener.

The listener serves `GET /metrics` and answers every other path with `404`,
including the evidence routes. The exposition is Prometheus text format,
declared as `Content-Type: text/plain; version=0.0.4`. Two request-boundary
series are published:

| Series | Type | Meaning |
|---|---|---|
| `evidence_http_requests_total` | counter | Requests served at the evidence boundary |
| `evidence_http_request_duration_seconds` | histogram | Duration of those requests |

The histogram publishes `_bucket`, `_sum`, and `_count`. Its upper bounds in
seconds are `0.005`, `0.01`, `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1.0`,
`5.0`, and `+Inf`. They are fixed by the build and are not configurable.

Both series carry the same four labels, and each is drawn from a closed set
fixed by the deployed contract rather than by anything a caller sends:

| Label | Values |
|---|---|
| `route` | A registered route template, otherwise `unmatched` |
| `method` | `GET`, `POST`, `HEAD`, `OPTIONS`, otherwise `other` |
| `status` | `success`, `client_error`, `server_error` |
| `error` | A reviewed problem code, otherwise `none` |

The registered route templates are `/v1/evidence`, `/v1/evidence/batch`,
`/v1/evidence-definitions`, `/catalog.jsonld`, `/health`, `/ready`,
`/openapi.json`, `/.well-known/evidence/jwks.json`, and
`/.well-known/jwt-vc-issuer`. The
reviewed problem codes are the closed public set: `evidence.invalid_request`,
`request.selector_invalid`, `auth.invalid_credential`, `evidence.denied`,
`resource.not_found`, `format.unsupported`, `evidence.unavailable`,
`evidence.rate_limited`, `source.unavailable`, and `service.unavailable`.

`status` is the outcome class and never the exact status code, because the
exact status of a denial belongs to the closed public problem contract rather
than to operational telemetry. `error` carries the same reviewed problem code
the caller received, which makes a denial rate observable without making the
reason for any one request observable.

Because both label sets are closed, series cardinality is bounded by the route
table and the problem-code set regardless of traffic, and the registry needs no
eviction. A caller cannot create a series or write a label value: a path
matching no route is counted as `unmatched` and the requested path is never
recorded anywhere in the exposition.

An abbreviated exposition:

```text
# HELP evidence_http_requests_total Requests served by the Evidence boundary.
# TYPE evidence_http_requests_total counter
evidence_http_requests_total{route="/health",method="GET",status="success",error="none"} 2
evidence_http_requests_total{route="/v1/evidence-definitions",method="GET",status="client_error",error="auth.invalid_credential"} 1
# HELP evidence_http_request_duration_seconds Request duration at the Evidence boundary.
# TYPE evidence_http_request_duration_seconds histogram
evidence_http_request_duration_seconds_bucket{route="/health",method="GET",status="success",error="none",le="0.005"} 2
evidence_http_request_duration_seconds_sum{route="/health",method="GET",status="success",error="none"} 0.000241
evidence_http_request_duration_seconds_count{route="/health",method="GET",status="success",error="none"} 2
```

The registry lives in process memory. A restart resets both series to zero,
which a `rate` or `increase` query handles under the ordinary counter-reset
rule. Version 1 neither persists counters nor pushes them anywhere.

The telemetry listener performs no authentication of its own. The private
binding and the operator's own network are the only access controls, so the
operator must not route it through a public ingress or a shared scrape network.
Request rates per route and per problem code are operational information about
the registry even though no individual request is described.

The accepted address range is therefore a floor, not a boundary. Startup
rejects the mistake that actually exposes telemetry, a public or unspecified
`bindHost`, but an accepted RFC 1918 or unique-local address only means the
endpoint is unreachable from the public internet. On a flat pod network or a
shared VPC every workload already holds such an address, so binding one there
makes the endpoint scrapable by every neighbouring workload. `127.0.0.1` with
a same-pod or same-host collector is the shape that keeps the operator
boundary the operator intended; any wider binding must be closed by a network
policy, and the operator owns that control.
 `evidence_http_requests_total` and `evidence_http_request_duration_seconds`
describe the HTTP boundary only. Version 1 publishes no source-call, signing,
or credential-acquisition series. A slow or failing upstream source is visible
only as evidence-request duration and as the problem code the boundary
returned; signing, audit-chain, and
source-credential health are reported by `/ready` rather than by telemetry.

Three unlabeled gauges are published on the same listener. None carries any of
the four request-boundary labels, since each reports a process-wide or on-disk
fact rather than a per-request outcome, and each is resampled immediately
before every scrape:

| Series | Type | Meaning |
|---|---|---|
| `evidence_rate_limiter_tracked_keys` | gauge | Pseudonym keys currently tracked by the rate limiter |
| `evidence_audit_segments` | gauge | Audit chain segments on disk, sealed and active |
| `evidence_audit_bytes` | gauge | Bytes occupied by the audit chain across every segment |

Operators should alert on `evidence_rate_limiter_tracked_keys` approaching the
100,000-key ceiling described under
[requester authority and purpose](#requester-authority-and-purpose), since a
deployment at that ceiling refuses new principals with a capacity error rather
than degrading gracefully.

The two audit gauges are computed by walking the audit directory rather than by
counting appends, so they fall when an operator archives sealed segments and
rise again as the chain grows. Rotation never deletes a sealed segment, so
nothing in the runtime bounds that growth, and audit bytes that grow without
bound are the signal that whatever archives or ships them has stopped. Neither
gauge observes an external receiver: both report what is on local disk, never
what any off-host copy accepted.

## Startup and readiness

Before production exposure, the operator runs:

```sh
evidence check --require-runtime-dependencies
evidence evaluate --fixture "<path>"
```

`evaluate` also accepts `--explain`, which prints the stages each fixture case
reached beside the unchanged result. It is offline-only, reports member names,
counts, identifiers, and declared forms rather than any value, and alters no
outcome, exit code, or message. Adding `--explain-format json` renders the same
trace as one JSON document, which then is the whole of standard output: the
summary line's verdict and evaluated-case count move inside the document rather
than trailing it, and the exit code and the operator message on standard error
are unchanged. See the fixture reference for what it prints.

All commands accept `--runtime <absolute-path>`. The same path may be supplied
through `REGISTRY_EVIDENCE_RUNTIME`; the reference default is
`/etc/registry-evidence/runtime.yaml`. That file supplies the absolute
`bundleDirectory`. Command-line or environment values cannot override governed
bundle fields. The runtime file, bundle directory, and every captured artifact must
be non-writable to the service process. Evidence Version 1 supports Unix targets
only because its secret and audit invariants require owner, mode, no-follow,
link-count, and open-file identity checks. A read-only mount is preferred;
directories use no write bits and files use no write bits. Fixture
paths are normalized, bundle-relative `fixtures/*.yaml` paths referenced by
exactly one requirement. A fixture path may be absent only under the explicit
local assurance profile.

The reference file-secret provider reads only regular, non-symlink files below
the configured `secretProviders.file.root`. The secret root is operator-only and
each secret file must be owned by the service identity with exact mode `0400` or
`0600`. Read-only container secret mounts commonly present `0400`; `0600` remains
valid when the operator stages owner-writable material before the service starts.
Audit and subject-binding secret files contain independently generated raw key
bytes, must each be at least 32 bytes, must use distinct references, and must
resolve to distinct bytes. They are not decoded as base64 by the file provider.
Source credentials retain their provider-defined lexical form. Local signing
material is an ES256 P-256 private JWK whose public projection exactly matches
`signing.activePublicJwkFile`. Production and evidence-grade runtime
configuration instead names a Transit Unix socket, mount, key name, pinned
nonzero version, and bounded timeout. Transit metadata must report
`ecdsa-p256`, signing enabled, `derived=false`, `exportable=false`, and
`allow_plaintext_backup=false`, and its public key must exactly match the
governed active public JWK. Only active and published non-revoked public keys
appear at the JWKS endpoint. The audit JSONL path must be on storage whose
append durability, permissions, capacity, backup, restore, retention, and keyed
chain verification the operator owns.

`evidence check` validates and compiles the complete bundle, and resolves and
validates the mounted audit, subject-binding, and signer exactly as startup
does, including the asynchronous provider sign-and-verify test, without
opening the audit chain. A deployment whose secret or provider material
startup would refuse, including a signer whose public key differs from
`signing.activePublicJwkFile`, fails check. Source credentials are not
resolved by check; readiness owns them. Fixture evaluation
covers positive, negative, boundary, missing-data, source-failure,
existence-disclosure, and anti-reconstruction behavior without a running
source.
 `evidence check --require-runtime-dependencies` is the pre-routing container
form. In addition to what `evidence check` verifies, it opens and verifies the
audit writer, requires the signer self-test, resolves source credentials
without sending an evidence-data request, and requires the configured
access-token JWKS endpoint to provide a usable key set. This fail-closed
preflight does not change normal
serving readiness, which retains its bounded issuer-outage behavior.

For `assuranceProfile: local`, supervised Mint may use the exact canonical
issuer origin `http://127.0.0.1:<non-zero-port>` only when `jwksUri` is the
same origin plus `/.well-known/jwks.json`. Production and evidence-grade, and
every other authentication location, remain HTTPS-only.

`disclosureGuard.families` is a trusted bundle-review attestation, not a
domain-semantic classifier. The runtime rejects two simultaneously enabled
requirements with the same declared family. It cannot infer that differently
labelled families are semantically equivalent without adding forbidden domain
policy to the generic core. Operators must therefore review the complete
bundle for threshold ladders, overlapping partitions, relationship graphs, and
equivalent definitions before assigning distinct family identifiers. The
anti-reconstruction fixtures record that reviewed decision.

`observed_at` is supplied by the runtime and normalized to UTC. Rust derives
`legal_local_date` and `legal_local_time` from the requirement's optional IANA
`observationTimezone`; omission uses UTC. Requirements whose result depends on
local legal time should declare the timezone explicitly and include fixtures
on both sides of relevant date, time, daylight-saving, and offset boundaries.

The operator starts the reviewed revision with:

```sh
evidence serve
```

Startup confirms that the immutable bundle compiled, runtime ownership and
every local path/trust binding validated, mounted secret files and signer
metadata parsed, the active public key matched, the signer completed its
sign-and-verify test, and the audit chain opened and verified. Readiness
rechecks the subject-binding key, signing provider, pinned audit sink, and every source
credential. Basic, static Authorization header, and static API-key credentials
are checked locally. OAuth client-credentials readiness performs its bounded token
bootstrap against the configured token endpoint.
An explicit local source with `authentication.kind: none` has no credential
check or bootstrap and sends no authentication header. Production and
evidence-grade bundles reject that source kind at startup.
Neither startup nor readiness sends an evidence-data request or probes a source
data endpoint. Readiness
fails when a required local runtime or bundle input, selector binding,
credential, CA binding, audit dependency, or signing dependency is absent,
mutable, or invalid.

A statement source holds no credential, so readiness has nothing to bootstrap
for one. How old its mounted extract is still does not decide readiness. An
extract past its source's `maximumExtractAgeSeconds` refuses every evaluation
that reads it, with `source.unavailable` at the boundary and the
`source-extract-stale` audit category, while `/ready` stays `200` and the
requirements on other sources keep being served. Every replica may mount the
same file, so removing all of them from rotation would turn one stale source
into a full service outage. The deployment preflight is
`evidence check --require-runtime-dependencies`: it refuses an extract that is
already stale before traffic is routed. A later
transition to stale remains visible through the safe startup diagnostic and
audit category. Version 1 operator conformance additionally requires every
stale-extract fault to identify only the governed source or extract profile,
never the publisher's `extractId`, filesystem path, or another metadata value.
Alert on that safe diagnostic and audit category, not on readiness. The cure is
to publish a fresh extract and restart. Startup itself does not refuse an
already-stale extract because a restart racing a republish would otherwise
crashloop.

The access-token issuer's `jwksUri` is retrieved once at startup and again on
each readiness check, subject to the verifier cache lifecycle and a short
suppression interval after a failure. Both report and neither refuses: a
`jwksUri` that cannot be used is named in the log at startup rather than
discovered one rejected request at a time, but the issuer is a shared
dependency this deployment does not own, so an issuer outage does not withhold
its readiness or prevent it from starting. A key set already retrieved keeps
being accepted for a bounded allowance past its cache lifetime while the issuer
is unreachable, so a brief issuer outage does not turn into total rejection
here; once that allowance runs out, every request is rejected with the same
closed `401` a bad token receives, and the reason appears only in this
deployment's log.

The native operations are:

```text
GET /v1/evidence-definitions
POST /v1/evidence
POST /v1/evidence/batch
GET /.well-known/oauth-protected-resource
GET /health
GET /openapi.json
GET /ready
GET /.well-known/evidence/jwks.json
GET /.well-known/jwt-vc-issuer
```

`GET /openapi.json` publishes the generated public contract as
`application/json`. It carries no credential requirement because the
served bytes are the released generated artifact: the same document shipped in
`products/evidence/generated/`, independent of the deployed bundle.

`GET /.well-known/oauth-protected-resource` publishes the closed RFC 9728
resource document for `service.publicOrigin`. It names that exact origin, one
authorization-server issuer, the Evidence JWKS URI, and header-only Bearer
transport. It is cacheable for at most ten minutes with a strong ETag and
supports exact `If-None-Match` revalidation. Protected-route `401` responses
link it through `WWW-Authenticate`. The document is public routing metadata,
not an entitlement catalog or a trust decision by itself.

A successful `GET /v1/evidence-definitions` response uses `application/json`
and the closed requester-scoped definition schema. It requires the same strict
Bearer authentication profile and per-principal request budget as evidence
creation.

A successful `POST /v1/evidence` response uses `application/jose+json` and the
flattened JWS JSON Serialization unless the requester selected another enabled
format under [response formats](#response-formats). No public or
cross-requester catalog is supported.

A successful `POST /v1/evidence/batch` response uses only
`application/vnd.registrystack.evidence.request-batch+json`. The closed
`registry.evidence-request-batch/v1` envelope preserves request order and has
one `evidence` or `evidence_not_available` result per item. A request must send
that exact `Accept`; missing, wildcard, singular, parameterized, combined, or
weighted values return the existing `format.unsupported` problem
before source access.

`GET /.well-known/jwt-vc-issuer` is unauthenticated discovery for the SD-JWT VC
format. It publishes the exact configured provider identity as `issuer` and
that origin plus `/.well-known/evidence/jwks.json` as `jwks_uri`, and nothing
else. It does not inline the key set. Outside local assurance, enabling the
format requires `service.providerId` to be a stable HTTPS origin. Metadata is served
whether or not any grant enables the credential format, it never reveals which
requesters or requirements do, and it is discovery rather than a trust anchor
on exactly the terms in [secrets and keys](#secrets-and-keys).
No-match and ambiguous outcomes are publicly indistinguishable by default.
An HTTP source may additionally declare one exact unresolved Problem Details
tuple. Only the closed exact response becomes public evidence unavailable at a
singular or search stage; its neutral audit decision is `unresolved`, not
`no-match`, because the upstream result may be hidden or ambiguous. The problem
body, type, code, detail, and trace are never recorded. A mismatch and an
unresolved fetch after unique search are dependency failures.
Source, signing, and dependency failures use stable safe problem codes and do
not reflect protected inputs. Signing failure returns a safe transient failure.

Every authorization refusal after successful authentication collapses to one
generic problem with code `evidence.denied` and HTTP 403 and reveals no layer
detail: a principal outside the bundle audience, a requirement no matched grant
permits, an authority the grant does not carry, and an unsigned-envelope request
the bundle or grant does not allow all return the same body. This is deliberate;
the response is not an oracle for which check failed. Because the wire response
is intentionally uninformative, operators debug a 403 from trusted local state,
not from the response. Confirm, in order: the Bearer principal is in the
deployed bundle's audience; a grant matches the requested requirement, purpose,
and subject roles; the grant carries the claimed authority; and, only for an
unsigned request, both the bundle and that grant permit
`application/vnd.registrystack.evidence-unsigned+json`. Before returning that
problem, the keyed audit chain durably records the minimal refusal event under
its server-minted operation identifier. It proves that the authenticated requester
was refused without recording which request field or authority check failed.
The caller never sees the event. If the audit append fails, Evidence returns
the generic `service.unavailable` problem with HTTP 503 instead. Authentication,
malformed-request, and invalid-selector failures are operational-only and do not
create this event.

## Measured throughput

One end-to-end measurement is kept in the repository so capacity planning
starts from a number rather than an estimate. It drives the real router over
real sockets, and every request in it runs token verification, rate limiting,
Rhai request preparation, one outbound source call, Rhai extraction, evidence
construction, in-process ES256 signing, and both durable audit appends for each
successful request. It does not model the latency or availability of an
external Transit deployment.

| Measurement | Value |
|---|---|
| Sustained rate | 7057 requests/second |
| Audit appends | 14 115 appends/second (two per request) |
| Latency p50 / p95 / p99 | 17.89 / 21.37 / 23.03 ms |
| Non-2xx responses | 0 |
| Offered concurrency | 128 requests in flight, 128 principals |
| Window | 10 s measured, after a 3 s unmeasured warm-up |
| Host | Apple M5 Max, 18 logical cores, macOS 26.4.1, optimized build |
| Date | 2026-08-03 |

Reproduce with:

```bash
cargo test --release -p registry-evidence --lib -- \
  --ignored --nocapture sustained_load_holds_one_thousand_requests_per_second
```

The row records one run. An independent repeat of it on the same host measured
6976 requests/second at a p50 of 17.75 ms, so treat the rate as carrying about
a percent of run-to-run variation rather than as an exact figure. The same
check passes on an unoptimized build at 3183 requests/second with a p50 of
40.11 ms.

The measurement is only meaningful if the upstream source is not the thing
being measured, so the harness serves it from a minimal in-process handler
returning one constant JSON body and measures that handler's own standalone
ceiling in the same run, under the same client, worker count, header set, and
window. That ceiling was 145 273 requests/second, 20.6 times the Evidence
rate. The check refuses to report a pass or a failure below 5 times, and
reports the run as inconclusive instead.

Latency here is a closed-loop consequence of the offered concurrency: 128
requests in flight at 7057 requests/second is about 18 ms each. A deployment
offering less concurrency sees lower latency and a lower rate. The audit sink
commits in groups, so its rate rises with the number of appends in flight and
falls sharply when few are; a deployment that expects high throughput must let
requests overlap.

The harness lifts four production-meaningful defaults that would otherwise
become the thing measured, and lifts them only in its own temporary copy of
the fixture bundle: the per-principal rate limits, `maximumConcurrentRequests`,
each source's outbound `concurrencyLimit`, and the audit segment's
`maximumFileBytes`. Those raised values are measurement scaffolding, not a
recommended deployment posture. Keep the shipped defaults and tune from
observed traffic.

## Capacity planning
 The rate in the Measured throughput section is one host with one constant
source. Sizing a real deployment is a matter of finding which ceiling binds
first, and for most
deployments it is not Evidence.

Outbound source concurrency binds first whenever the provider is slower than
the in-process handler used for measurement. Each source's `concurrencyLimit`
is the number of requests Evidence will have outstanding to that source at
once, so sustained throughput through it is about `concurrencyLimit` divided by
the source's round-trip latency. A `concurrencyLimit` of 8 against a provider
answering in 20 ms sustains roughly 400 requests/second, and Evidence being
capable of thousands changes nothing about that. The field accepts 1 to 256 and
has no default: every bundle states it explicitly, because the right value is a
claim about what the provider tolerates rather than a number Evidence can pick.
Raising it moves load onto the provider, so raise it against the provider's own
documented or agreed limit, not against Evidence's spare capacity.

`listener.maximumConcurrentRequests` is the admission ceiling, from 1 to 4096.
It is a semaphore over evaluations already accepted, not a connection limit and
not an instant refusal: a request arriving with every slot taken waits for one
within whatever remains of `listener.requestTimeoutMilliseconds`, and receives
a `503` problem response only if the budget runs out first. Two sizing errors
follow from that. Set well below the source concurrency, it leaves provider
capacity unused, since Evidence will not have enough evaluations in flight to
keep the source busy. Set far above what the sources can absorb, it does not
add throughput; it converts overload into queueing, which the caller sees as
rising latency and then as timeouts. Size it near the total concurrency the
configured sources can actually sustain, and treat `requestTimeoutMilliseconds`
as the decision about how long a caller should wait before being turned away.

Two ceilings are not configured fields. Worker threads follow the host's
available parallelism, so vertical scaling changes the ceiling that CPU-bound
work, signing and Rhai evaluation, imposes; the runtime document does not carry
a thread count. Offered concurrency is not yours at all: it is what callers
send. The levers here bound what is admitted and what is dispatched onward,
never how much arrives.

Throughput below expectations is therefore diagnosed by finding the binding
ceiling before changing anything, and the `error` label on
`evidence_http_requests_total` separates the three rejections: `evidence.rate_limited`
is the per-principal limiter, `service.unavailable` is the request timeout
budget running out, which under load is normally a request that never got an
admission slot, and `source.unavailable` is the source failing rather than
merely being slow. A saturated but healthy source produces
none of those. It appears only as `evidence_http_request_duration_seconds`
rising while the request count stays flat, because Evidence is waiting on the
provider and reporting success when the answer arrives; confirming that
diagnosis needs source latency observed at the provider, which is why the
`concurrencyLimit` arithmetic is worth doing before traffic rather than
after. Because the audit sink commits in groups, a deployment held to few
requests in flight also pays a higher per-record audit cost than the table in
the Measured throughput section, which is a consequence of the low concurrency
rather than a separate problem to tune.

## Verification and release limit

A relying party or operator re-verifies a stored signed response offline with
`evidence verify --jws <file> --jwks <file> --policy <file> [--at <rfc3339-utc>]`.
The pinned JWKS file is the complete trust set and the policy document carries
every expectation from independent trusted state: the retained request nonce,
the expected assurance profile, role-bound subject bindings, output contract,
and explicit `revokedKeyIds` denylist under
[`contracts/verification-policy.schema.yaml`](contracts/verification-policy.schema.yaml).
A denied identifier fails before a key is selected even if the pinned file
still contains it.
The command performs no network access, reports cryptographic authenticity
separately from current validity, and exits 0 only when both hold; an
authentic but expired response exits 3. Every failed policy comparison reports
one generic class so verification is not an oracle.

Operators must verify a candidate revision with the applicable phase and final
commands in [AGENTS.md](AGENTS.md). Public-demo source tests are optional,
ignored, read-only, local, and non-gating. They may run only after deterministic
mocks pass and only with approved synthetic selectors and securely stored
credentials under [the source-testing contract](SOURCE-TESTING.md).

Evidence Version 1 is releasable only when all four coequal acceptance
definitions pass the complete offline and HTTP path, all Definition of Done
rows are green on one revision, generated contracts reproduce exactly, and the
security acceptance matrix is reviewed. Implementation stops at that boundary.
Future profiles require a separately approved concept and plan.
