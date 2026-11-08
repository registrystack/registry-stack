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
operators trust each other. Evidence Version 1 has no application database, unless
status is enabled (`CONCEPT.md` section 15.9), and persists no selector, source,
evidence, or response data; the status ledger holds keyed pseudonyms and
digests, never raw values. No runtime can enable status yet. An external durable
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
authentication, sources, request policy, scripts, disclosure, rate
limits, signing policy, or audit fail-closed behavior. The two content hashes
identify the exact loaded inputs but are not trust decisions. Complete grants are compiled
separately, activated into the runtime's authority store and captured at startup; they may only
narrow the installed package ceilings. The operator
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

`evidencectl package` compiles an editable project and one explicit production
target into a new candidate directory. It is a create-only authoring command,
not an approval, promotion, deployment, key-generation, caller-registration,
or service-start command. It runs the real `evidence` binary through its
offline bundle-and-runtime validation entry point, including exact extract,
signer-assurance, listener, secret-provider, TLS, and acquisition bindings,
and evaluates every referenced fixture
without generating a temporary signing key or other validation secret. It then
atomically publishes a candidate containing immutable `bundle/` with `SHA256SUMS`
and an optional `REVISION`, plus separate `runtime.yaml` and
`compiled-authority.yaml` handoff documents. The package contains no production private key, credential, token,
local request, audit entry, or source response.

The operator reviews and transfers the exact package, records its package
digest, and independently provisions every logical file-secret reference the
package report lists. The list is the deduplicated union of governed bundle
references and generated runtime references, including a local signer's
private-key reference; it never resolves or reports a value. Secret ownership
and mode requirements remain unchanged: each referenced
secret is a regular owner-only file accepted by the eventual service identity.
The package and runtime must be non-writable to that identity. The
runtime is target-specific and remains outside the immutable `bundle/`. Signed assertions continue to carry only a configuration
revision as `configurationRevision`. That value is scoped to the one requirement
the assertion answers, not to the whole package digest. The public signing keys and
`signing.revokedKeyIds` are outside it: publishing, activating, retiring, or
revoking a key changes the package digest and the JWKS but no
`configurationRevision`. So is `authentication.revokedKeyIds`: revoking an
identity-provider key changes which caller tokens are accepted and the package
digest, but no `configurationRevision`.

Run the following grouped handoff after provisioning and whenever candidate
bytes, runtime bindings, trust files, or secrets change:

```sh
evidence authority activate --runtime-config '<candidate>/runtime.yaml' \
  --document '<candidate>/compiled-authority.yaml' --operator-reference '<change-reference>'
evidencectl doctor --runtime-config '<candidate>/runtime.yaml'
evidencectl test '<editable-project>' --target '<deployment-target>'
evidence serve --runtime-config '<candidate>/runtime.yaml'
```

Activation writes `evidence-activation-audit/v1` entries to the `activation`
companion of the runtime's configured audit destination: beside a file
destination `audit.jsonl` it writes `audit.activation.jsonl` under its own
single-writer lock, so it runs while `evidence serve` holds the service file, and a
`stdout` destination becomes stderr. Ship the companion file with the service
audit. It resolves only the audit key and sink, without initializing sources or
the signer.

Each activation writes a `request` entry before it takes the authority lock,
then a `response` entry under the same correlation. The request carries an
activation ID, the package digest, the authority revision and digest, and the
optional operator reference as a keyed hash scoped to that activation. The
reference must be 1 through 256 bytes without control characters; use a
non-secret change reference. An invalid reference produces a correlated request
and `refused` response with no reference hash, without changing authority state.
The response carries the outcome: `applied` with the
history sequence, `refused` for a validation refusal, `failed` for a commit
failure before state replacement, or `unfinished` when commit durability cannot
be established. An `unfinished` response carries no sequence: the active revision
may have changed. Inspect authority history and retry the same document to complete
the durability check before continuing the handoff. If the destination refuses
the request entry, activation fails and changes nothing. Ceiling, target, and binding refusals never touch the authority
store, so they cannot consume the history bound. A package and authority revision
that are already active are refused as already active. This repeat guidance
requires unchanged `authority.root`, `authority.target`, package digest, and
authority revision, even when secrets or other runtime settings change. When
activation reaches this refusal, it exits with failure, prints `target authority
revision <revision> is already active for this package as sequence <sequence>;
nothing needs activating` on stderr, and records a `refused` response. Nothing
needs activating, so continue with the remaining steps of the handoff.

If the destination refuses the response entry after the commit, activation exits
with failure and names the active revision, digest, and sequence. The activation
took effect; restore the audit destination and confirm it with
`evidence authority history --runtime-config '<candidate>/runtime.yaml'`. A crash
between the commit and the response leaves a request with no response; inspect
authority history before proceeding. Failed state durability barriers never
acknowledge success. The audit trail lives only in the audit destination; the
authority store holds the history alone.

`doctor` delegates the runtime-owned startup dependency preflight without
opening the public listener, sending an Evidence request, or appending an
application audit event. Audit initialization may briefly hold its operational
lock. The runtime remains the authority for startup. Route traffic only after
`/ready`. For one approved
synthetic deployment subject, retain the signed response, verify it against an
independently prepared `production` policy and trusted keys, and confirm that
its access and disclosure audit entries reached the audit destination.

Configure an HTTPS OIDC issuer independently of Evidence. Its client registration
must bind the approved resource and scopes; the governed bundle pins issuer,
JWKS URI, audience, allowed algorithms, token types, and claim mappings.
Inspect the installed package and target with `evidencectl artifact inspect <candidate>` and verify
an actual issuer-to-resource request at handoff. Inspection does not register a
client, decide authority, or issue a token. Maintained local tooling uses pinned
stock ThunderID.

Docker Compose remains a documented deployment adapter, never build output.
It mounts the approved package unchanged and read-only, supplies a
separate container runtime file and owner-readable secret mounts, gives only
the audit path persistent writable storage while serving, activates target
authority explicitly through a one-shot service, mounts that activated state
read-only into the serving process, binds Evidence privately, and
keeps public TLS and routing operator-controlled. A deployment that enables the
status module of `CONCEPT.md` section 15.9 adds a PostgreSQL service, and
exposes the public status list route only through a path-restricted proxy that
forwards `GET` on the list path and nothing else. The OIDC issuer retains its
public HTTPS issuer identity and JWKS URI: internal plain-HTTP service
names do not replace either value. Container images and their provenance are
operator responsibilities; Version 1 proves this journey with released bare
binaries, not generated containers or orchestrator manifests.

### Public certificate check

The public certificate check (`CONCEPT.md` section 15.11) is an unauthenticated
Evidence route that reads registry data. It exists only when the
package declares `publicCheck` and the target authority activates
`publicCheck.definition`; otherwise `POST /v1/public-check` answers as an
unknown route. Evidence has no rate limiter on it and never reads a client
address, so the operator's proxy carries these duties:

1. Forward exactly `POST` and `OPTIONS` on `/v1/public-check`. Refuse every
   other method on that path, and answer 404 on every other path, so no
   relying-service route is reachable.
2. Apply a per-client request limit and a cap on the whole path, and refuse
   with `429` so a checker can tell the limit from an Evidence outage. The
   admission limit `maximumConcurrentRequests` still bounds concurrent source
   reads, but a flood that passes the proxy can occupy those slots.
3. Keep no log with client addresses or request headers for that location,
   neither the access log nor the error log (nginx writes the client address in
   error-log lines too, including rate-limit refusals and upstream errors). The
   check code is in the request body, never in a path or query, so a log of the
   path holds no code; a log of addresses would let the operator correlate
   checkers with certificates.
4. Terminate TLS on the check origin printed on the certificate.

Run the check on its own Evidence instance, with only the check requirement and
its own signing, audit and subject-binding keys, so a flood or a compromise on
the public path reaches no institutional signing key and does not starve
relying services. This is recommended, not enforced. The cost is a second
process with its own package, runtime file, keys and audit destination.

A check-only instance still needs a minimal `authentication` block in its
target, because the target schema requires one and startup proves that the
issuer's key source answers. The example target
(`examples/public-check/public-check-target.yaml`) shows the smallest working
block. The cost is an OIDC issuer that the instance never uses for the check
but whose key source must be reachable at startup. The target authority may
carry `accessProfiles: {}` with `publicCheck` as its only grant.

### Git-managed environments

Use one protected branch and complete named environment targets. The maintained
reference layout is under
[`reference/deployment-targets/`](reference/deployment-targets/):

```text
shared/
  evidence-project/
environments/
  local/
    evidence/{target.yaml,authority.yaml,public-keys/}
  staging/
    evidence/{target.yaml,authority.yaml,public-keys/}
    transit/{proxy-configs/,policies/}
  production/
    evidence/{target.yaml,authority.yaml,public-keys/}
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
| Authenticated definition response | Lists the exact complete request shapes available to this verified token from the loaded package, each with the configuration revision an assertion for that one requirement carries. | It performs no provider access, does not grant authority, and is not a global catalog. |
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
   governed package digest.
3. Run the production `evidencectl package` flow, which generates and seals
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
reserved or the whole request returns `evidence.rate-limited` and charges nothing.
A bucket never holds more than `burstPerPrincipal` tokens, so a batch with more
items than the burst, or a holder-bound release presenting more holder keys
than the burst, can never be admitted however long the caller waits. Evidence
refuses it as `evidence.invalid-request`, with no `Retry-After`, and charges
nothing, rather than returning a rate limit that invites a retry which cannot
succeed. The caller receives the registered invalid-request body unchanged:
the frozen problem contract selects its detail by code alone, so the refusal
names neither the burst nor the batch size.

The largest cost a bundle admits is the larger of two numbers. A request batch
may carry up to sixteen items for any audience-scoped requirement, whatever a
source's own `batch.maximumItems` says, because items above that ceiling run
sequentially rather than being refused. A holder-bound release may carry up to
`maximumHolderBoundBatchSize` holder keys when the bundle serves a holder-bound
requirement and enables `sd-jwt-vc-batch`. `evidence check` and `evidencectl
doctor` warn when `burstPerPrincipal` is below that cost, naming the ceiling
and the key but never the configured value. It is a warning rather than a refusal: a burst below the batch
size is a deliberate way to cap how much one principal may ask for at once,
at the price of refusing every larger batch. The shipped reference and starter
configurations set `burstPerPrincipal: 16`; raise it at least that far unless
the cap is intended.
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
starts, the captured `sourceAcquisition.acquisitionDeadlineMilliseconds` is the
absolute deadline for its pack acquisition and for admission to its terminal
release append. Admission to that append is the disclosure-begin boundary.
Evidence starts no new credential, source, or release-append
operation after that deadline. A terminal release append admitted before the
deadline completes without cancellation, and the exact audited response bytes
may return after the deadline expires. The deadline is therefore not a hard
wall-clock response cutoff. A signed source's verified `validUntil` remains an
independent data-validity bound.

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
no issuance session, holder binding ceremony, or presentation verification. A
status list and revocation exist only for a requirement that declares credential
status under the version 2 profiles of `CONCEPT.md` section 15.9.
`/.well-known/jwt-vc-issuer` publishes no
per-requester or per-requirement information. The `vct` claim is the
requirement's declared `isConformantTo` identifier, so the credential type is a
governed bundle decision rather than a client choice. The subject identifier
stays the audience-scoped pseudonym, so the same person requested for a
different audience yields a different identifier and the credential is not a
general-purpose multi-verifier credential.

An audience-scoped single-credential request may carry an optional `holderKeys`
array containing one public EC P-256 JWK. That key is echoed into the `cnf`
claim and is meaningful only for the SD-JWT VC format. An unacceptable key is
rejected as a malformed request alongside the nonce check, before authentication,
credential acquisition, and
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
exposes as unavailable may appear as `evidence-not-available`; mixed and
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

Replacing a source credential file at the same secret reference does not
invalidate an unexpired OAuth token. Provision provider overlap, replace
owner-only files, drain and restart every affected Evidence process when
immediate cache replacement is needed, verify a real synthetic source request,
and retire the predecessor under the provider's token-validity policy. See
[Source credential rotation](reference/request-adapter/deployment-projects/SOURCE-CREDENTIAL-ROTATION.md)
for the supported sequence and the distinct emergency-revocation boundary.

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

The normalized target binds one service public key through `signer.publicJwkFile`
and its matching provider version through `signer.keyVersion`. It does not author
additional published service keys or a signing-key denylist.

For planned rotation, create a successor non-exportable Transit version and commit
its exact public JWK under a new thumbprint filename. Distribute that key to relying
parties before switching. Their approved trust set must retain the predecessor
through the assertion-validity-plus-clock-skew window. Consumers using only cached
service JWKS need a coordinated refresh or a cutover window.

Build and check a new candidate with the successor `signer.publicJwkFile` and
`signer.keyVersion`, install its bundle, activate its complete authority and restart
every replica. Keep both provider versions permitted during the rollout. After all
replicas use the successor and the validity window has elapsed, remove the old
version from the proxy policy and raise the provider's `min_encryption_version`.

Emergency rotation first disables provider signing for the compromised version.
Distribute its thumbprint to consumer denylists, then deploy a checked successor or
leave the service unavailable. Never mutate sealed bundle bytes to add an
unsupported authoring field. For a compromised caller-token issuer key, set
`authentication.oidc.revokedKeyIds` in the target and rebuild before restart.

## Source and selector controls

A governed `sourceConnections` map reviews the non-secret authority for every
named workload connection. Each entry contains an `endpoints` list. An endpoint
policy fixes the Adapter pack endpoint id, exact base URL, optional trust
profile, client-identity requirement, and authentication kind and authority.
Secret references, attempt limits, response limits, private-network allowances,
and trust-anchor files belong to the matching runtime binding instead.

Each source binds one digest-pinned Adapter pack and Evidence route to a named
connection. Its `inputs` map projects only authorized selector fields into
named route inputs; its posture and fact schema must equal the pinned route
contract. The pack owns request construction, extraction, response validation,
and destination endpoint selection. There is no inline source transport plan
and no runtime override of the reviewed pack, route, connection, selector map,
posture, or fact schema.

`runtime.yaml` binds the same connection name under `sourceConnections`, and
the value's `id` must equal the map key. Its endpoint ids, base URLs, trust
profiles, client identity, and credential kinds must match the governed policy.
One name in one Evidence process shares the endpoint transport resources,
admission permits, and OAuth cache across every program that reaches it.
Different names remain isolated even when their destinations or credential
bytes happen to match. Facts and authorization decisions always remain
request-local. Waiting is bounded, cancellation releases capacity, and separate
processes do not share a distributed concurrency budget.

`sourceAcquisition` supplies finite operational ceilings for one acquisition:
data operations, elapsed milliseconds, and aggregate response bytes. Omission
uses 5 operations, 30,000 milliseconds, and 1,048,576 bytes. These runtime
limits may constrain a reviewed pack further, but cannot add routes, endpoint
authority, requests, or response shapes.

The bundle-only check path has no runtime connection material and performs no
HTTP request. It validates the complete digest-pinned pack closure and governed
binding. `evidence check` additionally validates runtime endpoint, credential,
TLS, CA-bundle, and extract bindings without sending source data. Live
evaluation builds the shared resources and refuses a governed connection that
does not have an exact runtime binding.

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

A definition may name a second Source for holder-presented acquisition
(`acquisition.holderPresented`). The request's selector profile selects exactly
one channel, with no fallback, and the assertion's `channel` member records
which one produced it. The holder-presented Source must use the
`wallet-presentation-v1` host protocol, the definition answers as signed JWS
only, and a relying party must opt in to the `holder-presented` channel through
its channel policy. The authoring reference lists the startup refusals.

The wallet presentation service (`evidence-oid4vp`) releases a received
presentation or wallet error to Evidence once: the first successful read
consumes it, and a later read of the same reference is a 404 (a read is not
retried safely after delivery). Its `/ready` answers 503 once a client
identifier certificate is past its `notAfter`, because wallets refuse the
request objects. Its limiters for the wallet-facing request and response paths
use one key for all wallets and bound the service as a whole, so a deployment
must rate limit per source at its ingress in front of those two paths; without
that, one client can exhaust the budget for every wallet.

Every source declares its acquisition posture, exactly equal to the posture in
the digest-pinned Adapter route contract. Its requirement inherits that
posture:

| Posture | Operator claim |
|---|---|
| `source-derived` | Full acquisition and disclosure minimization |
| `field-projected` | Strong acquisition and disclosure minimization |
| `record-transformed` | Disclosure minimization only |

The operator must not describe a `record-transformed` integration as full
lifecycle minimization. The posture describes what crossed the provider
boundary before the Adapter route transforms and validates it. Route replay
must prove provider-specific field selection where claimed. A provider whose
wire response cannot be closed at that boundary must use `record-transformed`,
even when the final validated facts are narrow.

A statement returning one aggregate is `source-derived` on the same terms as an
API returning that aggregate, because the narrow fact is what crossed the source
boundary. A later derivation may map that fact to the asserted concept without
changing the acquisition posture.

Each requirement names exactly one source binding. The bound Adapter route is
the complete reviewed acquisition program, including every permitted provider
operation, retry, and validation step. Its closed input map is populated only
from the source binding's authorized selector projections. Caller values,
responses, and scripts cannot select another pack, route, connection, endpoint,
credential, or additional operation.

Request-batch evaluation preserves request order and runs the same source route
independently for each item. The retired source-specific `prepare_batch` and
`extract_batch` ABI is not part of the pack-source contract. Any optimization
inside an Adapter route remains bounded by that route's reviewed steps and the
shared acquisition operation, deadline, and response-byte budgets; it does not
create a second Evidence batching authority.

A governed endpoint policy may name a logical TLS trust profile, and inbound
authentication may name one for the access-token issuer's key set.
`runtime.yaml` binds each name to one bounded PEM CA file, trusted beside the
system roots for the connection or issuer that names it and no other. Hostname
and fixed-origin verification remain mandatory; there is no insecure or
trust-all mode. Version 1 ignores `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` and has no application-level proxy.

## Audit and operational data

After successful authentication, the configured audit sink must durably accept
a minimal authorization-refusal event before a generic `403` is returned. It
must durably accept one access-attempt event before each actual evidence-data
source read. That access event captures the effective immutable acquisition
limits in the closed `executionBounds` object before credential resolution or
source effects. The sink must also accept the disclosure-release event after
final serialization and any signing, and before response release. Any failure
blocks the applicable action and returns a generic `503` when an HTTP response
remains possible.

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
confuse them. The audit log is the accountability record: durable, complete,
and it has no severity levels and no way to turn records off; tamper evidence
comes from the append-only storage it is shipped to.
Every authorized evidence evaluation writes one access-attempt event durable
before each actual source read and the disclosure-release or terminal event
required by its outcome. Every authenticated authorization refusal writes one
minimal denial event before its response. Those gates are pinned by frozen
Version 1 security invariants and are not configurable. The `tracing` channel
is the operational and diagnostic record: it has levels, it is buffered and
lossy, and it is cheap. The rule for operators and integrators is:
accountability facts belong in the audit log and never only in tracing, and
operational noise belongs in tracing and never in the audit log. If an
adopter needs more detail than the frozen audit record carries, which some
regulators require, the correct shape is a separate operational log keyed by
the audit entry's `eventId`, not a verbosity setting on the audit log.

The refusal event is written under the distinct
`registry.evidence.audit.authorization-refusal/v2` entry schema, in the same
envelope and destination as current authorized-material entries. New singular
authorized-material entries use `registry.evidence.audit/v3`; retained
`registry.evidence.audit/v2` entries remain readable history. A semantic reader
selects the record shape by the envelope's `schema` member. Readers must accept
the new authorized `/v3` schema before operators route traffic to the changed
runtime. `evidencectl audit show` keeps its internal
`registry.evidence.local-audit-operation/v2` projection and reads retained
authorized `/v2` history alongside `/v3`; that projection is not an entry
schema.

Every singular and request-batch `/v3` access-attempt record requires exactly
one closed `executionBounds` object with three positive integers:
`maximumDataOperations`, `acquisitionDeadlineMilliseconds`, and `maximumResponseBytes`.
They are the effective `sourceAcquisition` values captured from the immutable
runtime configuration. When that block is omitted, the captured defaults are
`5`, `30000`, and `1048576`. The object carries no endpoint, credential, secret,
or source value. Terminal `/v3` records must omit it, and retained `/v2` records
must also omit it.

The request-batch route adds
`registry.evidence.audit.request-batch/v3` entries to that same destination. One access
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
three entry schemas before deploying the request-batch runtime.

The serving process writes those records as line-delimited JSON on standard
error, one per served request, and `EVIDENCE_LOG` selects verbosity with a
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
route template, request method, status category, and reviewed problem code, or
for the source series a governed source identifier from the bundle, so series
cardinality is bounded by the deployed contract and cannot grow with caller
input. A path that matches no route is counted as `unmatched` and a
method outside the served set as `other`, so a caller cannot write a label
value. Operators should still reach this listener only from their own network,
since request rates per route are operational information. The series and
labels it publishes are in [Metrics reference](#metrics-reference).

The operator owns audit shipping, retention beyond `audit.retentionDays`, backup,
restore, access control, and key rotation for the selected destination. A
deployment profile may require more reviewed metadata or retention, but it
cannot silently weaken the native privacy contract.

The audit master is expanded through HKDF into the key that computes
identifier pseudonyms. The subject-binding master is a separate secret
reference and must resolve to different bytes, so an audit pseudonym oracle
never becomes a subject-binding oracle, and the operator ceremony stays at two
independent masters.

Exactly one Evidence process may write a given audit file. The file
destination takes an exclusive OS advisory lock on `<audit.path>.lock` at
startup; a second process pointed at the same path fails at startup with a
sink-locked error rather than interleaving its writes with the first. Run more
than one replica by giving each its own `audit.path`, for example on a
per-replica volume, or by choosing `destination: stdout` and letting the
platform's log collector gather every replica's stream. Use a readiness probe
and restart-on-failure to recover from a crashed writer.

Appends and readiness probes check the pinned identity and modification
fingerprint of the active file and the lock file without rescanning the
growing file. Any external write, truncation, or replacement of either makes
readiness and every later append fail closed. A failed durable write stops the
writer for the life of the process: every later audited request is refused
with the generic `503` until the process restarts.

## Audit destinations, rotation, and retention

Every audit entry is one JSON line with exactly six members:

| Member | Meaning |
|---|---|
| `schema` | The current writer schema: `registry.evidence.audit/v3`, `registry.evidence.audit.request-batch/v3`, or `registry.evidence.audit.authorization-refusal/v2`. Retained authorized-material `/v2` entries remain readable history. |
| `eventId` | A random UUID the writer mints for this entry. |
| `time` | The writer's RFC 3339 UTC timestamp for the append. |
| `phase` | `request` for an access attempt, written before the source read it authorizes; `response` for every terminal record: a release, a denial, or a failure. |
| `correlation` | The server-minted operation identifier, equal to `record.operation`, shared by every entry of one operation. |
| `record` | The closed, minimized Evidence record described above. |

Entries are not chained. Each one stands alone, so a reader can validate any
line without the lines before it.

`audit.destination: file`, the default, appends to `audit.path` and returns
from an append only after the entry's bytes are synced to disk; appends that
arrive during one durable write share the next one. When an append would push
the active file past `audit.rotateBytes` (100 MiB by default), the writer
renames it to `<audit.path>.<sequence>`, where `<sequence>` is an ascending,
zero-padded, eight-digit number, and opens a fresh active file at
`audit.path`, online and with no operator action. When the writer opens and
each time it rotates, it deletes sealed files last modified more than
`audit.retentionDays` ago (90 by default); it never deletes the active file.
The next sequence is recorded in `<audit.path>.seq` at every start and before
every rotation, so numbering continues across restarts even after retention or
a shipper removed every sealed file. It restarts only when `<audit.path>.seq`
is lost with them, as in a fresh or restored directory, and two replicas'
streams use the same names, so archives must still not be keyed on the sealed
file name alone. An entry larger than 1 MiB is refused, and the request it
belongs to fails closed.

A crash, a kill, or a full disk can leave the active file ending in part of an
entry. At the next start the writer copies the bytes after the last complete
line to the owner-only (`0600`) side file `<audit.path>.torn`, syncs it,
truncates the active file to its last complete line, and logs the side file's
path and byte count, never the bytes, at error level. An entry is acknowledged
only after the write holding it is synced, so the torn bytes belong to no
acknowledged entry and no acknowledged entry is lost. Inspect the side file and
archive it with the sealed files, then remove it: a later torn line finds the
side file holding other bytes and is refused until it is moved, because the
writer never overwrites it. A configured `audit.path` whose file name ends in
`.lock`, `.seq`, `.seq.tmp`, `.torn`, or a sealed-segment `.<sequence>` is
refused, because a stream at the shorter name owns that file.

Never rename, edit, or truncate the active file while the service runs; the
writer treats that as tampering and stops. Copying a sealed file is safe at any
time, since the writer reads no sealed file after it is sealed.

`audit.destination: stdout` writes each entry as one line on standard output
and flushes it. The serving process writes its operational records to
standard error whatever the destination is, so the stream carries audit entries
alone, each with its `schema` member. Durability, rotation, and retention then belong to the collector, and
an entry is accepted once the line is written to the stream. `evidence check
--require-audit-under` refuses a `stdout` destination, because there is no
local file to contain, and `evidencectl audit show` has nothing local to read.

Stop the service with SIGTERM, which is what a service manager and a container
runtime both send, or with Ctrl-C for an interactive process. The server stops
accepting connections, finishes the evaluations already admitted, completes
their audit writes, and exits successfully; `listener.shutdownGraceMilliseconds`
is the operational target for that drain rather than a cancellation boundary.
Exiting is also what releases the lock on `<audit.path>.lock`.

### Ship audit to append-only storage

Tamper evidence belongs to where audit entries end up, not to the file the
service writes. Ship sealed files, or the `stdout` stream, to storage the
Evidence host cannot rewrite: object storage with an object lock, a
write-once archive, or a log pipeline whose retention the Evidence operator
account cannot change. Ship each sealed file before `audit.retentionDays` deletes
it, and confirm that the entries reached the store as part of backup, restore,
and incident procedures. Restore audit history into that store, never back
into the live audit directory.

### Audit key rotation

Every pseudonym carries the governed `audit.hashKeyVersion` in its
`hmac-sha256:v<version>:` prefix, so entries written under different key
material stay distinguishable in one log and rotation needs no fresh audit
path. The runtime cannot tell a replacement master from the one it replaces:
replacing the master bytes without incrementing `hashKeyVersion` silently
changes every pseudonym under an unchanged prefix. Rotate the audit master
only this way:

1. Generate a fresh independent audit master into a new secret file.
2. Build a governed bundle revision whose `audit.hashKeyRef` names it and
   whose `audit.hashKeyVersion` is one higher, and record the change, the
   bundle revision, and both versions in the change record.
3. Run `evidence check --require-runtime-dependencies` and the full handoff
   checks, restart the service, and route traffic only after readiness
   succeeds.
4. Keep the previous master under its governed secret controls for as long as
   pseudonyms from its epoch must be recomputable for an investigation.

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
  bind: 127.0.0.1:9090
```

`bind` is a `host:port` socket address whose host is a numeric loopback, RFC
1918 private IPv4, or RFC 4193 unique-local IPv6 address. Hostnames and
unspecified, multicast, and public addresses are rejected at startup, as are
port `0` and an address that repeats the evidence listener binding. Both listeners bind before either
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
| `status` | `success`, `client-error`, `server-error` |
| `error` | A reviewed problem code, otherwise `none` |

The registered route templates are `/v1/evidence`, `/v1/evidence/batch`,
`/v1/evidence-definitions`, `/catalog.jsonld`, `/health`, `/ready`,
`/openapi.json`, `/.well-known/evidence/jwks.json`, and
`/.well-known/jwt-vc-issuer`. The
reviewed problem codes are the closed public set: `evidence.invalid-request`,
`request.selector-invalid`, `auth.invalid-credential`, `evidence.denied`,
`resource.not-found`, `format.unsupported`, `evidence.unavailable`,
`evidence.rate-limited`, `source.unavailable`, and `service.unavailable`.

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
evidence_http_requests_total{route="/v1/evidence-definitions",method="GET",status="client-error",error="auth.invalid-credential"} 1
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
`bind` host, but an accepted RFC 1918 or unique-local address only means the
endpoint is unreachable from the public internet. On a flat pod network or a
shared VPC every workload already holds such an address, so binding one there
makes the endpoint scrapable by every neighbouring workload. `127.0.0.1` with
a same-pod or same-host collector is the shape that keeps the operator
boundary the operator intended; any wider binding must be closed by a network
policy, and the operator owns that control.
`evidence_http_requests_total` and `evidence_http_request_duration_seconds`
describe the HTTP boundary only. Fixed source execution and assertion signing
also publish bounded attempt counts and latency histograms:

| Series | Labels | Meaning |
|---|---|---|
| `evidence_source_requests_total` | `source`, `outcome` | Fixed HTTP or statement attempts, including failures and cancellations |
| `evidence_source_request_duration_seconds` | `source`, `outcome` | Attempt latency, with histogram bucket, sum and count series |
| `evidence_signer_requests_total` | `signer="active"`, `outcome` | JWS or SD-JWT issuance attempts, excluding readiness probes |
| `evidence_signer_request_duration_seconds` | `signer="active"`, `outcome` | Issuance latency, with histogram bucket, sum and count series |
| `evidence_build_info` | `version`, `bundle`, `authority` | Gauge fixed at 1 for the captured package and authority revision. `authority="package"` means no separate authority document is active, so the package's own ceilings govern. |

Source IDs come only from the governed bundle. Outcomes are closed categories:
`success`, `cancelled`, `credential`, `concurrency`, `timeout`, `transport`,
`unauthorized`, `forbidden`, `rate-limited`, `server-error`, `protocol`,
`verification`, `statement`, `signing`, and `serialization`. Only observed
categories emit series. No selector, subject, request ID, raw error, URL,
credential, or signing key becomes a label. Source observations cover transport,
projection, and response verification; assertion derivation remains visible at
the request boundary. Upstream reachability does not decide `/ready`.
A source-data outage returns `503 source.unavailable` without `Retry-After`
when no useful recovery interval is known; meaningful rate-limit hints remain.
The instance stays ready while its own required dependencies are healthy,
without probing source-data endpoints. See the shared
[HTTP recovery contract](../platform/HTTP-PROBLEMS.md).

One unlabeled gauge is published on the same listener. It carries none of the
four request-boundary labels, since it reports a process-wide fact rather than
a per-request outcome, and it is resampled immediately before every scrape:

| Series | Type | Meaning |
|---|---|---|
| `evidence_rate_limiter_tracked_keys` | gauge | Pseudonym keys currently tracked by the rate limiter |

Operators should alert on `evidence_rate_limiter_tracked_keys` approaching the
100,000-key ceiling described under
[requester authority and purpose](#requester-authority-and-purpose), since a
deployment at that ceiling refuses new principals with a capacity error rather
than degrading gracefully.

Evidence publishes no audit series. Audit writer health is reported by
`/ready`, and disk use in the audit directory is bounded by
`audit.rotateBytes` and `audit.retentionDays` and belongs to host monitoring.

One source counter is published, with one series per source the governed
bundle declares, each present from startup at `0`:

| Series | Type | Meaning |
|---|---|---|
| `evidence_source_shape_drift_total` | counter | HTTP source responses whose shape departed from the declared projection |

Its only label, `source`, is a source identifier from the governed bundle. The
set is fixed when the process starts, so neither traffic nor a source can add a
series. A response is counted once however many members drifted, and every
drifted response is counted, including those whose WARN record the interval
below suppressed. Alert on any increase: a source that renamed, dropped, or
retyped a member the projection selects fails or degrades every request that
reads it until the bundle is updated.

```text
# HELP evidence_source_shape_drift_total Source responses whose shape departed from the declared projection.
# TYPE evidence_source_shape_drift_total counter
evidence_source_shape_drift_total{source="civil-register"} 0
```

### Source diagnostics

A source failure reaches the caller as `source.unavailable` or
`evidence.unavailable`, which names no member and no cause, and the served
request's `category` field names only the failure class. Operational records
name the governed source and a closed pack-execution category. They never carry
raw response content, selector values, subjects, credentials, endpoint URLs,
schema values, or script messages. Provider 404 bodies and other error payloads
remain dependency data and are not reflected to the caller or operator log.

A schema or script refusal in the Adapter route remains a value-free protocol
failure. The operator uses the governed source id, route id, stable closed
category, Adapter pack revision, and provider-side telemetry to locate drift.
Evidence does not publish response pointers or member names learned from an
untrusted provider body.

The projection and 404 records are rate-limited: each is written at most once
per 60 seconds per source, and `suppressed` counts the events of the same kind
for that source that were not written since the previous record. A 404 that is
exactly the declared `unresolvedProblem` is an ordinary outcome and writes
nothing.

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

Every command that reads a deployment takes `--runtime-config <absolute-path>`
after the subcommand; the maintained container image passes
`/etc/registry-evidence/runtime.yaml`. That file supplies the absolute
`package.root`. The earlier `--runtime` flag and `REGISTRY_EVIDENCE_RUNTIME`
variable are refused with the replacement named, so a stale invocation fails
instead of silently reading another file. Command-line or environment values
cannot override governed bundle fields. The runtime file, bundle directory, and every captured artifact must
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
appear at the JWKS endpoint. A file audit destination must be on storage whose
append durability, permissions, capacity, backup, and restore the operator
owns, and the operator ships its sealed files to append-only storage.

`evidence check` is offline. It reads the runtime file, verifies the package
`package.root` names, validates and compiles the complete bundle, reads each
CA bundle a trust profile names, and checks every binding between the runtime
file and the bundle. It reads no secret material, opens no audit destination,
and contacts no provider, source, or issuer. It reports every problem it finds
as a positioned diagnostic with a three-segment code, and exits `0` when the
deployment passed, `1` when it was refused, `2` on a usage error, and `3` when
an input it depends on could not be read. Fixture evaluation
covers positive, negative, boundary, missing-data, source-failure,
existence-disclosure, and anti-reconstruction behavior without a running
source.
 `evidence check --require-runtime-dependencies` is the target-host and
pre-routing container form. In addition to what `evidence check` verifies, it
refuses a writable deployment input, refuses a stale extract, resolves and
validates the mounted audit, subject-binding, and signer secrets exactly as
startup does, opens and verifies the audit writer, requires the asynchronous
provider sign-and-verify self-test, resolves source credentials without
sending an evidence-data request, and requires the configured access-token
JWKS endpoint to provide a usable key set. A deployment whose secret or
provider material startup would refuse, including a signer whose public key
differs from `signing.activePublicJwkFile`, fails this form. A dependency the
host cannot provide exits `3`; an input the host holds wrongly exits `1`. This
fail-closed preflight does not change normal
serving readiness, which retains its bounded issuer-outage behavior.

Adding `--require-audit-under <absolute-directory>` proves one further
property: that the file destination `audit.path` resolves at or below a directory the
deployment declares persistent. Evidence canonicalizes the declared root and
the deepest existing ancestor of the configured destination before comparing,
so a destination outside the root, and a symlink inside the root that leads to
ephemeral storage, both fail closed. The option requires
`--require-runtime-dependencies` and relaxes nothing: the audit writer still
has to open and lock. A `stdout` destination fails the option, since it has no
local file to contain. Whether the declared root is durable storage is
the deployment's responsibility, not Evidence's; Evidence resolves its own
configured destination and never inspects mounts. Failures name which side
failed and no path.

Adding `--without-audit-lock` checks a candidate staged beside the running
instance it will replace, which shares its audit path and so holds the
single-writer lock by design. The option requires
`--require-runtime-dependencies`. The audit boundary is proved without taking
that lock: the audit destination settings and hash key, an owner-controlled
directory the service user can write, and an existing active file and lock
companion that are owner-only, singly linked, and writable, with an active file
whose final entry is complete or ends in a torn line `serve` would move to its
side file. Every other dependency is proved as without the
option, and no audit entry is appended. It does not detect a second writer, so
`serve` still refuses to start while another instance holds the lock; without
the option, a held lock refuses the check with `another process holds the
single-writer lock beside the audit file`.

For `assuranceProfile: local`, a supervised issuer may use the exact canonical
issuer origin `http://127.0.0.1:<non-zero-port>` only when `jwksSource.uri` is the
same origin plus `/.well-known/jwks.json` or `/oauth2/jwks`. Production and evidence-grade, and
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
sign-and-verify test, and the audit writer opened. Readiness
rechecks the subject-binding key, signing provider, pinned audit writer, and every source
credential. Basic, static Authorization header, and static API-key credentials
are checked locally. OAuth client-credentials readiness performs its bounded token
bootstrap against the configured token endpoint.
An explicit local source with `authentication.type: none` has no credential
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

Age is measured from the extract's `publishedAt` to the evaluation instant. An
extract whose `publishedAt` is in the future counts as fresh: its age is
negative, so it passes the check until that instant plus
`maximumExtractAgeSeconds`. Evidence does not allow for clock skew or refuse a
future date. The publisher's clock is therefore yours to run: keep it
synchronised (NTP), and treat a `publishedAt` ahead of the time you published
as a publishing fault. A wrong publisher clock can make an old extract look
fresh and Evidence will not notice.

The access-token issuer's `jwksSource.uri` is retrieved once at startup and again on
each readiness check, subject to the verifier cache lifecycle and a short
suppression interval after a failure. Both report and neither refuses: a
`jwksSource.uri` that cannot be used is named in the log at startup rather than
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

The response carries one entry per definition handle. A definition that
declares holder-presented acquisition states the `channel` (`source` or
`holder-presented`) of the entry's own `subjects`. When the caller is entitled
to both channels of one definition, the entry carries the source channel's shape
as its own and one item in `alternatives` for the holder-presented channel, with
that channel's `subjects` and `responseFormats`. A channel the caller is not
entitled to is never listed. The entry of a source-only definition has neither
member. Two entries that share a handle in any other way (two shapes on one
channel, or different purposes under one handle) refuse the complete document
with `service.unavailable`.

A successful `POST /v1/evidence` response uses `application/jose+json` and the
flattened JWS JSON Serialization unless the requester selected another enabled
format under [response formats](#response-formats). No public or
cross-requester catalog is supported.

A successful `POST /v1/evidence/batch` response uses only
`application/vnd.registrystack.evidence.request-batch+json`. The closed
`registry.evidence-request-batch/v1` envelope preserves request order and has
one `evidence` or `evidence-not-available` result per item. A request must send
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
The Adapter route returns a closed `no-match` or `ambiguous` outcome without
provider details, and Evidence collapses both to unavailable according to the
requirement's disclosure rule. Provider problem bodies, types, codes, details,
and traces are never reflected to the caller. Transport, authentication,
budget, protocol, script, schema, and signing failures remain dependency or
service failures rather than becoming `no-match`. Safe problem codes do not
reflect protected inputs.

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
problem, the audit writer durably records the minimal refusal event under
its server-minted operation identifier. It proves that the authenticated requester
was refused without recording which request field or authority check failed.
The caller never sees the event. If the audit append fails, Evidence returns
the generic `service.unavailable` problem with HTTP 503 instead. Authentication,
malformed-request, and invalid-selector failures are operational-only and do not
create this event.

## Measured throughput

This end-to-end measurement drives the real router over real sockets. Every
request runs token verification, rate limiting, Rhai request preparation, one
outbound source call, Rhai extraction, evidence construction, in-process ES256
signing, and both durable file audit appends. It does not model an external
Transit deployment's latency or availability.

The test copies `products/evidence/fixtures/acceptance/all-definitions` into a
temporary deployment and drives its adult-status request. It uses a local
signer, a preconfigured test authenticator, and the actual file-backed audit
writer with group commit, writing a temporary `audit.jsonl`. No audit sink is
injected. The fixed upstream JSON and raised fixture limits below make this a
controlled local journey, not a production workload.

These figures come from a shared development machine and are directional,
not deployment capacity claims. Unrelated compilation overlapped this run;
they do not establish a performance change from earlier measurements.

| Measurement | Value |
|---|---|
| Sustained rate | 5,461 requests/second |
| Audit appends | 10,923 appends/second (two per request, independently rounded) |
| Latency p50 / p95 / p99 | 20.07 / 44.82 / 64.75 ms |
| Non-2xx responses and failures | 0 |
| Offered concurrency | 128 requests in flight, 128 principals |
| Window | 10 s measured, after a 3 s unmeasured warm-up |
| Host | Apple M5 Max, 18 logical cores, macOS 26.4.1, optimized build |
| Host load averages, start / end (1, 5, 15 min) | 31.11, 28.39, 23.68 / 45.46, 32.14, 25.17 |
| Unrelated compiler processes, start / end | 1 Cargo and 17 rustc / 1 Cargo and 8 rustc |
| Source revision | `8821b3a67` |
| Date | 2026-09-25 |

Reproduce with:

```bash
cargo test --locked --release -p registry-evidence --lib -- \
  --ignored --nocapture sustained_load_holds_one_thousand_requests_per_second
```

The release test was compiled before the timed window. The check passed and
verified one access-attempt and one disclosure-release audit record for every
released assertion. Absolute rate and latency on this shared host remain
directional observations, not acceptance gates for the audit simplification.

The harness serves the upstream source from a minimal in-process handler
returning one constant JSON body. It measures that handler's standalone
ceiling in the same run, with the same client, worker count, header set, and
window. The source sustained 130,722 requests/second with no failures, 23.9
times the Evidence rate. Below five times the Evidence rate, the check reports
an inconclusive result because the source harness may be the bottleneck.

Latency is a closed-loop consequence of the offered concurrency. A deployment
with fewer requests in flight sees a different latency and rate. The audit
writer commits in groups, so concurrent appends can share a write and fsync;
this measurement does not represent the per-record cost at low concurrency.

The harness raises four defaults only in its temporary fixture bundle: the
per-principal rate limits, `maximumConcurrentRequests`, each source's outbound
`maximumConcurrency`, and the audit file's `rotateBytes`. Those values are
measurement scaffolding, not a recommended deployment posture. Keep the
shipped defaults and tune from observed traffic.

## Capacity planning

The rate in the Measured throughput section is one host with one constant
source. Sizing a real deployment is a matter of finding which ceiling binds
first, and for most
deployments it is not Evidence.

Outbound source concurrency binds first whenever the provider is slower than
the in-process handler used for measurement. Each runtime endpoint binding's
`maximumConcurrency` is the number of requests one Evidence process may have
outstanding through that named connection and endpoint at once. Sustained
throughput through it is therefore about `maximumConcurrency` divided by the
provider's round-trip latency. A value of 8 against a provider answering in
20 ms sustains roughly 400 requests/second, and Evidence being capable of
thousands changes nothing about that. The field accepts 1 to 256 and defaults
to 8.

Every source program that uses the same connection name in one process shares
that capacity. Different names have isolated permits, even if they select the
same origin. The limit is not distributed across replicas: the fleet can place
up to `maximumConcurrency` multiplied by the number of Evidence processes in
flight against that endpoint. Size both the per-process limit and replica count
against the provider's tolerance for the whole workload. Raising either moves
load onto the provider, so raise them against the provider's documented or
agreed limit, not against Evidence's spare capacity.

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
`evidence_http_requests_total` separates the three rejections: `evidence.rate-limited`
is the per-principal limiter, `service.unavailable` is the request timeout
budget running out, which under load is normally a request that never got an
admission slot, and `source.unavailable` is the source failing rather than
merely being slow. A saturated but healthy source produces
none of those. It appears only as `evidence_http_request_duration_seconds`
rising while the request count stays flat, because Evidence is waiting on the
provider and reporting success when the answer arrives; confirming that
diagnosis needs source latency observed at the provider, which is why the
`maximumConcurrency` arithmetic is worth doing before traffic rather than
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
A policy document the command cannot read is reported as the closed `malformed`
class too. `evidence check-policy --verification-policy <file>` reads the same
document the same way and reports every problem with its line, column, and
code, and `--holder-bound-policy <file>` does the same for the policy
`evidence verify-presentation` reads. No diagnostic repeats a value written in
the policy, and the command compares the policy with no response, so it is no
oracle either. It exits 0 when the policy reads, 1 when it was refused, 2 on a
usage error, and 3 when the file could not be read.

Operators must verify a candidate revision with the applicable phase and final
commands in [AGENTS.md](AGENTS.md). Public-demo source tests are optional,
ignored, read-only, local, and non-gating. They may run only after deterministic
mocks pass and only with approved synthetic selectors and securely stored
credentials under [the source-testing contract](SOURCE-TESTING.md).

Evidence Version 1 is releasable only when all four coequal acceptance
definitions pass the complete offline and HTTP path, every row of
`contracts/acceptance-test-traceability.yaml` passes on one revision, generated contracts reproduce exactly, and the
security acceptance matrix is reviewed.
