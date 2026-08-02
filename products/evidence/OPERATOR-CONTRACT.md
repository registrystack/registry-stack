# Evidence Version 1 operator contract

Status: Implemented Version 1 operator contract

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
- fixed, bounded HTTP JSON source requests with fixed or selector-bound paths,
  fixed non-secret headers, client-side response projection, denied redirects,
  logical private-CA trust profiles, and generic Basic, static Bearer, static
  API-key, or OAuth 2.0 client-credentials authentication through secret
  references;
- one active EdDSA reference signing key, flattened JWS JSON success responses,
  and public key discovery at `/.well-known/evidence/jwks.json`;
- keyed JSONL audit on storage whose durability the operator has explicitly
  established;
- production HTTPS exposure, dependency timeouts, per-source concurrency
  limits, per-principal rate controls, and bounded failed-selector attempts.

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
one listener, bundle directory, secret root, audit destination, and local TLS
trust files. The runtime file cannot override service identity, trust domain,
authentication, authority, sources, request policy, scripts, disclosure, rate
limits, signing policy, or audit fail-closed behavior. The two content hashes
identify the exact loaded inputs but are not trust decisions. The operator
establishes trust through review, distribution controls, read-only mounts, and
process replacement for every revision.

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

## Discovery of available evidence

Evidence Version 1 answers “what may this caller request?” with authenticated
`GET /v1/evidence-definitions`. Availability is requester-relative: the
definition must exist in the exact deployed bundle and exactly one authority
path must match the verified token, requirement, purpose, audience, complete
subject-role set, selector profiles, and value origins. The runtime never
publishes a global unauthenticated list.

Discovery uses four separately trusted surfaces:

| Artifact | Purpose | What it does not do |
|---|---|---|
| Generated Evidence OpenAPI | Describes `GET /v1/evidence-definitions`, `POST /v1/evidence`, operational routes, envelopes, media types, and safe problems. | It contains no deployment definitions or entitlements. |
| Authenticated definition response | Lists the exact complete request shapes available to this verified token at this bundle revision. | It performs no provider access, does not grant authority, and is not a global catalog. |
| Static onboarding material | Gives an approved consumer token-acquisition instructions, human descriptions, legal context, endpoint trust, and verifier policy through the existing API catalog, developer portal, configuration repository, or bilateral process. | It is not accepted by the runtime and grants no authority. |
| Evidence JWKS | Publishes the active and retained public verification keys. | It is not a trust anchor and contains no definition or entitlement metadata. |

Each item in `definitions` is one complete invocable combination, not a
cartesian product for the client to assemble. It contains:

- exact governed bundle revision plus legal issuer and technical provider;
- requirement and Evidence Type identifiers;
- one allowed purpose;
- output concept identifiers and value forms;
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

The publication workflow is:

1. Review the complete bundle and its combined disclosure surface.
2. Run `evidence check` and every referenced fixture, and record the exact
   governed bundle revision.
3. Publish the generic OpenAPI and static onboarding material; configure token
   issuance and verifier trust through the same governed process.
4. Obtain a token, call `GET /v1/evidence-definitions`, and bind the returned
   `configurationRevision` to the deployment revision expected during rollout.
5. Construct requests only from one returned complete shape. Do not combine
   subjects, profiles, purposes, or fields across items.
6. On a relevant bundle or trust change, update onboarding material and
   coordinate rollout. Clients observe the new revision through authenticated
   discovery, not by probing problem responses.

Version one does not implement a public, cross-requester, searchable, mutable,
or federated catalog, a registration editor, or a `describe` CLI command.
`/health`, `/ready`, `/openapi.json`, public problems, and JWKS never reveal
enabled definitions or selector profiles.

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

The listener request timeout bounds admission, concurrency queueing, and body
collection. It is not a total evaluation deadline. Once a protected evaluation
starts, Evidence lets it finish under the separately bounded OIDC and source
operations so cancellation cannot bypass required audit or signed-response
release ordering.

## Response formats

Evidence releases one stateless assertion. `responseFormats` decides which
serializations may carry it, and the closed values are `signed-jws`,
`unsigned-json`, and `sd-jwt-vc`. Both the immutable bundle and every authority
grant declare the list, both default to `[signed-jws]` alone, and both must
keep `signed-jws` enabled. Startup rejects a duplicate or unknown value and
rejects any list that drops the signed default.

The two lists are intersected and never unioned. A format is releasable only
where the bundle and the one complete matched grant both name it, so enabling a
format bundle-wide grants nothing by itself, and a grant cannot widen beyond the
bundle. Requesting a format outside the intersection is refused with the
ordinary `not_authorized` problem before credential acquisition and source
access, and the refusal does not reveal which layer withheld it. An `Accept`
that names no known format at all, or that is duplicated, combined,
parameterized, or weighted, returns `response_format_not_acceptable` with HTTP
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
claim and is meaningful only for the SD-JWT VC format. Only a public OKP
Ed25519 JWK is accepted; an unacceptable key is rejected as a malformed request
alongside the nonce check, before authentication, credential acquisition, and
source access. The key never reaches authorization, selectors, Rhai, sources,
audit, or the signed-JWS payload. Evidence issues no key-binding JWT, requires
none, and verifies none, so `cnf` is an unverified caller-supplied
convenience for whatever presentation layer the operator runs elsewhere.

Signing failure remains fail-closed for every protected format. A deployment
that cannot sign returns a safe transient failure and never downgrades an
SD-JWT VC request to unsigned output or to the signed default.
[The SD-JWT VC demo](SD-JWT-VC-DEMO.md) exercises this whole path locally.

## Secrets and keys

Source credentials and private signing material are supplied only through the
supported secret-reference mechanism. They do not appear in YAML values,
Rhai, command arguments, environment dumps, logs, audit, errors, snapshots,
or generated contracts. Private key parsing uses an explicit algorithm
allowlist. Missing or failed signing is fail-closed and never releases an
unsigned success response.

The operator configures one active signing key and retains each retired public
key in the published JWKS for at least the maximum assertion validity plus
allowed clock skew. The JWKS is discovery, not a trust anchor. Verifiers obtain
the provider identity and JWKS location through governed configuration, pin
that trust, allowlist the expected algorithm, and resolve `kid` only within the
trusted key set. They never follow a message-provided remote key URL.

A valid signature proves that the technical provider controlling the key signed
the exact payload. It does not prove the source fact is true, confer legal
notarization, create a qualified electronic signature, or create a holder
credential. Governance establishes the provider's authority to act for the
named legal issuer.

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

Every source declares its acquisition posture. Requirements inherit the
posture of their configured source:

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

Bundle-fixed headers cannot set authentication, routing, cookies, framing,
forwarding, proxy, or tracing fields. Selector-bound path placeholders occupy
complete segments and Rust expands them directly from already authorized
selectors. Scripts render only query pairs and one JSON body.

A source may name a logical TLS trust profile. `runtime.yaml` binds it to one
bounded PEM CA file. Hostname and fixed-origin verification remain mandatory;
there is no insecure or trust-all mode. Version 1 ignores `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` and has no application-level proxy.

## Audit and operational data

The configured audit sink must durably accept the access-attempt event before
the first evidence-data source read. It must durably accept the
disclosure-release event after signing and before response release. Either
failure blocks the applicable action.

Audit contains reviewed identifiers and decision categories, never raw
selector values, per-field selector hashes, source values, Supported Values,
credentials, tokens, or raw subject identifiers. When correlation is required,
one keyed, domain-separated, versioned pseudonym covers the complete canonical
role, selector-profile identifier, ordered field names, and selector value
bundle. It must not be globally stable across purposes or audiences.

Operational logs contain route templates, operation identifiers, duration,
status category, and safe internal error categories only. Request bodies,
selector profile identifiers and values, source requests and responses,
authority grants, Rhai inputs, credentials, tokens, and disclosed values are
excluded from logs, metrics, traces, snapshots, panics, and errors.

The serving process writes those records as line-delimited JSON on standard
output, one per served request, and `EVIDENCE_LOG` selects verbosity with a
default of `info`. Offline commands print their own result and emit no
operational records. Every response, including responses to unrouted paths,
carries the request's operation identifier in `X-Request-Id`; it is minted by
Evidence and never taken from an inbound header, so a caller reporting a
problem can quote an identifier the operator can find without disclosing
anything about the request.

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

At process startup the runtime verifies the complete keyed JSONL chain and
captures the exact audit file identity, length, modification fingerprint, and
verified tail. Steady-state appends and readiness probes validate that pinned
identity and fingerprint plus the expected tail and length without rescanning
the growing file. Any external replacement or modification makes readiness and
future appends fail closed. A restart performs the complete keyed-chain
verification again. Operators should also run their governed offline chain
verification during backup, restore, and incident procedures.

## Audit chain rotation and rollback

`auditStorage.maximumFileBytes` is a hard ceiling. The runtime enforces it when
it opens the file at startup, before every append, and on every readiness
probe. A deployment that reaches the ceiling fails closed: appends are refused,
so evidence requests fail, and readiness reports the service unavailable.
Version 1 has no online rotation, so the operator must rotate the chain during
a planned stop before the ceiling is reached.

Rotation is a stop-and-rename procedure for three reasons. The service holds an
exclusive advisory lock on `<auditStorage.path>.lock` for its whole life, so no
second process can write the same chain. The running process pins the open
audit file by identity and fingerprint, so a rename underneath a running
process makes readiness and every later append fail closed rather than silently
continue. Both the audit file and its lock file must stay owner-only mode
`0600`, singly linked, regular files, so copy-and-truncate, hard links, and
symlinks are all rejected.

1. Watch the audit file length against `auditStorage.maximumFileBytes` and
   schedule the window with headroom. The ceiling is not a rotation trigger; it
   is an outage.
2. Stop the service with SIGTERM, which is what a service manager and a
   container runtime both send, or with Ctrl-C for an interactive process. The
   server stops accepting connections, finishes the evaluations already
   admitted, completes their audit writes, and exits successfully.
   `listener.shutdownGraceMilliseconds` is the operational target for that
   drain, not a cancellation boundary: an evaluation already inside the runtime
   is allowed to finish so its audit and signing invariants hold. Confirm the
   process has exited before continuing, which is also what releases the lock.
3. Archive the retired chain by rename, preserving owner and mode:

   ```sh
   mv /var/lib/registry-evidence/audit/evidence.jsonl \
      /var/lib/registry-evidence/audit/evidence-<utc-timestamp>.jsonl
   ```

   Leave `evidence.jsonl.lock` in place. It carries no chain state.
4. Record the archived file name, its byte length, its final record hash, and
   the stop and start times in the operator change record. Each chain file
   begins at genesis and is independently verifiable, and nothing inside the
   new file points back at the archived one, so this record is the only link
   between the retired chain and its successor. Without it the deployment has a
   gap it cannot later explain.
5. Start the service again. Startup finds no file at the audit path, creates
   one with mode `0600`, and begins a new keyed chain at genesis.
6. Verify before restoring traffic. `GET /ready` must return `200` on the new
   chain, and the governed offline chain verification must pass over both the
   archived file and the new file. Retain the archived file under the
   deployment's audit retention rule.
7. Roll back by repeating step 2, renaming the archived chain back to the audit
   path, and starting again. Startup reverifies the complete keyed chain, so a
   restored file that was modified refuses to start rather than continuing on a
   forked chain. Never concatenate, merge, or edit chain files, and never
   restore a chain that a later process has already appended to.

Readiness behavior across the window is deliberate. The service is stopped for
steps 3 and 4, so `/ready` does not answer at all and the operator must drain
traffic on the stop rather than wait for a readiness signal. After the start it
returns `200` only once the new chain is opened and verified along with the
subject-binding key, the signing provider, and every source credential.

No event is lost and no record is ambiguous, provided the order above is kept.
The stop is graceful, so an admitted evaluation writes its disclosure-release
event before the process exits. The archive is a rename of an already closed
file, so nothing can be appended to a retired chain. The successor is a new
file starting at genesis, so no record belongs to two chains.

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
declared as `Content-Type: text/plain; version=0.0.4`. Two series are
published:

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

The registered route templates are `/v1/evidence`,
`/v1/evidence-definitions`, `/health`, `/ready`, `/openapi.json`,
`/.well-known/evidence/jwks.json`, and `/.well-known/jwt-vc-issuer`. The
reviewed problem codes are the closed public set: `malformed_request`,
`invalid_selector`, `authentication_failed`, `not_authorized`,
`response_format_not_acceptable`, `evidence_not_available`, `rate_limited`,
`dependency_unavailable`, and `service_unavailable`.

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
evidence_http_requests_total{route="/v1/evidence-definitions",method="GET",status="client_error",error="authentication_failed"} 1
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

The series describe the HTTP boundary only. Version 1 publishes no source-call,
signing, credential-acquisition, or audit-sink series. A slow or failing
upstream source is visible only as evidence-request duration and as the problem
code the boundary returned; audit, signing, and source-credential health are
reported by `/ready` rather than by telemetry.

## Startup and readiness

Before production exposure, the operator runs:

```sh
evidence check
evidence evaluate --fixture <path>
```

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
exactly one requirement.

The reference file-secret provider reads only regular, non-symlink files below
the configured `secretProviders.file.root`. The secret root is operator-only and
each secret file must be owned by the service identity with mode `0600`.
Audit and subject-binding secret files contain independently generated raw key
bytes and must each be at least 32 bytes. They are not decoded as base64 by the
file provider. Source credentials retain their provider-defined lexical form.
Signing material is an Ed25519 private JWK whose `kid` exactly matches
`signing.activeKeyId`; only the public current key and configured retired public
keys appear at the JWKS endpoint. The audit JSONL path must be on storage whose
append durability, permissions, capacity, backup, restore, retention, and keyed
chain verification the operator owns.

`evidence check` validates and compiles the complete bundle. Fixture evaluation
covers positive, negative, boundary, missing-data, source-failure,
existence-disclosure, and anti-reconstruction behavior without a running
source.

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
every local path/trust binding validated, mounted secret files and signing
material parsed, and the audit chain opened and verified. Readiness rechecks
the subject-binding key, signing provider, pinned audit sink, and every source
credential. Basic, static Bearer, and static API-key credentials are checked
locally. OAuth client-credentials readiness performs its bounded token
bootstrap against the configured token endpoint. OIDC JWKS retrieval is lazy
and follows the verifier cache lifecycle, so readiness does not prefetch it.
Neither startup nor readiness sends an evidence-data request or probes a source
data endpoint. Readiness
fails when a required local runtime or bundle input, selector binding,
credential, CA binding, audit dependency, or signing dependency is absent,
mutable, or invalid.

The native operations are:

```text
GET /v1/evidence-definitions
POST /v1/evidence
GET /health
GET /openapi.json
GET /ready
GET /.well-known/evidence/jwks.json
GET /.well-known/jwt-vc-issuer
```

`GET /openapi.json` publishes the generated public contract as
`application/openapi+json`. It carries no credential requirement because the
served bytes are the released generated artifact: the same document shipped in
`products/evidence/generated/`, independent of the deployed bundle.

A successful `GET /v1/evidence-definitions` response uses `application/json`
and the closed requester-scoped definition schema. It requires the same strict
Bearer authentication profile and per-principal request budget as evidence
creation.

A successful `POST /v1/evidence` response uses `application/jose+json` and the
flattened JWS JSON Serialization unless the requester selected another enabled
format under [response formats](#response-formats). No public or
cross-requester catalog is supported.

`GET /.well-known/jwt-vc-issuer` is unauthenticated discovery for the SD-JWT VC
format. It publishes the configured provider identity and the same public key
set as `/.well-known/evidence/jwks.json`, and nothing else. It is served
whether or not any grant enables the credential format, it never reveals which
requesters or requirements do, and it is discovery rather than a trust anchor
on exactly the terms in [secrets and keys](#secrets-and-keys).
No-match and ambiguous outcomes are publicly indistinguishable by default.
Source, signing, and dependency failures use stable safe problem codes and do
not reflect protected inputs. Signing failure returns a safe transient failure.

Every authorization refusal collapses to one generic `not_authorized` problem
(code `n`) with HTTP 403 and reveals no layer detail: a principal outside the
bundle audience, a requirement no matched grant permits, an authority the grant
does not carry, and an unsigned-envelope request the bundle or grant does not
allow all return the same body. This is deliberate; the response is not an
oracle for which check failed. Because the wire response is intentionally
uninformative, operators debug a 403 from trusted local state, not from the
response. Confirm, in order: the Bearer principal is in the deployed bundle's
audience; a grant matches the requested requirement, purpose, and subject
roles; the grant carries the claimed authority; and, only for an unsigned
request, both the bundle and that grant permit
`application/vnd.registrystack.evidence-unsigned+json`. The keyed audit chain
records the refusal phase for after-the-fact diagnosis; the caller never sees
it.

## Verification and release limit

A relying party or operator re-verifies a stored signed response offline with
`evidence verify --jws <file> --jwks <file> --policy <file> [--at <rfc3339-utc>]`.
The pinned JWKS file is the complete trust set and the policy document carries
every expectation from independent trusted state: the retained request nonce,
the expected role-bound subject bindings, and the expected output contract,
under
[`contracts/verification-policy.schema.yaml`](contracts/verification-policy.schema.yaml).
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
