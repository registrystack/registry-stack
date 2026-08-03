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

Audit and operational logging are separate channels and operators must not
confuse them. The audit chain is the accountability record: durable, complete,
tamper-evident, and it has no severity levels and no way to turn records off.
Both records every request writes, the access-attempt event durable before any
source read and the disclosure-release event durable before response release
as described above, are pinned by frozen Version 1 security invariants and are
not configurable. The `tracing` channel is the operational and diagnostic
record: it has levels, it is buffered and lossy, and it is cheap. The rule for
operators and integrators is: accountability facts belong in the audit chain
and never only in tracing, and operational noise belongs in tracing and never
in the audit chain. If an adopter needs more detail than the frozen audit
record carries, which some regulators require, the correct shape is a separate
operational log keyed by the audit record's `eventId`, not a verbosity setting
on the chain.

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
prove the active segment too, stop the service first, as under Rollback below.
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

The accepted address range is therefore a floor, not a boundary. Startup
rejects the mistake that actually exposes telemetry, a public or unspecified
`bindHost`, but an accepted RFC 1918 or unique-local address only means the
endpoint is unreachable from the public internet. On a flat pod network or a
shared VPC every workload already holds such an address, so binding one there
makes the endpoint scrapable by every neighbouring workload. `127.0.0.1` with
a same-pod or same-host collector is the shape that keeps the operator
boundary the operator intended; any wider binding must be closed by a network
policy, and the operator owns that control.

The two request-boundary series above describe the HTTP boundary only. Version
1 publishes no source-call, signing, credential-acquisition, or audit-sink
series. A slow or failing upstream source is visible only as evidence-request
duration and as the problem code the boundary returned; audit, signing, and
source-credential health are reported by `/ready` rather than by telemetry.

A third series, `evidence_rate_limiter_tracked_keys`, is also published on the
same listener: a gauge reporting the current number of tracked rate-limit
keys. It carries none of the four request-boundary labels, since it reports a
process-wide capacity fact rather than a per-request outcome. Operators should
alert on it approaching the 100,000-key ceiling described under
[requester authority and purpose](#requester-authority-and-purpose), since a
deployment at that ceiling refuses new principals with a capacity error rather
than degrading gracefully.

## Startup and readiness

Before production exposure, the operator runs:

```sh
evidence check
evidence evaluate --fixture "<path>"
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

`evidence check` validates and compiles the complete bundle, and resolves and
validates the mounted audit, subject-binding, and signing secret material
exactly as startup does, without opening the audit chain. A deployment whose
secret material startup would refuse, including a signing key whose `kid` does
not match `signing.activeKeyId`, fails check. Source credentials are not
resolved by check; readiness owns them. Fixture evaluation
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

## Measured throughput

One end-to-end measurement is kept in the repository so capacity planning
starts from a number rather than an estimate. It drives the real router over
real sockets, and every request in it runs token verification, rate limiting,
Rhai request preparation, one outbound source call, Rhai extraction, evidence
construction, Ed25519 signing, and both durable audit appends.

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

The measured rate above is one host with one constant source. Sizing a real
deployment is a matter of finding which ceiling binds first, and for most
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
`evidence_http_requests_total` separates the three rejections: `rate_limited`
is the per-principal limiter, `service_unavailable` is the request timeout
budget running out, which under load is normally a request that never got an
admission slot, and `dependency_unavailable` is the source failing rather than
merely being slow. A saturated but healthy source produces
none of those. It appears only as `evidence_http_request_duration_seconds`
rising while the request count stays flat, because Evidence is waiting on the
provider and reporting success when the answer arrives; confirming that
diagnosis needs source latency observed at the provider, which is why the
`concurrencyLimit` arithmetic above is worth doing before traffic rather than
after. Because the audit sink commits in groups, a deployment held to few
requests in flight also pays a higher per-record audit cost than the table
above, which is a consequence of the low concurrency rather than a separate
problem to tune.

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
