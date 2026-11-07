# Evidence Version 1 contract sources

Status: frozen Evidence Version 1 source contracts

These files are the human-reviewable source contracts for Evidence. They freeze
the public and trusted-bundle boundaries. Code-generated JSON Schema and
OpenAPI artifacts implementing these semantics are committed under
`../generated/` and reproduced exactly with
`../scripts/check-contracts.sh`; generated files are never hand-edited. The
generated set includes `evidence-unsigned-envelope-v1.schema.json`, the closed
envelope returned when unsigned output is explicitly requested and permitted,
plus `evidence-request-batch-v1.schema.json` and
`evidence-request-batch-response-v1.schema.json` for the bounded signed-JWS-only
multi-subject operation. It also includes
`client-profile/client-profile.schema.json` and
`client-contracts/client-contracts.schema.json`, the closed application-owned
progressive client profile and the reviewed, requester-scoped client-safe
contract snapshot, generated from the `registry-evidence-client` readers.

The normative source set is:

- `cccev-field-mapping.yaml`: CCCEV 2.2.0 alignment and Evidence extensions;
- `request.schema.yaml`, `request-batch.schema.yaml`,
  `request-batch-response.schema.yaml`, `definitions.schema.yaml`,
  `evidence.schema.yaml`, and `jws-profile.yaml`: public discovery, singular
  requests and bounded ordered request batches, the required `requestNonce`
  and its echo in the Evidence payload, response-format negotiation, payload,
  ES256 service signing, RFC 7638 key identifiers, publication, revocation,
  rotation, and strict verifier rules;
- `sd-jwt-vc-profile.yaml`: the audience-scoped SD-JWT VC response format, its
  exact claim and disclosure mapping, the optional `cnf` holder key, the
  issuer-metadata path, RFC 9901 and SD-JWT VC draft v18 pins, and its explicit profile non-goals. It adds a
  serialization of the same assertion and no credential lifecycle;
- `verification-policy.schema.yaml`: the closed relying-procedure policy
  document consumed by the offline `evidence verify` command, including
  required and optional output rules, its frozen command surface, exit codes,
  and no-network rule;
- `problem-contract.yaml`: safe public failures, the `format.unsupported`
  negotiation failure, W3C trace correlation, and existence-collapse rules;
- `authority-context.schema.yaml` and `selector-contract.yaml`: normalized
  authority, one-decision authorization inputs, exact selector profiles, and
  value-origin rules;
- `audit-event.schema.yaml` and `request-batch-audit-event.schema.yaml`: the
  protected native audit-record shapes, carried in the `record` member of the
  shared platform audit envelope, with
  distinct entry schemas for mutually exclusive complete authorized-material
  and minimal authenticated authorization-refusal shapes. Complete events carry
  the closed `responseProtection` mode and require `signingKeyId` exactly for
  cryptographically protected release. Current `/v3` access-attempt events also
  require the closed positive `executionBounds` captured from effective
  immutable runtime configuration before credentials or effects, while
  terminal events omit it. Retained authorized-material `/v2` events remain
  readable and omit it; the authorization-refusal `/v2` shape is unchanged and
  omits response protection, signing identity, and execution bounds. The
  request-batch shape groups bounded item indices by authority and pseudonymized
  subject set and records one ordered terminal outcome set;
- `public-check-request.schema.yaml`, `public-check-answer.schema.yaml`, and
  `public-check-audit-event.schema.yaml`: the experimental
  `POST /v1/public-check` body, the unsigned answer
  `registry.evidence.public-check/v1alpha1`, and the closed audit record of
  that unauthenticated route, which `audit-event.schema.yaml` does not carry.
  The generated JSON schemas `evidence-public-check-request-v1alpha1.schema.json`
  and `evidence-public-check-answer-v1alpha1.schema.json` under `../generated/`
  are produced from the first two;
- `bundle.schema.yaml` and `runtime.schema.yaml`: the immutable governed bundle,
  its digest-pinned Adapter pack route bindings, reviewed non-secret connection
  policies, bundle-level and grant-level `responseFormats` permission, closed
  process-local endpoint and credential bindings, and their non-override boundary;
- `supported-value-forms.yaml`: the complete closed value-form vocabulary;
- `rhai-abi.yaml` and `primitive-library.yaml`: the selector-aware `derive/3`
  assertion ABI, domain-neutral primitive allowlist, and resource limits;
- `security-invariant-matrix.yaml`: threat, enforcement point, and required
  negative test for every Version 1 trust and privacy invariant; and
- `security-test-traceability.yaml`: exact executable Rust tests satisfying
  every named `sec-*` requirement. The package contract test rejects a missing,
  extra, duplicated, or stale test reference; and
- `acceptance-test-traceability.yaml`: exact executable Rust tests satisfying
  every numbered Version 1 acceptance requirement, under the same rejection
  rule.

The current trusted derivation ABI is defined in
[`../reference/request-adapter/ADAPTER-API.md`](../reference/request-adapter/ADAPTER-API.md).
Source acquisition and extraction use the [Adapter pack contract](../../adapter/CONCEPT.md);
Evidence retains authorization, input minimization, fact validation, derivation,
signing, and release audit. The deployment and fixture references under
[`../reference/request-adapter/`](../reference/request-adapter/) describe the
corresponding current Evidence workflows.

`source-contract.yaml` and `sqlite-extract-source-contract.yaml` are explicitly
retired migration records for the inline Source transports. `rhai-abi.yaml`
defines only the current assertion derivation ABI. Current source preparation, acquisition
and extraction are governed Adapter pack route logic; an Evidence bundle selects
a pinned pack, route, reviewed connection and authorized selector inputs without
reproducing that transport program.

## Pre-1.0 definitions discovery migration

Registry Stack deliberately retains the `registry.evidence-definitions/v1`
identity while evolving the closed response before v1.0. The current shape adds
the effective audience, a stable complete-definition handle, effective response
formats, stable concept handles, required-output status, and bounded-list form
metadata. It also makes `maximumHolderBoundBatchSize` explicit, and it states a
concept's `form` as a mapping named by `type`: `{type: boolean}`, or
`{type: list, items: string, minimumItems: 1, maximumItems: 8, unique: true}`
with the list's members beside the tag. This is a pre-1.0
breaking product improvement. A strict client or validator built against the
older schema rejects the added members because that schema has
`additionalProperties: false`.

The governed `bounded-identifier` concept form adds exact, source-owned JSON
string outputs with an immutable prefix and byte bounds. Its discovery and
client-contract form is the existing `string`; relying parties that
compare a request field must compare the complete value exactly. Existing
controlled categories remain finite reviewed codelists. A deployment using the
new form needs an Evidence Gateway and authoring-tool version that recognizes
its bundle declaration.

Upgrade Evidence Gateway and every Evidence client or protocol adapter that
reads its definitions response together. The ceiling was published as
`holderBoundBatchMaxSize` before the configuration conventions release and is
`maximumHolderBoundBatchSize` from it on, with no alias on either side: the
current Evidence client refuses a response carrying the old member as it
refuses any unknown member, and an older strict client refuses the new one
the same way. There is no interoperation window across that rename. The
current client still reads a response with no ceiling member at all as `1`,
the only safe inference for a deployment that predates batch-ceiling
discovery; that default does not make any client able to read a response
written for the other spelling.

Access-attribution forwarding belongs to the reviewed protected-read host
protocol selected by a pack endpoint. It requires a provider that explicitly
trusts the authenticated Evidence service to supply the reserved requester and
purpose headers. The retired inline `forwardAccessAttribution` Source member
is not a configuration alias for that protocol.

All schemas use source-neutral identifiers. Names of compatibility targets may
appear only below `../fixtures/source-shapes/`. Acceptance-case vocabulary is
confined to test-only bundles below `../fixtures/acceptance/`; it is not core
Evidence vocabulary.

## Interpretation rules

1. Caller data never creates authority. One authorization decision must match
   the requester, optional actor, requirement revision, purpose, audience,
   authority path, and every role's selector profile and value origin.
2. A selector profile has one exact field set. Alternative sufficient sets or
   an added disambiguator are separate named profiles.
3. The provider owns record lookup. A pack route receives only its named,
   authorized selector inputs and returns the closed `Matched`, `NoMatch`,
   `Ambiguous`, or `Unresolved` lookup result; only `Matched` carries
   schema-validated facts. A reviewed
   deterministic derivation may compare declared authorized selectors with
   complete facts from one uniquely resolved authoritative record.
4. Rust owns authorization, minimized pack inputs, fixed path and header
   authority, networking, credentials, TLS trust, response and fact-schema
   validation, evidence construction, signing, and audit. Governed Adapter pack
   routes own source preparation and extraction. Evidence Rhai derives declared
   concepts from matched facts and explicitly declared authorized selectors; it
   cannot perform I/O.
5. Signed flattened JWS over the exact UTF-8 payload bytes is mandatory and the
   default result. The exact unsigned media type selects the separately typed
   unsigned envelope, and the exact `application/dc+sd-jwt` media type selects
   the audience-scoped SD-JWT VC serialization, each only when the immutable
   bundle and the one complete matched grant both permit it. No failure on any
   format falls back to another format, and the final immutable bytes exist
   before the disclosure-release audit that gates them.
   Admission to that durable append is the disclosure-begin boundary and final
   acquisition-deadline gate. An
   append admitted before expiry completes without cancellation and may return
   the exact bytes after expiry; the deadline is not a hard response-time cutoff.
6. The complete enabled bundle is one disclosure surface. Individually safe
   definitions may still be rejected when their combination reconstructs a
   protected value.
7. The governed bundle and `runtime.yaml` are separate closed startup inputs.
   Runtime binds only process-local paths, listener and acquisition bounds, the
   audit destination, endpoint material, file secrets, signer transport and
   pinned version, and logical private CAs.
   It cannot override governed semantics, source authority, or the governed
   active public key.
8. Service signing keys are exact ES256 P-256 public JWKs whose `kid` is their
   RFC 7638 thumbprint. Production and evidence-grade signing uses a pinned
   non-exportable Transit key through a workload-local Unix socket. Local
   authoring alone may resolve a private JWK file.
9. Active, published, and revoked key sets are explicit and disjoint. Denied
   identifiers are checked before selecting a cached key, and configuration
   changes take effect only through restart.
10. The multi-subject request-batch route authenticates once, uses one
    evaluation instant, atomically charges its complete item count, and
    validates and authorizes every item before I/O. It releases one ordered,
    signed-JWS-only envelope after durable batch-native terminal audit, or one
    safe outer problem with no partial results.

Version 1 stops before documents, credential issuance protocols and credential
lifecycle (except the credential status profile of `CONCEPT.md` section 15.9), replay or nonce state beyond the stateless request-nonce echo and
comparison, server-issued challenges, OOTS, delegated agents, federation,
workflow, a public requester-entitlement or definition catalog, a searchable,
mutable, aggregate, or federated catalog, runtime bundle mutation, source
planning, multi-source fulfillment, and a general policy engine. The SD-JWT VC
response format is a serialization of the same assertion under
`sd-jwt-vc-profile.yaml`; it introduces no offer, code, nonce, status, or
persisted credential state; version 2, approved in `CONCEPT.md` section 15.9
and not yet published, adds the status reference and the ledger, and nothing
else. Authenticated definition discovery is a closed projection of
existing authority, not an authorization source or catalog. The separately
packaged public provider advertisement exposes only closed service facts for
external indexing and creates neither trust nor access. No contract here
reserves a field or hook for future profiles.
