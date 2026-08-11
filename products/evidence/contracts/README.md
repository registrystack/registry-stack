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
multi-subject operation.

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
- `verification-policy.schema.yaml`: the closed all-required relying-procedure
  policy document consumed by the offline `evidence verify` command, its frozen
  command surface, exit codes, and no-network rule;
- `problem-contract.yaml`: safe public failures, the
  `response_format_not_acceptable` negotiation failure, and existence-collapse
  rules;
- `authority-context.schema.yaml` and `selector-contract.yaml`: normalized
  authority, one-decision authorization inputs, exact selector profiles, and
  value-origin rules;
- `audit-event.schema.yaml` and `request-batch-audit-event.schema.yaml`: the
  protected native audit-record shapes, with
  distinct discriminators for mutually exclusive complete authorized-material
  and minimal authenticated authorization-refusal shapes. Complete events carry
  the closed `responseProtection` mode and require `signingKeyId` exactly for
  cryptographically protected release; the refusal shape omits both; the
  request-batch shape groups bounded item indices by authority and pseudonymized
  subject set and records one ordered terminal outcome set;
- `bundle.schema.yaml` and `runtime.schema.yaml`: the immutable governed bundle,
  its bundle-level and grant-level `responseFormats` permission, closed
  process-local runtime bindings, and their non-override boundary;
- `supported-value-forms.yaml`: the complete closed value-form vocabulary;
- `rhai-abi.yaml` and `primitive-library.yaml`: the closed `prepare/2`,
  `extract/2`, `prepare_batch/2`, `extract_batch/2`, and selector-aware
  `derive/3` entry points, domain-neutral
  primitive allowlist, and resource limits;
- `source-contract.yaml`: the fixed HTTP JSON source boundary and the closed set
  of acquisition kinds a requirement may declare; and
- `sqlite-extract-source-contract.yaml`: the coequal `sqlite-extract` source
  boundary, covering one reviewed statement executed against a read-only
  mounted extract, the authorizer and bounds it runs under, the extract's
  publication metadata and maximum age, and the runtime file binding that
  names it; and
- `security-invariant-matrix.yaml`: threat, enforcement point, and required
  negative test for every Version 1 trust and privacy invariant; and
- `security-test-traceability.yaml`: exact executable Rust tests satisfying
  every named `sec-*` requirement. The package contract test rejects a missing,
  extra, duplicated, or stale test reference; and
- `acceptance-test-traceability.yaml`: exact executable Rust tests satisfying
  every numbered Version 1 acceptance requirement, under the same rejection
  rule.

The complete trusted-script ABI, configuration vocabulary, executable fixture
contract, and deployment-shaped references live under
[`../reference/request-adapter/`](../reference/request-adapter/). They are
normative Version 1 inputs, not future-profile examples.

## Pre-1.0 definitions discovery migration

Registry Stack deliberately retains the `registry.evidence-definitions/v1`
identity while making `holderBoundBatchMaxSize` a required member of the
closed definitions response after v0.18. This is a pre-1.0 breaking product
improvement. A strict client or validator built against the v0.18 schema
rejects the added member because that schema has `additionalProperties: false`.

Upgrade Evidence Gateway and every Evidence client or protocol adapter that
reads its definitions response together. The current Evidence client treats a
missing `holderBoundBatchMaxSize` as `1`, which supports a staged rollback or a
short interoperation window in which the client is upgraded before Evidence
Gateway. That default does not make an older strict client able to read the new
response. Do not upgrade Evidence Gateway first while an older client or
adapter remains in service.

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
3. The provider owns record lookup. Extraction may return only `match`,
   `no_match`, or `ambiguous`; only `match` carries facts. A reviewed
   deterministic derivation may compare declared authorized selectors with
   complete facts from one uniquely resolved authoritative record.
4. Rust owns authorization, minimized script inputs, fixed path and header
   authority, networking, credentials, TLS trust, response projection, output
   validation, evidence construction, signing, and audit. Rhai prepares only
   ordered query pairs and one JSON body, extracts the closed lookup result or
   an exact opaque-slot bijection for an eligible source batch,
   and derives declared concepts from matched facts and explicitly declared
   authorized selectors. It cannot perform I/O.
5. Signed flattened JWS over the exact UTF-8 payload bytes is mandatory and the
   default result. The exact unsigned media type selects the separately typed
   unsigned envelope, and the exact `application/dc+sd-jwt` media type selects
   the audience-scoped SD-JWT VC serialization, each only when the immutable
   bundle and the one complete matched grant both permit it. No failure on any
   format falls back to another format, and the final immutable bytes exist
   before the disclosure-release audit that gates them.
6. The complete enabled bundle is one disclosure surface. Individually safe
   definitions may still be rejected when their combination reconstructs a
   protected value.
7. The governed bundle and `runtime.yaml` are separate closed startup inputs.
   Runtime binds only process-local paths, listener bounds, audit storage,
   file secrets, signer transport and pinned version, and logical private CAs.
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
lifecycle, replay or nonce state beyond the stateless request-nonce echo and
comparison, server-issued challenges, OOTS, delegated agents, federation,
workflow, public or federated catalogs, runtime bundle mutation, source
planning, multi-source fulfillment, and a general policy engine. The SD-JWT VC
response format is a serialization of the same assertion under
`sd-jwt-vc-profile.yaml`; it introduces no offer, code, nonce, status, or
persisted credential state. Authenticated definition discovery is a closed projection of
existing authority, not an authorization source or catalog. No contract here
reserves a field or hook for future profiles.
