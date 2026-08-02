# Evidence Version 1 contract sources

Status: frozen Evidence Version 1 source contracts

These files are the human-reviewable source contracts for Evidence. They freeze
the public and trusted-bundle boundaries. Code-generated JSON Schema and
OpenAPI artifacts implementing these semantics are committed under
`../generated/` and reproduced exactly with
`../scripts/check-contracts.sh`; generated files are never hand-edited. The
generated set includes `evidence-unsigned-envelope-v1.schema.json`, the closed
envelope returned when unsigned output is explicitly requested and permitted.

The normative source set is:

- `cccev-field-mapping.yaml`: CCCEV 2.2.0 alignment and Evidence extensions;
- `request.schema.yaml`, `definitions.schema.yaml`, `evidence.schema.yaml`, and
  `jws-profile.yaml`: public discovery, request, the required `requestNonce`
  and its echo in the Evidence payload, response-format negotiation, payload,
  signing, rotation, and strict verifier rules;
- `verification-policy.schema.yaml`: the closed all-required relying-procedure
  policy document consumed by the offline `evidence verify` command, its frozen
  command surface, exit codes, and no-network rule;
- `problem-contract.yaml`: safe public failures, the
  `response_format_not_acceptable` negotiation failure, and existence-collapse
  rules;
- `authority-context.schema.yaml` and `selector-contract.yaml`: normalized
  authority, one-decision authorization inputs, exact selector profiles, and
  value-origin rules;
- `audit-event.schema.yaml`: the protected native audit record, including the
  closed `responseProtection` mode carried by every event and the `signingKeyId`
  required exactly for signed release;
- `bundle.schema.yaml` and `runtime.schema.yaml`: the immutable governed bundle,
  its bundle-level and grant-level `responseFormats` permission, closed
  process-local runtime bindings, and their non-override boundary;
- `supported-value-forms.yaml`: the complete closed value-form vocabulary;
- `rhai-abi.yaml` and `primitive-library.yaml`: the closed `prepare/2`,
  `extract/2`, and selector-aware `derive/3` entry points, domain-neutral
  primitive allowlist, and resource limits;
- `source-contract.yaml`: the single fixed HTTP JSON source boundary; and
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
   ordered query pairs and one JSON body, extracts the closed lookup result,
   and derives declared concepts from matched facts and explicitly declared
   authorized selectors. It cannot perform I/O.
5. Signed flattened JWS over the exact UTF-8 payload bytes is mandatory and the
   default result. The exact unsigned media type selects the separately typed
   unsigned envelope only when the immutable bundle and the one complete
   matched grant both permit it. No signed-path failure falls back to unsigned
   output, and the final immutable bytes exist before the disclosure-release
   audit that gates them.
6. The complete enabled bundle is one disclosure surface. Individually safe
   definitions may still be rejected when their combination reconstructs a
   protected value.
7. The governed bundle and `runtime.yaml` are separate closed startup inputs.
   Runtime binds only process-local paths, listener bounds, audit storage,
   file secrets, and logical private CAs and cannot override governed
   semantics or source authority.

Version 1 stops before documents, credentials, replay or nonce state beyond the
stateless request-nonce echo and comparison, server-issued challenges, OOTS,
delegated agents, federation, workflow, public or federated catalogs, runtime
bundle mutation, source planning, multi-source fulfillment, and a general
policy engine. Authenticated definition discovery is a closed projection of
existing authority, not an authorization source or catalog. No contract here
reserves a field or hook for future profiles.
