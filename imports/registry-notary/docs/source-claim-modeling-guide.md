# Source And Claim Modeling Guide

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** evaluation · **Audience:** operator

This guide helps adopter teams design the source connections and claims that
Registry Notary will evaluate. It complements the config reference by focusing
on modeling choices: what belongs in an upstream source, what belongs in a
Notary claim, and how to avoid accidental over-collection.

## Mental Model

Registry Notary does four separate jobs:

1. Authenticate the caller and check scopes.
2. Read the minimum required data from configured source registries.
3. Evaluate a configured claim from that source data or dependent claims.
4. Return a claim result, render a supported format, or issue a credential.

The source registry remains the system of record. Notary should not become a
copy of the registry, and a sidecar should not decide whether a claim is true.
Keep source connectors narrow and keep claim semantics in Notary config.

## Pick The Source Connector

| Connector | Use when | Config value |
| --- | --- | --- |
| DCI | The upstream speaks a DCI-style search envelope | `connector: dci` |
| Registry Data API | The upstream or sidecar exposes `/v1/datasets/{dataset}/entities/{entity}/records` lookups | `connector: registry_data_api` |
| OpenFn sidecar | An adaptor or workflow must normalize a system into the Registry Data API shape | Configure Notary with `registry_data_api` pointing at the sidecar |

Prefer the simplest direct source. Add an OpenFn sidecar when the target system
needs adaptor code, request shaping, credential handling, or normalization that
does not belong inside Notary itself.

## Source Connection Design

A source connection is a reusable upstream target:

```yaml
evidence:
  source_connections:
    civil_registry:
      base_url: https://registry.example.gov
      source_auth:
        type: oauth2_client_credentials
        token_url: https://registry.example.gov/oauth2/client/token
        client_id_env: CIVIL_REGISTRY_CLIENT_ID
        client_secret_env: CIVIL_REGISTRY_CLIENT_SECRET
        request_format: json
      max_in_flight: 8
      retry_on_5xx: true
      bulk_mode: none
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
```

Design rules:

- Configure exactly one of `token_env` or `source_auth`.
- Use HTTPS source URLs in shared environments.
- Keep `max_in_flight` below the upstream's safe concurrency limit.
- Leave `retry_on_5xx: true` for idempotent reads.
- Set `retry_on_5xx: false` for sidecar worker flows that must not repeat.
- Use `bulk_mode: none` until the source contract has been tested.
- Keep `field_paths` and claim-level `fields` limited to what claims need.

## DCI Sources

DCI sources use a search endpoint and an envelope shape. Check these fields with
the source owner:

- `search_path`: DCI search path relative to `base_url`.
- `sender_id`: Notary identity sent to the source.
- `receiver_id`: optional source receiver identity.
- `query_type`: usually `idtype-value`.
- `registry_type`, `registry_event_type`, `record_type`: source-specific
  envelope fields.
- `records_path`: JSON Pointer to records in a single response.
- `bulk_records_path`: JSON Pointer used inside each batched response item.
- `max_results`: default is 2 so Notary can distinguish not found, exactly one,
  and ambiguous.
- `field_paths`: source-level JSON Pointer aliases for fields used by claims.

For OpenCRVS-style DCI, confirm whether the token endpoint expects JSON or form
encoding. The config default is form; the OpenCRVS demo uses
`request_format: json`.

## Registry Data API Sources

Registry Data API sources expose lookup-style reads:

```text
GET /v1/datasets/{dataset}/entities/{entity}/records?{lookup_field}={lookup_value}&fields=a,b&limit=2
Authorization: Bearer <source-token>
Data-Purpose: <purpose>
```

Successful responses use:

```json
{ "data": [{ "field": "value" }] }
```

Use this connector when an upstream already has the shape or when an internal
sidecar normalizes a target system into that shape.

## OpenFn Sidecar Sources

The OpenFn sidecar is a separate process that runs pinned worker code and
returns a Registry Data API-shaped response. Notary still models it as:

```yaml
evidence:
  source_connections:
    openfn_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: OPENFN_SIDECAR_TOKEN
```

Use the sidecar when the target system needs:

- An adaptor or workflow to fetch data.
- Credential material that should stay out of Notary config.
- Output normalization.
- A private worker process boundary.
- Per-source smoke checks before Notary depends on it.

Sidecar rules:

- Do not expose the sidecar publicly.
- Pin worker runtime and adaptor versions.
- Store sidecar target credentials in sidecar env, not in Notary config.
- Return no more than two records for a lookup.
- Return only normalized fields needed by Notary.
- Do not put claim logic in the sidecar.

See
[`../crates/registry-notary-openfn-sidecar/README.md`](../crates/registry-notary-openfn-sidecar/README.md)
for sidecar manifest and worker details.

## Claim Boundaries

A claim should express one decision or one extracted value. Good examples:

- `birth-record-exists`
- `date-of-birth`
- `farmer-under-4ha`
- `household-enrolled-in-program`

Avoid claims such as `person-profile` or `full-registry-record`. Those tend to
over-collect, over-disclose, and become hard to authorize safely.

Every claim should answer:

- Which target entity is being evaluated?
- Is requester identity or relationship context needed?
- Which caller scope may evaluate it?
- Which source fields are required?
- What happens when no record is found?
- What happens when multiple records are found?
- Is the output a value, a predicate, or a redacted assertion?
- Can this claim be issued as a credential?

## Source Bindings

A source binding connects a claim to one source read:

```yaml
source_bindings:
  birth_record:
    connector: dci
    connection: civil_registry
    required_scope: civil_registry:evidence_verification
    dataset: civil_registry
    entity: birth_registration
    lookup:
      input: target.identifiers.national_id
      field: UIN
      op: eq
      cardinality: one
    query_fields:
      - input: target.identifiers.national_id
        field: UIN
        op: eq
    fields:
      birth_date:
        field: birth_date
        type: date
        required: true
```

Important choices:

- `required_scope`: scope the caller must have before this binding can read the
  source.
- `lookup.input`: request lookup path, such as `target.id`,
  `target.identifiers.<scheme>`, `target.attributes.<name>`, `requester.id`,
  `requester.identifiers.<scheme>`, `requester.attributes.<name>`, or
  `relationship.attributes.<name>`.
- `lookup.field`: upstream identifier field.
- `lookup.cardinality`: use `one` when the claim needs exactly one record.
- `query_fields`: optional multi-field lookup override. Use it when the source
  supports querying by more than one request path, such as first name, last
  name, and date of birth. Leave it empty for single-field lookup.
- `fields`: only fields needed by the rule.

Use separate bindings when a claim needs data from multiple registries. Use
claim dependencies when a rule can reuse previous claim outputs instead of
reading the same source again.

## Rule Types

Use `exists` when the fact is the presence of exactly one source record:

```yaml
rule:
  type: exists
  source: birth_record
```

Use `extract` when the claim returns a source field:

```yaml
rule:
  type: extract
  source: birth_record
  field: birth_date
```

Use `cel` when the claim is derived from source fields or dependent claim
results:

```yaml
depends_on:
  - farmed-land-size
rule:
  type: cel
  expression: "claims.farmed_land_size.value < 4.0"
  bindings:
    claims:
      farmed_land_size:
        claim: farmed-land-size
```

CEL-enabled builds are experimental for beta because the timeout bounds request
latency but is not a hard CPU or step limit. Prefer `exists` or `extract` when
they express the claim clearly.

## Disclosure And Formats

Disclosure config controls what the caller can ask Notary to reveal:

```yaml
disclosure:
  default: redacted
  allowed:
    - value
    - redacted
```

For privacy-sensitive claims, prefer redacted or predicate outputs. Allow
`value` only when the relying party genuinely needs the value.

`formats` controls renderable response formats for the claim. Include
`application/vnd.registry-notary.claim-result+json` for standard JSON claim
results. Add SD-JWT VC issuance through a credential profile rather than by
adding broad render formats.

## Credential Eligibility

A claim can be issued as a credential only when both sides agree:

```yaml
claims:
  - id: birth-record-exists
    credential_profiles:
      - birth_record_sd_jwt

credential_profiles:
  birth_record_sd_jwt:
    allowed_claims:
      - birth-record-exists
```

This two-way relationship prevents a profile from accidentally issuing from a
claim that was not designed for that credential, and prevents a claim from being
issued by an unrelated profile.

## Batch And Bulk Reads

Batch evaluation lets one request evaluate many target items for a claim. It
should be enabled only when the source and caller are ready for that access
pattern:

```yaml
operations:
  batch_evaluate:
    enabled: true
    max_subjects: 100
```

`evidence.inline_batch_limit` sets a general default. The claim-level
`max_subjects` config key is retained as the limit name for now, but it applies
to batch `items[]` target entries and should be lower when a source is sensitive
or slow.

Bulk source modes are separate from API batch evaluation:

- `none`: one source read per target item.
- `dci_batched_search`: DCI source supports a batched search envelope.
- `rda_in_filter`: Registry Data API source supports an `in` style filter and
  the operator attests that each lookup is unique.

Do not enable bulk modes until contract tests prove response shape,
cardinality, and source limits.

## Purpose Propagation

Claims and source bindings carry purpose through the request path. Use stable,
human-reviewable purpose values such as:

- `benefit_eligibility_check`
- `wallet_credential_issuance`
- `program_enrollment_verification`

Avoid using free-form user text as purpose. Purpose values should be part of the
deployment's policy review, source-owner agreement, and audit review.

## Modeling Checklist

- The claim id is stable and specific.
- The claim reads the fewest possible source fields.
- The source owner has confirmed lookup field, cardinality, and response shape.
- Missing, ambiguous, and upstream-error behavior are acceptable to the relying
  party.
- Caller scopes match source-owner access policy.
- Disclosure defaults to the least revealing useful output.
- Credential issuance is explicitly allowed by both claim and profile.
- Batch and bulk modes are disabled until source contracts are tested.
- OpenFn sidecars normalize data only and do not decide claims.
- `doctor --live` passes against a controlled test target.

## Testing With Doctor

Run non-live checks first:

```sh
registry-notary doctor --config registry-notary.yaml
```

Then run a live probe only with a controlled test target:

```sh
registry-notary doctor \
  --config registry-notary.yaml \
  --live
```

Live doctor probes can contact the upstream source. Use test data, document the
purpose with the source owner, and keep probe output out of screenshots or
support tickets unless it has been reviewed for disclosure.
