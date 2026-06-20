# Evidence Gateway Packs

Page type: maintainer guide
Product: Registry Lab
Layer: Evidence Gateway fixtures, Notary execution, and Lab smoke tests
Audience: maintainers and demo operators

This page explains the current Evidence Gateway packs in Registry Lab and the
fastest ways to test them.

## Pack Names And Binding Names

Registry Lab records two identities for each governed evidence fixture:

- `binding.id`: the runtime or ecosystem binding used by Lab scripts and Notary
  matching, such as `birth-registration-evidence/v1`.
- `evidence_pack.pack_id`: the neutral evidence contract name, such as
  `birth-registration-evidence/v1`.

Keep these fields aligned unless there is a real external protocol reason not
to. Pack and binding IDs should name the evidence being requested, not an
internal learning path or source adapter.

## Current Packs

| Binding id | Pack id | Evidence | Implemented input | Output |
| --- | --- | --- | --- | --- |
| `combined-support-eligibility/v1` | `combined-support-eligibility/v1` | Combined support eligibility demo evidence | `target.identifiers.national_id` | claim-result JSON, redacted result, SD-JWT VC |
| `birth-registration-evidence/v1` | `birth-registration-evidence/v1` | CRVS birth registration evidence backed by OpenCRVS DCI | `target.identifiers.UIN` with issuer `opencrvs` | claim-result JSON, redacted result, SD-JWT VC |
| `birth-certificate-evidence/v1` | `birth-certificate-evidence/v1` | Birth Evidence object and birth event existence | `target.identifiers.registration_number`; `target.attributes.given_name`, `target.attributes.surname`, `target.attributes.birth_date` for the demographic object claim | OOTS-style object JSON in claim-result JSON |
| `marriage-certificate-evidence/v1` | `marriage-certificate-evidence/v1` | Marriage Evidence object and marriage event existence | `target.identifiers.registration_number` | OOTS-style object JSON in claim-result JSON |

The certificate packs are derived from OOTS-style data models, but their runtime
names use the evidence requested. They are not OOTS conformance claims.

## Identifier And Demographic Matching

The implemented paths use identifiers. Demographic search is intentionally
called out in pack metadata when it is not implemented.

| Pack id | Identifier lookup | Demographic lookup |
| --- | --- | --- |
| `birth-registration-evidence/v1` | Implemented with `target.identifiers.UIN` | Not implemented in the current OpenCRVS Notary config |
| `birth-certificate-evidence/v1` | Implemented with `target.identifiers.registration_number` on `birth.certificate_summary` | Implemented with `target.attributes.given_name`, `target.attributes.surname`, and `target.attributes.birth_date` on `birth.certificate_summary_by_demographics` |
| `marriage-certificate-evidence/v1` | Implemented with `target.identifiers.registration_number` | Not implemented |
| `combined-support-eligibility/v1` | Implemented with `target.identifiers.national_id` | Not implemented |

Do not present the OpenCRVS demographic lookup as working until a configured
claim exists for it and a live fixture proves unique-match, no-match, and
multiple-match behavior.

## Certificate Evidence Shape

`birth.certificate_summary` and
`birth.certificate_summary_by_demographics` return a Birth Evidence object in
the claim-result `value`. The object includes common envelope fields
`identifier`, `issuing_date`, `issuing_authority`, `is_about`,
`is_conformant_to`, and `distribution`, plus `certifies_birth` with the child
and available parent details.

`marriage.certificate_summary` returns a Marriage Evidence object in
`value`. The object includes the same common envelope fields plus
`certifies_marriage` with `marriage_date`, `marriage_place`, and the two
spouses.

`birth.event_exists` and `marriage.event_exists` remain predicate claims for
clients that only need a boolean existence proof.

## Fast Tests

Run the local pack contract and runner tests:

```bash
just evidence-gateway-test
```

This runs:

```bash
scripts/check-evidence-gateway-fixtures.py
python3 -m unittest scripts.test_evidence_gateway_fixtures scripts.test_evidence_gateway_live_fixtures
```

Run the full live OpenCRVS DCI path when `.env.local` contains the OpenCRVS
credentials:

```bash
just opencrvs-dci
```

Run a specific live fixture profile against an already-running Notary:

```bash
just evidence-gateway-live birth-registration-evidence/v1 \
  --base-url http://127.0.0.1:4352 \
  --auth api-key \
  --token "$OPENCRVS_EVIDENCE_CLIENT_TOKEN" \
  --subject-id "$OPENCRVS_DEMO_SUBJECT_UIN" \
  --output output/opencrvs-dci/evidence-gateway-live-birth-registration-evidence.json
```

Use `--mode strict` only when every golden case for that profile is expected to
be executable live.

## Local CRVS Relay Live Test

The default lab includes a CRVS-style civil relay and civil notary:

- `civil-registry-relay` serves CSV-backed civil registry data on
  `http://127.0.0.1:4311`.
- `civil-notary` evaluates civil evidence on `http://127.0.0.1:4321`.

Start the local lab, then run both certificate packs:

```bash
just up
just evidence-gateway-crvs-live
```

That command exercises `birth-certificate-evidence/v1` and
`marriage-certificate-evidence/v1` through `civil-notary`, which reads
`civil_status_record`, `certificate`, event, and person rows from
`civil-registry-relay`. The runner writes
`output/evidence-gateway-live-crvs-certificates.json`.

The fixture requests still use `format: minimized_json` as the pack contract
label; the live Registry Notary request is translated to
`application/vnd.registry-notary.claim-result+json`. The certificate object
claims depend on configured source chaining using lookup inputs such as
`sources.birth_record.id`. Jurisdiction-denial cases for the certificate packs
remain explicit live blockers until civil negative gate credentials are added.
