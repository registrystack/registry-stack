# Run the FHIR health evidence demo

Page type: tutorial
Product: Registry Lab, Registry Notary, FHIR source adapter
Layer: evaluation
Audience: integrators testing Registry Notary with FHIR-shaped health data

Use this tutorial to run the deterministic FHIR demo in Registry Lab and verify
the health-navigation claim set. The demo uses a local FHIR R4 fixture server,
a private source-adapter sidecar, and a Registry Notary instance. It does not
call a public clinical test server, and it does not claim FHIR server
conformance.

The demo starts three local services:

- `fhir-fixture-server`: deterministic FHIR R4 fixture API on
  `http://127.0.0.1:4361`.
- `fhir-source-adapter-sidecar`: private source adapter on
  `http://127.0.0.1:4360`.
- `fhir-health-notary`: Registry Notary on `http://127.0.0.1:4362`.

Registry Notary evaluates claims by calling the source adapter. The source
adapter fetches and relates FHIR resources, then returns projected source fields
to Notary. In this demo, "evidence" means a Registry Notary claim result. It is
not the FHIR `Evidence` resource.

## Before you start

Run from the Registry Lab directory:

```bash
cd /path/to/registry-lab
```

You need:

- Docker running.
- Demo secrets generated in `.env`.
- A compatible `registry-notary` source checkout if you build from sibling
  repositories.

Generate local demo secrets if you have not already:

```bash
just generate
```

Build the FHIR profile images:

```bash
just fhir-build
```

If your sibling source checkouts are on different branches, set the source
directories before building:

```bash
REGISTRY_NOTARY_SOURCE_DIR=../registry-notary \
REGISTRY_PLATFORM_SOURCE_DIR=../registry-platform \
CROSSWALK_SOURCE_DIR=../crosswalk \
just fhir-build
```

## Run the demo

Start the FHIR services:

```bash
just fhir-up
```

Run the smoke:

```bash
just fhir-smoke
```

Expected ending:

```text
FHIR smoke passed; artifacts written to output/fhir-smoke
```

Stop the FHIR services when you are done:

```bash
just fhir-down
```

## What the smoke verifies

The smoke waits for the fixture server, source adapter, and Notary discovery
route, then evaluates three groups:

1. Person health-navigation claims for target `person-123`, requested by
   guardian `guardian-1`.
2. Provider affiliation for target `provider-123`.
3. Facility service availability for target `facility-1`.

The person group evaluates these claims:

```text
patient-record-exists
age-over-18
not-recorded-deceased
coverage-active
coverage-eligibility-confirmed
enrolled-in-program
encounter-completed
referral-active
appointment-booked
lab-result-available
vaccination-recorded
prior-authorization-approved
source-trace-available
requester-guardian-confirmed
```

The provider and facility groups evaluate:

```text
provider-affiliated-with-facility
facility-offers-service
```

Every claim must return `satisfied: true`. The smoke accepts both the current
`results` response shape and the older `claim_results` response shape while the
client compatibility layer is kept.

## Inspect the outputs

The smoke writes JSON artifacts under:

```text
output/fhir-smoke/
```

Useful files:

- `person-workflow-evaluation.json`: person intake, coverage, eligibility,
  referral, appointment, care, lab, immunization, authorization, trace, and
  guardian relationship claim results.
- `provider-affiliation-evaluation.json`: provider-to-facility affiliation
  claim result.
- `facility-service-evaluation.json`: facility service-offering claim result.

Use `jq` to inspect the claims:

```bash
jq '.results // .claim_results' output/fhir-smoke/person-workflow-evaluation.json
```

## Try one evaluation manually

Load the generated local credentials:

```bash
set -a
. .env
set +a
```

Evaluate the person workflow claims:

```bash
curl -fsS -X POST http://127.0.0.1:4362/v1/evaluations \
  -H "Authorization: Bearer ${FHIR_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/fhir-health-navigation" \
  -d '{
    "requester": { "type": "Person", "id": "guardian-1" },
    "target": { "type": "Person", "id": "person-123" },
    "relationship": { "type": "guardian" },
    "claims": [
      "patient-record-exists",
      "age-over-18",
      "not-recorded-deceased",
      "coverage-active",
      "coverage-eligibility-confirmed",
      "enrolled-in-program",
      "encounter-completed",
      "referral-active",
      "appointment-booked",
      "lab-result-available",
      "vaccination-recorded",
      "prior-authorization-approved",
      "source-trace-available",
      "requester-guardian-confirmed"
    ],
    "purpose": "https://demo.example.gov/purpose/fhir-health-navigation"
  }' | jq '.results // .claim_results'
```

## How the FHIR adapter maps data

The source adapter configuration is
`config/fhir/fhir-source-adapter-sidecar.yaml.template`.
It defines one source per projected FHIR evidence view. Each source has:

- An anchor resource, usually `Patient`, found by search parameters.
- Related resources, such as `Coverage`, `CoverageEligibilityResponse`,
  `EpisodeOfCare`, `Encounter`, `ServiceRequest`, `Appointment`,
  `DiagnosticReport`, `Immunization`, `ClaimResponse`, `RelatedPerson`,
  `PractitionerRole`, or `HealthcareService`.
- JSON Pointer projections that produce the source fields Notary rules read.

The Notary claim configuration is `config/notary/fhir-health-notary.yaml`.
It binds the projected fields to claim rules. Most demo claims are predicates:
they prove a condition such as "coverage is active" or "a referral is active"
without returning the full FHIR resource.

## Boundaries

- The FHIR fixture server is deterministic demo data, not a production FHIR
  server.
- The demo uses read-only FHIR search and projection. It does not write FHIR
  resources.
- The demo evaluates claim results only. It does not issue a FHIR-specific
  verifiable credential profile.
- The demo uses private-network HTTP inside Compose. Hosted deployment uses the
  governed sidecar bootstrap in `compose.fhir-hosted.yaml`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `missing FHIR_EVIDENCE_CLIENT_BEARER` | Run `just generate`, then rerun `just fhir-smoke`. |
| `fhir-source-adapter-sidecar` is not ready | Run `docker compose -f compose.yaml --profile fhir logs fhir-source-adapter-sidecar`. Check source checkout compatibility if the image was rebuilt. |
| Notary discovery returns `401` | Confirm the `Authorization: Bearer ${FHIR_EVIDENCE_CLIENT_BEARER}` header is present. |
| A claim is unsatisfied | Inspect `output/fhir-smoke/*.json`, then compare the claim id with `config/notary/fhir-health-notary.yaml`. |

## Next

- [Registry Lab documentation map](README.md)
- [DHIS2 OpenFn Notary tutorial](dhis2-openfn-notary-tutorial.md)
- [OpenFn sidecar Notary tutorial](openfn-sidecar-notary-tutorial.md)
