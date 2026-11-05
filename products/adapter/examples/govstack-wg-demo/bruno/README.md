# Registry WG demo collection

This Bruno collection runs one authorized demo journey against three loopback
services:

- the synthetic demo issuer at `127.0.0.1:18109`;
- the live DHIS2-backed, read-only Consultation facade at `127.0.0.1:18110`;
- the local BReg-backed Consultation and Write facade at `127.0.0.1:18111`.

The first request obtains a short-lived bearer token and creates a unique run
identifier. The DHIS2 folder then selects a live record and organisation unit
from its first List response. The BReg folder creates a run-specific contact,
proves exact replay, reads its strong validator, removes `note` with JSON Merge
Patch, proves update replay, and demonstrates a stale `If-Match` refusal.

## Run

Start the three demo services, open this `bruno` directory as a collection,
select the `LocalExample` environment, and run the whole collection in sequence.
With Bruno CLI installed, the equivalent command from this directory is:

```sh
bru run --env LocalExample
```

`dhis2_record_id` and `dhis2_org_unit` default to `auto`. For a controlled live
dataset, override either value in a private environment or with repeated CLI
`--env-var` options. The committed environment contains only loopback origins
and synthetic selectors. It contains no bearer token or source credential.

Request payloads and assertions follow the generated contracts:

- [DHIS2 Consultation OpenAPI](../../dhis2-consultation/generated/openapi.json)
- [BReg Consultation and Write OpenAPI](../../breg-govstack/generated/openapi.json)

The running demo also serves those deployment-specific contracts over its
self-signed TLS endpoint:

- `https://127.0.0.1:19443/contracts/dhis2/1.0.0/openapi.json`
- `https://127.0.0.1:19443/contracts/breg/1.0.0/openapi.json`

DHIS2 requests are read-only. The collection does not claim or attempt DHIS2
Write support.
