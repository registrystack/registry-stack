# DHIS2 2.41.9 enrollment-status consultation profile

This directory contains a Registry Stack-maintained, unofficial consultation
profile for one bounded journey: read the enrollment status for one exact DHIS2
tracked-entity UID in one fixed program.

The fixed `registry-notary` workload selects the exact tracked-entity UID under
the profile's public-task legal basis. This profile does not claim an
individual subject-binding assertion or individual consent, and its public
contract explicitly declares consent is not required.

The reviewed operation is one Basic-authenticated `GET` to
`/api/tracker/enrollments`. Its query is closed to:

- the canonical consultation input in `trackedEntity`;
- one pack-owned `program` UID;
- `orgUnitMode=ALL`;
- `fields=status`;
- `pageSize=2`, which allows Relay to distinguish no match, one match, and an
  ambiguous result without following pagination.

The response contract is the exact DHIS2 2.41.9 envelope observed by the
redacted interoperability probe: `enrollments`, `page`, `pageSize`, and
`pager`, where `pager` contains `page` and `pageSize`. Only `status` is acquired
from an enrollment and released. Unknown envelope or record members are
rejected.

The fixed program UID is deliberately part of the integration-pack hash. A
country using another DHIS2 program must review and mint a new pack rather than
turning the program into caller-selected runtime configuration. The example
private binding uses a pure root-origin placeholder, an exact
`/stable-2-41-9` application base path, and an environment-backed Basic
credential reference. The compiler concatenates that hash-covered base path
with the pack-owned `/api/tracker/enrollments` path without normalization or
caller input. The destination policy still owns only the HTTPS origin for DNS
and TLS enforcement. The example contains no credential value or live host.

The example omits `dns_family`, which keeps the strict dual-stack default and
requires definitive A and AAAA lookup outcomes. If the reviewed domain-based
DHIS2 deployment is intentionally IPv4-only, set
`"dns_family": "ipv4_only"` on its `data_destination` and repin the
private-binding hashes. That mode performs only A lookups and never falls back
across address families. Do not select it merely to mask a transient DNS
failure.

Compilation and synthetic response fixtures earn only repository conformance
evidence. They do not claim DHIS2 maintainer endorsement, a country deployment,
or a successful Relay end-to-end execution. A root-mounted deployment may omit
`application_base_path`; omission and an explicit `/` compile to the same
canonical root binding.

## Operator journey

Use [`relay-config.example.yaml`](relay-config.example.yaml) as the single
configuration starting point for this profile. It is a complete local-profile
document with exact artifact hashes, not a production identity or live source
binding.

1. Review `integration-pack.json` and `public-contract.json`. If the country
   program, purpose, scope, input, projection, cardinality, or bounds differ,
   mint and review a new version instead of turning those values into runtime
   options.
2. Copy `private-binding.example.json`, replace only the deployment-owned HTTPS
   origin, optional application base path, tenant and registry identities, and
   bounded limits, then update its raw SHA-256 digest in the Relay config. Keep
   the credential reference and generation aligned with `source_credentials`.
3. Replace the example OIDC issuer, JWKS URL, Relay public URL, and Notary client
   identity. Put the runtime PostgreSQL URL, audit secrets, pseudonym material,
   and DHIS2 Basic credential values in the secret store under the environment
   references named by the config. Do not put values in YAML.
4. Run `registry-relay doctor --config <path> --profile local --format json` in
   the same process environment. Resolve every missing reference or artifact
   closure finding before touching the state plane.
5. Have the DBA provision the isolated PostgreSQL identities, then run the
   idempotent `registry-relay consultation bootstrap-state` command documented
   in the [operations runbook](../../docs/ops.md#bootstrap-native-consultation-state).
   Bootstrap with one declared pseudonym key id and an explicit future write
   deadline and audit-retention interval.
6. Start Relay with only its runtime database identity. Readiness must be green
   before Notary calls the protected profile metadata route and then the exact
   `/execute` route using the contract's OIDC scope and
   `Data-Purpose: program-enrollment-verification`.

The public response releases only the closed cardinality outcome and, for one
validated match, the DHIS2 enrollment `status`. Relay never releases the
tracked-entity selector, source URL, Basic credentials, raw DHIS2 envelope, or
backend diagnostic. Back up the PostgreSQL state plane and manage the
pseudonym material under the same retention policy before treating the journey
as production-ready.
