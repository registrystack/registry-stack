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

The reviewed source operation has one 10-second total deadline covering DNS,
connect, request, and response handling. The previous 5-second bound failed
closed against the authorized integration instance. The operation remains at
Relay's hard source ceiling and still performs exactly one exchange with no
retry.

Notary wraps the complete internal service hop in one fixed, non-configurable
25-second absolute deadline. Semaphore wait, workload-token reload, Relay
request and response, strict decoding, and final result acceptance all consume
that same budget. The Relay source operation's 10 seconds is nested inside it.
There is no operator timeout knob and no retry, redirect, proxy, or result
cache. Consultation-enabled Relay requires `server.request_timeout` greater
than 25 seconds. Registry-backed Notary requires at least 30 seconds, retaining
a five-second listener reserve around its service hop. The unchanged 30-second
default used by these examples satisfies both bounds.

## Operator journey

Use [`relay-config.example.yaml`](relay-config.example.yaml) for Relay and
[`notary-config.example.yaml`](notary-config.example.yaml) for its minimized
Notary handoff. They are complete local-profile starting points, not production
identities or live source bindings.

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
   before activating Notary. Keep Relay's outer `server.request_timeout` above
   25 seconds and Notary's at least 30 seconds; the examples retain the
   30-second default.
7. Copy the Notary example. Replace the Relay HTTPS origin and add only the
   exact reviewed private CIDRs needed to reach an internal Relay. Notary has
   no DHIS2 URL or credential because Relay alone owns source access.
8. Mount the Relay workload JWT at `evidence.relay.token_file`. Rotate that file
   atomically; Notary reloads it for every Relay operation, while Relay alone
   verifies its signature, workload binding, time bounds, and required scope
   on every protected request. Make the mounted regular file readable only by
   the Notary service account, for example mode `0600`. Keep the Notary API-key
   fingerprint and audit hash secret in the secret store named by the config,
   never in YAML.
9. Run `registry-notary explain-config --config <path> --format json`, then
   `registry-notary doctor --config <path>`. Offline output reports only the
   credential file's availability. In a controlled integration environment,
   add `--live` to have Relay authenticate the current credential and verify
   the exact hash-pinned profile before starting the listener.
10. Start Notary. Startup fails closed unless the Relay credential and profile
    verify. One `/v1/evaluations` request may ask for both
    `dhis2-enrollment-known` and `dhis2-enrollment-status`; Notary coalesces
    them into one Relay consultation and returns minimized claim-result
    documents containing the boolean and status plus standard result metadata.

The complete Notary request for that journey is:

```http
POST /v1/evaluations
X-API-Key: <notary-api-key>
Data-Purpose: program-enrollment-verification
Content-Type: application/json

{
  "target": {"type": "person", "id": "<tracked-entity-uid>"},
  "claims": [
    {"id": "dhis2-enrollment-known", "version": "1"},
    {"id": "dhis2-enrollment-status", "version": "1"}
  ],
  "disclosure": "value",
  "purpose": "program-enrollment-verification"
}
```

Notary's Relay readiness check has a separate 5-second outer bound and performs
only authenticated profile metadata verification. It never executes a
consultation or calls DHIS2.

The local example explicitly uses Notary's single-process `in_memory` state, so
`/ready` reports HTTP 200 after the Relay profile is verified. Its
`checks.relay` block reports one successful check and no failure. Configure the
typed Notary-owned PostgreSQL state plane for every production or multi-instance
deployment.

The public response releases only the closed cardinality outcome and, for one
validated match, the DHIS2 enrollment `status`. Relay never releases the
tracked-entity selector, source URL, Basic credentials, raw DHIS2 envelope, or
backend diagnostic. Notary returns its evaluation id as public traceability
metadata. The Relay consultation id remains restricted to audit records for
cross-service investigation and never enters public claim provenance. Back up
the PostgreSQL state plane and manage the pseudonym material under the same
retention policy before treating the journey as production-ready.
