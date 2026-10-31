# Adapter live-source handover closure

Date: 2026-10-31

This record closes the inherited cleanup checklist for the current read and
synchronous-write checkpoint. It does not accept the full delivery program.
The [integration review](increment-1.md), [staff review](increment-1-staff.md)
and [current-checkpoint audit](final.md) distinguish completed work from later
increments and external acceptance still blocked on a supplied client.

| Handover item | Current evidence and disposition |
|---|---|
| Platform resilience review and component findings | Reviewed cancellation, failure propagation, resource bounds and conformance corrections are integrated; the complete owning gates pass. Platform permits release abandoned half-open trials; Adapter throttle slots release on cancellation. |
| Cedar versus closed YAML after the first real write | The [authorization spike](authorization-spike.md) compares actual Cedar with a closed YAML candidate over organisation-unit hierarchy and source-owned ownership. Its synthetic proof does not install runtime authorization. |
| Definition of done and port-table status | [Delivery plan](../DELIVERY-PLAN.md) accepts Increments 0 and 1 only; the gate reports 35 of 37 rows delivered with evidence and keeps the two later rows pending. |
| D36 private-network plaintext consent | [CONCEPT.md](../CONCEPT.md), decision D36, records explicitly declared private CIDRs as operator consent for each authentication kind; authoring and serving checks agree. |
| Historical D26 and experiment narratives | The earlier commit body's pending-decision annotation is superseded by the accepted D26 decision in CONCEPT.md. Current source validates the parsed GraphQL operation kind. The experiment reviews describe actual native execution separately from earlier authoring-only proof. History is preserved rather than rewritten. |
| Private CIDR name and bound | `registry-adapter-core/src/naming.rs` and the platform destination policy both bound the allowlist to 16 entries. |
| DHIS2 C0 to C9 fixture refresh | The maintained pack and fixtures cover the reviewed version, no-program repeat case, pagination signals, import/WebMessage shapes, updatedAt revision, mapped attributes and UID-based entity types. Current provenance remains 7 captured and 4 documented DHIS2 fixtures. |
| Coordinator and egress comparison | [Component candidates](../COMPONENT-CANDIDATES.md) compares Coordinator calls to the public Adapter facade, independent authentication and egress, and durable waits. A Coordinator Adapter step remains advice, not implemented scope. |
| Real transport in CLI live verification | `registry-adapterctl/tests/verify.rs` uses an actual rustls TCP server to prove trusted certificates, anonymous HTTPS without authorization headers, untrusted-certificate refusal and redirect refusal. The owning gate includes nine CLI TLS cases. |
| Platform-backed assertion signer | `registry-adapter/src/auth/assertion.rs` signs and verifies each admitted key type and tests audience, lifetime, redaction and key-pair mismatch. |
| Header relay in both directions | `camel_header_filter.rs` proves request allowlisting, response copying, and refusal of reserved and API-key names in both configured lists. |
| Empty client allowlist | Runtime configuration tests refuse both omitted `allowedClients` and an explicit empty list. |
| PostgreSQL temporary-server probe race | Both probes in `test-postgres.sh` use TCP at 127.0.0.1. The exact pinned image starts its temporary server with an empty `listen_addresses`, so that server cannot satisfy either TCP probe. The wrapper regression passes and requires both probes before Cargo. |
| One reviewable PR and source privacy | One local branch and a prepared PR handoff cover the related work. The latest matching MCP read proof is retained with immutable artifacts. Source-host and credential scans found no matching values in changed tracked blobs. No producer push, merge, tag, release or production deployment is claimed. |

The same immutable executable has recorded DHIS2 read and synchronous write
journeys, public HAPI synthetic-record proof, and the matching six-case MCP
read composition. Real OpenCRVS read acceptance remains blocked: the required
new client is unavailable, and the old invalid client is not retried. Its
documented fixtures establish offline behavior only. OpenCRVS writes,
multi-step write resume, asynchronous 202 modes, DCI and later authoring work
remain outside this bounded handover and retain their delivery gates.
