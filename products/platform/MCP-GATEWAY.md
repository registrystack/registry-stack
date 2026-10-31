# Configurable MCP supporting service

Status: source-build-only foundation increment. `breg-mcp` remains the maintained citizen deployment path. The configurable `registry-mcp` binary is not part of numbered release assets, installers, `rstack` or container packaging.

## Ownership and shape

Registry Stack's integration maintainers own the `registry-mcp` composition service. Platform maintainers own `registry-mcp-edge`, the product-neutral transport, authentication, configuration and audit primitive. Each product owns its downstream authorization, data disclosure and effects. A provider translates those contracts; it does not replace them.

The shared edge avoids repeating the protected MCP transport and audit envelope in separate servers. The existing BReg executable remains a compatibility wrapper over the same BReg provider. Keeping that wrapper preserves its operator configuration and audit identity while allowing the configurable service to bind other products explicitly.

The service uses reviewed provider bindings, a fixed public tool ceiling and maintained product clients. It has no dynamic code loading, connector-authoring API, generic URL/SQL tool, assignment engine or workflow engine. External API adaptation stays in Live Adapter; durable orchestration stays in Coordinator.

## Protocol and tested surface

The lockfile resolves `rmcp` 3.7.0. The edge advertises MCP `2026-07-28` through the SDK's initialization result. It serves Streamable HTTP with tools/list, tools/call and protected-resource metadata. It does not advertise resources, prompts, sampling or model-host administration.

The executable compatibility proof uses the maintained Rust MCP client and real routers. This is not a compatibility certification for every chat host or every protocol revision the SDK can recognize. A dependency update that moves the default protocol needs an explicit wire-contract review and test update.

## Citizen and staff authority

Use separate configurations, resources, admitted clients, scopes and credentials for BReg citizen and Casework staff access. The configuration checker refuses mixing those two provider kinds in one resource. Each binding acquires its own downstream authorization; an inbound bearer is never forwarded as a provider credential.

The BReg citizen provider keeps its seven tools, caller-derived targets, own drafts, revisions, stable mutation attempts and browser review handoff. Only the separately authorized human review path submits a draft.

Casework offers assigned-task listing and task-context reads through dedicated delegated-reader routes. Its reader policy explicitly admits the gateway and represented staff population. Casework checks current assignment and source disclosure; ordinary producer, decision and administration routes remain separate. The assistant receives task context and its policy binding, excluding the internal policy closure for routing, clocks and retention.

Current-source context uses a second, source-specific authorization. An institution may explicitly grant BReg `get-review-context` to a trusted delegated agent profile, including for a submitted Proposal. This service grant is not a task grant and does not automatically intersect with the represented person's human BReg profile. BReg applies the fields, rows, scopes, purposes and clients authored in the agent profile. An omitted or unrestricted constraint does not become a personal permission check.

Keep that profile disabled until the institution has approved its reviewer population and disclosure ceiling. Configure only the required context fields and record targets. Use different reader/source profiles where reviewer groups have different ceilings, and keep each ceiling no broader than the intended population. Casework assignment checks do not replace the BReg disclosure ceiling.

Submitted task context and current-source context are distinct modes. The former returns retained task material; the latter needs an explicit admitted source profile. A missing current-source profile is a refusal with a configuration remedy, not a probe-and-retry workflow. The `authority: delegated-staff-read` selector declares this supported backend contract; it does not activate a reader or grant authority at Casework.

## Experimental external reads

The Adapter binding is experimental and requires a compatible producer with an executable effective-contract export. The committed producer-generated golden contract checks digest and schema compatibility without inventing a producer on main. The native drill additionally requires a matching Adapter binary, its tracked fixture snapshot and an owned PostgreSQL database.

Only configured, served GET and explicitly read-only POST operations can execute. The service pins the complete contract, compiles the selected operations' schemas and validates returned data. Tool names and descriptions are reviewed configuration. Catalog discovery checks authenticated readiness; invocation relies on the exact contract-pin header and the producer's journal-before-source admission.

`dataClass: non-personal` is an unchecked operator attestation. It is not a classifier, a personal-data grant or a substitute for source authorization. The golden journeys use facility data. Person-level access, represented-subject authority and external effects remain outside this binding's supported scope.

The source-built prototype accepts an operator-supplied machine token reference. Token expiry and rotation must be handled explicitly; it is not a managed credential-renewal service. Do not lengthen token lifetime to turn a synthetic proof into a production deployment. A maintained short-lived client-credentials path and institution issuer acceptance are separate readiness work.

## Verification and migration

Provider and edge tests own filtering, exact schemas, per-call credentials, audit release and refusal behavior. Native citizen, staff and Adapter journeys use real runtimes and PostgreSQL with synthetic identity/source fixtures. The `ci:full` PR label selects the native staff PostgreSQL lane; an ordinary package run leaves native tests ignored and is not equivalent proof.

Use the [runtime examples](examples/mcp-runtime/README.md) and the [service README](../../crates/registry-mcp/README.md). BReg-only operators should keep `breg-mcp` until there is a specific reason to adopt the source-built composition service. Moving configurations changes their envelope and generic audit namespace; preserve the audit key and provider/service identities needed for retry correlation.

Publication, supported institution issuers, broader product providers, external personal delegation and external writes remain separate delivery decisions.
