# Configuration trust and integrity

Registry-backed evidence relies on two related checks: semantic contract
agreement between Relay and Notary, and deployment integrity for the files an
operator activates.

## Semantic consultation agreement

The project compiler produces one public Relay consultation contract and one
public `contract_hash`. The contract covers purpose, inputs, outcomes, outputs,
provenance, runtime requirements, and applicable limits. Notary independently
validates the complete expected contract during startup and readiness, then
includes the exact hash on every execute request. Relay rejects a mismatch
before source access.

The hash is not a substitute for semantic validation. It is a content identity
for the compiler-produced contract, not an author-maintained version or a
product-specific adapter digest.

## Runtime credentials

Notary holds only its Relay workload credential. Keep the token in an
owner-readable file and rotate it by atomically replacing that file. Registry
destinations, source credentials, private CA material, mTLS keys, and protocol
credentials belong to Relay's private environment binding.

Never place secret values in authored project files, generated review reports,
diagnostics, logs, audit records, fixture traces, or deployment manifests.

## Deployment activation

A production deployment verifies its generated product configuration through
the repository's signed bundle boot boundary and anti-rollback state. A
combined generation must activate compatible Relay and Notary inputs
atomically. Blue-green switching may stage a complete replacement generation;
smaller deployments may drain, restart both products, verify readiness, and
resume. A mixed contract generation remains unavailable.

The broader project-root signing workflow is intentionally not documented as
an already shipped operator journey here. Until that project-authoring work is
delivered, use the existing product bundle verification controls and do not
claim coordinated root-signature verification that the runtime cannot prove.

## Review checklist

- Review the generated semantic delta and effective authority.
- Verify Relay and Notary expect the same contract and platform requirements.
- Keep service policy and source authority in their owning products.
- Verify secret references without reading or printing their values.
- Activate one complete generation and require both products to report ready.
- Preserve separate Relay and Notary audit keys and chains.
