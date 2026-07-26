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

Relay and Notary use separate product bundles. Build, sign, verify, and track
anti-rollback state for each product bundle independently. At boot, each
runtime verifies and activates only its own bundle. Current source does not
produce or verify a signed project-root bundle, and no Registry Stack
coordinator atomically activates both products.

Use compatible staged activation for a combined topology:

1. Verify the Relay bundle and the Notary bundle independently, including each
   signature, product identity, sequence, and anti-rollback state.
2. Start or stage Relay without admitting caller traffic. Require its health,
   readiness, audit, and deployment-posture checks to pass.
3. Start or stage Notary against that Relay. Require Notary startup and
   readiness to validate its complete expected Relay consultation contract,
   then require Notary health, audit, and deployment-posture checks to pass.
4. Admit caller traffic only after both products are ready and the Notary-to-
   Relay contract check succeeds.

This is not atomic project activation. The deployment platform controls traffic
admission around two product-owned boot boundaries. During execute, Notary
sends the exact `contract_hash`; an execute-time contract mismatch is rejected
by Relay before source access.

A future project-root packaging or coordination mechanism remains deferred
under [registry-stack issue #361](https://github.com/registrystack/registry-stack/issues/361).
Do not claim root-signature verification or a project activation coordinator
that current runtimes cannot prove.

## Review checklist

- Review the generated semantic delta and effective authority.
- Verify Relay and Notary expect the same contract and platform requirements.
- Keep service policy and source authority in their owning products.
- Verify secret references without reading or printing their values.
- Keep caller traffic blocked while Relay and Notary are staged separately.
- Admit traffic only after both products report ready and Notary validates its
  Relay contract.
- Preserve separate Relay and Notary audit keys and chains.
