# Secret Provider Readiness Contract

Registry products own their concrete secret-provider configuration, but shared
platform surfaces use one vocabulary for provider kind, key status, key
readiness, readiness-gated apply, and posture-safe reporting.

## Provider Kind

Use `KeyProviderKind` labels when reporting signing-key providers:

- `local_jwk_env` for local JWK material loaded from an environment variable.
- `file_watch` for local mounted files or watched secret files.
- `pkcs11` for HSM or smart-card providers reached through PKCS#11.
- `local_pkcs12_file` for local PKCS#12 files.
- `kms` for cloud or service KMS providers.
- `workload_identity` for workload identity, federation, or ambient identity
  providers that mint or authorize signing operations without local key export.

Product config should reject unknown provider labels for live apply. Add a new
shared label before accepting a new provider kind in public posture or apply
reports.

## Status And Readiness

Use `KeyStatus` for configured lifecycle state:

- `active` may sign and may publish public key material.
- `publish_only` may publish public key material but must not sign.
- `disabled` must not sign or publish as an active key.

Use `KeyReadiness` for current backend state:

- `ready` means the key may participate in live apply if its status also allows
  signing.
- `degraded` means the provider is reachable enough to report but should fail
  closed for live apply.
- `not_ready` means the provider is known unavailable or misconfigured.
- `unknown` means readiness could not be established and must fail closed.

`KeyReadinessSnapshot::allows_live_apply()` is the shared gate: only
`status = active` and `readiness = ready` allows live apply. All other status or
readiness combinations reject before anti-rollback state changes.

## Redaction Boundary

Posture and signed bundles may include shared labels, public key identifiers,
public JWKs, public certificate chains, and readiness labels. They must not
include local secret material or provider-specific identifiers that expose
deployment topology.

Do not copy these fields into posture or bundles:

- environment variable names that point at secrets;
- local filesystem paths;
- PKCS#11 slots, token labels, PIN sources, or object labels;
- cloud KMS resource names, key ring paths, or account/project identifiers;
- workload identity trust domains, audience values, subject selectors, or token
  exchange diagnostics;
- raw provider error strings if they can contain any of the above.

Products may log provider diagnostics on private operator channels after their
own redaction policy runs. Public posture should report only shared provider
kind, status, readiness, and product-owned public key references.
