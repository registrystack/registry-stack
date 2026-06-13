---
name: registry-notary-config-review
description: Use when reviewing or troubleshooting Registry Notary YAML, doctor output, claim/source bindings, credential profiles, caller/source auth, replay/status/audit posture, OID4VCI, federation, or OpenFn sidecar configuration.
---

# Registry Notary Config Review

Use this skill to review `registry-notary` configuration before deployment or when doctor, startup, readiness, source lookup, or credential issuance behavior is wrong.

## Review Workflow

1. Identify the configured job and deployment profile. Use "deployment profile" explicitly to avoid confusing it with credential or evaluation profiles.
2. Check caller auth and source auth separation.
3. Check claim ids, source bindings, lookup fields, matching policy, disclosure, supported formats, and credential profile references.
4. Check replay, credential status, audit, signing-key, OID4VCI, federation, self-attestation, and OpenFn sidecar posture for the declared deployment profile.
5. Run product validation when possible:

   ```sh
   registry-notary doctor --config <notary.yaml> --env-file <env-file> --format json
   ```

   Add `--profile <local|hosted_lab|production|evidence_grade>` only for an explicit review override.

6. Treat the product doctor JSON as the validation authority. Do not replace it with manual YAML reasoning. If validation cannot run, say exactly why.

## Review Output

Lead with actionable findings ordered by severity. Include config file and line references when available. Include the doctor result and do not include raw secrets, source rows, claim values, private JWKs, holder proofs, or disclosures.
