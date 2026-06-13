---
name: registry-notary-config-author
description: Use when a user wants Registry Notary YAML for claim evaluation, source bindings, caller/source auth, SD-JWT credential issuance, OID4VCI, federation, OpenFn source sidecars, or standalone Notary deployments.
---

# Registry Notary Config Author

Use this skill to draft or modify `registry-notary` configuration for a user's claim-evaluation or credential-issuance workflow.

## Workflow

1. Identify the job: standalone Notary against an existing API, Notary sourcing from Registry Relay, OID4VCI, federation, self-attestation, or OpenFn sidecar.
2. Establish the deployment profile: `local`, `hosted_lab`, `production`, or `evidence_grade`. Prefer writing it as `deployment.profile` in the final config. Use `--profile` only for temporary review overrides.
3. Model caller auth and source auth separately. Never reuse Notary caller credentials as source credentials.
4. Define claims, source bindings, lookup fields, matching policy, disclosure, and credential profiles only from user-provided semantics.
5. Use env-backed references for API key hashes, source tokens, Redis URLs, audit secrets, and private JWKs. Never place raw secrets in YAML, comments, logs, or final answers.
6. Run product validation when the binary is available:

   ```sh
   registry-notary doctor --config <notary.yaml> --env-file <env-file> --format json
   ```

7. Treat `registry-notary doctor` JSON as the validation authority. If the command is unavailable, report that product validation was not run and fall back to structural review only.

## Redaction Rules

Do not print raw API keys, bearer tokens, source tokens, private JWK material, Redis URLs, audit secrets, holder proofs, SD-JWT disclosures, source rows, claim values, or full environment dumps.

## Output

Return the config changes, the doctor command run, the doctor result, and any residual risk. Lead with blocking findings before optional hardening suggestions.
