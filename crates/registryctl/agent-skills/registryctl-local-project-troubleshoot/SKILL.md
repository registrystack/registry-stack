---
name: registryctl-local-project-troubleshoot
description: Use when a user has a registryctl-generated local project and doctor, smoke, status, logs, Relay, or Notary checks fail.
---

# registryctl Local Project Troubleshoot

Use this skill to troubleshoot generated local Registry projects without duplicating product validation rules.

## Workflow

1. Inspect `registryctl.yaml` to identify Relay, Notary, env file, output directory, and generated layout.
2. Run:

   ```sh
   registryctl doctor --format json
   ```

   Add `--profile <local|hosted_lab|production|evidence_grade>` only when the user asks for an explicit review override.

3. Parse the merged report. Attribute product failures back to the product that emitted them.
4. For runtime failures, use `registryctl status`, `registryctl logs`, `registryctl smoke`, or `registryctl notary smoke` as appropriate.
5. Fix the smallest project/config issue, rerun the relevant product doctor through registryctl, then rerun smoke only when runtime behavior was affected.

## Redaction Rules

Do not print raw env-file values, API keys, source tokens, Redis URLs, private JWKs, request bodies, source rows, claim values, or SD-JWT disclosures. Summarize redacted stdout/stderr only.

## Output

Lead with the failing check and concrete fix. Include commands run and final doctor/smoke result. If a product binary is missing, report the `not_run` result and installation/PATH action.
