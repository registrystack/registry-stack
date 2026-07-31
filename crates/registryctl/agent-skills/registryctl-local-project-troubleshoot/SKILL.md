---
name: registryctl-local-project-troubleshoot
description: Use when a user has a registryctl-generated local project and doctor, dev smoke, dev status, dev logs, Relay, or Notary checks fail.
---

# registryctl Local Project Troubleshoot

Use this skill to troubleshoot generated local Registry projects without duplicating product validation rules.

## Workflow

1. Inspect `registry-stack.yaml` and the selected environment file to identify
   the authored services, source binding, and ownership boundary. Do not edit
   generated files under `.registry-stack/`.
2. Run:

   ```sh
   registryctl doctor --profile local --format json
   ```

   The clone-free local runtime supports Docker Compose v2. Do not substitute
   another provider name or widen the listener.

3. Parse the merged report. Attribute product failures back to the product that emitted them.
4. For runtime failures, use `registryctl dev status`, `registryctl dev logs`,
   or `registryctl dev smoke` as appropriate.
5. Fix the smallest project/config issue, rerun the relevant product doctor through registryctl, then rerun smoke only when runtime behavior was affected.

## Redaction Rules

Do not print raw env-file values, API keys, source tokens, Redis URLs, private JWKs, request bodies, source rows, claim values, or SD-JWT disclosures. Summarize redacted stdout/stderr only.

## Output

Lead with the failing check and concrete fix. Include commands run and final
doctor or smoke result. If Docker Compose 2.35.0 or later is unavailable,
report the failed readiness category and supported-provider action. Doctor
inspects exact local digest-locked image availability without pulling images.
