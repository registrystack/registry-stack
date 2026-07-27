---
name: registryctl-local-project-troubleshoot
description: Use when a user has a registryctl-generated local project and doctor, smoke, status, logs, Relay, or Notary checks fail.
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
4. For runtime failures, use `registryctl status`, `registryctl logs`, or
   `registryctl smoke` as appropriate.
5. Fix the smallest project/config issue, rerun the relevant product doctor through registryctl, then rerun smoke only when runtime behavior was affected.

## Redaction Rules

Do not print raw env-file values, API keys, source tokens, Redis URLs, private JWKs, request bodies, source rows, claim values, or SD-JWT disclosures. Summarize redacted stdout/stderr only.

## Output

Lead with the failing check and concrete fix. Include commands run and final
doctor or smoke result. If Docker Compose v2 is unavailable, report the
`not_run` result and supported-provider action. The local doctor runs the
digest-pinned Relay container; it does not require an ambient Relay binary.
