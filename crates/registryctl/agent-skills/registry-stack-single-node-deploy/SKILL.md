---
name: registry-stack-single-node-deploy
description: Use when a user wants a self-hosted single-node Registry Relay, Registry Notary, or Relay plus Notary deployment using registryctl-generated project layout or equivalent local Compose wiring.
---

# Registry Stack Single-Node Deploy

Use this skill to help a user create, validate, and troubleshoot a single-node Registry stack.

## Workflow

1. Identify the mode: Relay only, Notary only, or Relay plus Notary.
2. Establish the deployment profile: `local`, `hosted_lab`, `production`, or `evidence_grade`. Prefer product configs declaring `deployment.profile`; use `registryctl doctor --profile` only as a temporary review override.
3. Generate or edit the smallest necessary project files.
4. Run product-owned validation through registryctl:

   ```sh
   registryctl doctor --format json
   ```

   For an explicit override:

   ```sh
   registryctl doctor --profile local --format json
   ```

5. Treat the merged JSON report as orchestration evidence only. Relay findings belong to `registry-relay`; Notary findings belong to `registry-notary`.
6. Start containers and run smoke checks only when the user asks for a runnable deployment or provides controlled test targets.

## Redaction Rules

Never print raw env-file values, API keys, bearer tokens, source tokens, Redis URLs, private JWKs, SD-JWT disclosures, source rows, claim values, or full environment dumps.

## Output

Report the commands run, whether product doctor checks passed, whether smoke checks ran, and any residual risk. Do not claim validation passed unless product doctor JSON says it passed.
