# Add Notary to your first Registry Relay API

Use this tutorial to add Registry Notary to the local spreadsheet API project
created by the Registry Relay tutorial. You will start Relay and Notary
together, prove anonymous claim access is denied, and evaluate one claim backed
by the Relay API.

The tutorial uses synthetic data and local demo credentials. Do not use the
generated local keys in production.

This tutorial uses a co-located local learning path: one folder, one Compose
file, and one local secrets file.

## Before you start

Complete the Relay spreadsheet API tutorial first:

```sh
registryctl init relay my-first-api --sample benefits
cd my-first-api
registryctl start
registryctl smoke
```

The Relay smoke test should pass before you add Notary.

## Add Registry Notary

From the Relay project directory, add Notary:

```sh
registryctl add notary --from local-relay
```

The command updates the local project:

```text
my-first-api/
  registryctl.yaml
  compose.yaml
  README.md
  relay/
    config.yaml
    metadata.yaml
  notary/
    config.yaml
  data/
    benefits_casework.xlsx
  bruno/
    registry-api/
  secrets/
    local.env
  output/
```

`registryctl` keeps Relay and Notary credentials in `secrets/local.env`. The
Relay and Notary runtime configs contain only fingerprint references,
commitments, and environment variable names.

The generated Compose file also starts a local Redis replay store for Notary
readiness. It is part of the local demo runtime and does not require manual
configuration.

Notary reads from Relay through the Compose network:

```text
http://registry-relay:8080
```

Local browser and curl examples use the host URL:

```text
http://127.0.0.1:4255
```

## Start Relay And Notary

Start the project again:

```sh
registryctl start
```

The command starts both services and waits for both health and readiness checks:

```text
Relay API:   http://127.0.0.1:4242
Notary API:  http://127.0.0.1:4255
```

Check the project status:

```sh
registryctl status
```

The Relay and Notary services should both report healthy and ready.

## Run The Notary Smoke Test

Run the Notary smoke checks:

```sh
registryctl notary smoke
```

The smoke test should pass:

```text
PASS notary healthz is public
PASS notary ready is public
PASS anonymous claims request is denied
PASS notary evaluator can list claims
PASS notary evaluator can verify benefits person exists
```

`registryctl` writes detailed results to:

```text
output/notary-smoke-results.json
```

The smoke result should not contain raw API keys, the Relay source token, local
env values, Relay source rows, or sensitive sample column values.

## Load Local Demo Keys

Load the generated local keys into your shell:

```sh
set -a
. secrets/local.env
set +a
```

The Notary tutorial adds these local values:

| Value | Environment variable | What it is for |
| --- | --- | --- |
| Notary evaluator key | `REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW` | Lets you call Notary evaluation routes |
| Notary evaluator fingerprint | `REGISTRY_NOTARY_TUTORIAL_EVALUATOR_HASH` | Lets Notary verify the local evaluator key |
| Notary audit hash secret | `REGISTRY_NOTARY_AUDIT_HASH_SECRET` | Lets Notary hash audit subjects without logging raw values |
| Relay source token for Notary | `EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN` | Lets Notary read the Relay source API |
| Notary demo issuer JWK | `REGISTRY_NOTARY_ISSUER_JWK` | Local demo signing key used only to make Notary readiness pass |
| Notary replay Redis URL | `REGISTRY_NOTARY_REPLAY_REDIS_URL` | Points Notary at the local demo Redis replay store |

The Notary evaluator key is for you calling Notary. The Relay source token is
for Notary calling Relay. They are intentionally separate.

## Prove Anonymous Claim Access Is Denied

Call the claim list without a credential:

```sh
curl -i http://127.0.0.1:4255/v1/claims
```

Notary should return `401 Unauthorized`.

Call the same route with the Notary evaluator key:

```sh
curl -sS \
  -H "x-api-key: $REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW" \
  http://127.0.0.1:4255/v1/claims
```

The response should include the starter claim:

```text
benefits-person-exists
```

## Evaluate A Claim From Relay Data

Evaluate whether the synthetic person `per-2001` exists in the Relay-backed
benefits dataset:

```sh
curl -sS -X POST \
  -H "x-api-key: $REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW" \
  -H "Content-Type: application/json" \
  -H "Accept: application/vnd.registry-notary.claim-result+json" \
  -d '{
    "target": {
      "type": "person",
      "id": "per-2001"
    },
    "claims": ["benefits-person-exists"],
    "disclosure": "predicate",
    "purpose": "https://example.local/purpose/tutorial"
  }' \
  http://127.0.0.1:4255/v1/evaluations
```

Notary should return a successful claim result for `benefits-person-exists`.
The response should show the claim outcome, not the Relay source row.

What happened:

- You called Notary with the Notary evaluator key.
- Notary checked that the key can evaluate the configured claim.
- Notary used its internal Relay source token to query Relay.
- Relay enforced its row-read scope and purpose-header rules.
- Notary returned the configured claim result without exposing the spreadsheet
  row.

## Compare Relay And Notary

Relay still exposes the source-facing consultation API:

```sh
curl -sS -G \
  -H "Authorization: Bearer $ROW_READER_RAW" \
  -H "Data-Purpose: https://example.local/purpose/tutorial" \
  --data-urlencode "id=per-2001" \
  http://127.0.0.1:4242/v1/datasets/benefits_casework/entities/person/records
```

Notary exposes a claim API:

```sh
curl -sS -X POST \
  -H "x-api-key: $REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW" \
  -H "Content-Type: application/json" \
  -H "Accept: application/vnd.registry-notary.claim-result+json" \
  -d '{
    "target": { "type": "person", "id": "per-2001" },
    "claims": ["benefits-person-exists"],
    "disclosure": "predicate",
    "purpose": "https://example.local/purpose/tutorial"
  }' \
  http://127.0.0.1:4255/v1/evaluations
```

Use Relay when a caller is allowed to consult configured records. Use Notary
when a caller should receive a narrow claim result.

## Optional: open the Bruno collection

`registryctl add notary --from local-relay` refreshes the generated Bruno
collection with Notary requests. Bruno is optional. The tutorial and API work
without it.

Open the generated collection:

```sh
registryctl bruno open
```

If Bruno is installed, the collection opens with Relay and Notary folders. If
Bruno is not installed, the command prints the collection path and an install
link.

If the Bruno CLI is installed, you can run the collection:

```sh
registryctl bruno run
```

If `bru` is not installed, the command prints a fallback and exits without
blocking Relay or Notary.

## Open The Notary API Reference

Open the Notary API surface:

```sh
registryctl notary open
```

The command prints the local OpenAPI URL and an authenticated curl example:

```text
Notary OpenAPI: http://127.0.0.1:4255/openapi.json
Use the generated local evaluator key:
curl -H "x-api-key: $REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW" http://127.0.0.1:4255/openapi.json
```

## Stop The Local Project

When you are done:

```sh
registryctl stop
```

This stops both local services. It does not delete your workbook, generated
configs, local keys, or smoke results.

## Troubleshooting

| Symptom | Cause | Resolution |
| --- | --- | --- |
| `registryctl add notary --from local-relay` cannot find a Relay project | The current directory does not contain a generated `registryctl.yaml` with a Relay section. | Run the command from the Relay tutorial project directory. |
| `registryctl add notary --from local-relay` cannot find a source token | `secrets/local.env` is missing or does not contain the Relay row-reader key. | Recreate the Relay project or restore the generated local env file. |
| `registryctl start` starts Relay but Notary is not ready | Notary config, source token, or Compose service wiring is invalid. | Run `registryctl status`, then `registryctl logs` and check the Notary service errors. |
| Notary `/ready` is degraded while `/healthz` is healthy | The local replay store or demo issuer key is not available to Notary. | Run `registryctl stop`, then `registryctl start`; if it persists, inspect `registryctl logs`. |
| `registryctl notary smoke` returns `401` for authorized calls | The Notary evaluator key was not loaded or does not match the generated Notary fingerprint. | Run `. secrets/local.env`, then retry. |
| Claim evaluation returns a source auth error | Notary cannot authenticate to Relay with `EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN`. | Confirm `secrets/local.env` has the source token and Relay is running. |
| Claim evaluation returns target not found | The target id is not in the sample workbook or the Relay entity lookup changed. | Use `per-2001` for the tutorial target, or inspect the Relay `person` entity. |
