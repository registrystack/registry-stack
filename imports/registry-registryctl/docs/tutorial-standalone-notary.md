# Create a standalone Registry Notary

Use this tutorial to create a standalone Registry Notary project for an
existing Registry Data API. You will point Notary at the Relay API from the
spreadsheet tutorial, start Notary from a separate folder, and evaluate the
same starter claim without co-locating Notary in the Relay project.

The tutorial uses synthetic data and local demo credentials. Do not use the
generated local keys in production.

## Before you start

Complete the Relay spreadsheet API tutorial first and leave Relay running:

```sh
registryctl init relay my-first-api --sample benefits
cd my-first-api
registryctl start
registryctl smoke
```

Load the Relay local demo keys into your shell:

```sh
set -a
. secrets/local.env
set +a
```

Keep that Relay project running. The standalone Notary project will join the
Relay project's Docker Compose network and call the Relay service by name.

## Create the standalone Notary project

From the parent directory of `my-first-api`, create a Notary project:

```sh
cd ..
registryctl init notary my-standalone-notary \
  --source-url http://registry-relay:8080 \
  --source-network my-first-api_default \
  --source-token-from-env ROW_READER_RAW
cd my-standalone-notary
```

`registryctl` creates:

```text
my-standalone-notary/
  registryctl.yaml
  compose.yaml
  README.md
  notary/
    config.yaml
  bruno/
    registry-api/
  secrets/
    local.env
  output/
```

The Notary config contains the source API URL, source dataset, entity, lookup
field, env variable names, and credential commitments. The raw Notary evaluator
key, source API token, audit secret, local demo issuer key, and Redis URL live
only in `secrets/local.env`.

If you do not pass `--source-token-from-env`, `registryctl` writes a placeholder
source token in `secrets/local.env`. Replace it before running the Notary smoke
test.

## Start standalone Notary

Start the Notary project:

```sh
registryctl start
```

The command starts Notary and a local Redis replay store, then waits for
`/healthz` and `/ready`:

```text
Notary API: http://127.0.0.1:4255
OpenAPI:    http://127.0.0.1:4255/openapi.json
```

Check status:

```sh
registryctl status
```

Notary should report healthy and ready.

## Run the Notary smoke test

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

The smoke result should not contain raw API keys, source tokens, local env
values, Relay source rows, or sensitive sample column values.

## Evaluate the claim with curl

Load the standalone Notary keys:

```sh
set -a
. secrets/local.env
set +a
```

Evaluate whether the synthetic person `per-2001` exists in the source API:

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

## Optional: open the Bruno collection

`registryctl` generates a Bruno collection for the standalone Notary project.
Bruno is optional. The tutorial and API work without it.

Open the generated collection:

```sh
registryctl bruno open
```

If Bruno is installed, the collection opens. If Bruno is not installed, the
command prints the collection path and an install link.

If the Bruno CLI is installed, you can run the collection:

```sh
registryctl bruno run
```

If `bru` is not installed, the command prints a fallback and exits without
blocking Notary.

## Stop the local projects

Stop standalone Notary:

```sh
registryctl stop
```

Then stop the Relay project:

```sh
cd ../my-first-api
registryctl stop
```
