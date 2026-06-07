# Publish a spreadsheet as a secured API

Use this tutorial to create a local Registry Relay project from a sample Excel
workbook. You will install `registryctl`, start a protected API, prove
anonymous access is denied, read spreadsheet data through a secured route, and
open the local API reference.

The tutorial uses synthetic data and local demo credentials. Do not use the
generated local keys in production.

## Before you start

Install:

- `curl`, `tar`, and `shasum` or `sha256sum`
- Docker Desktop, Colima, Podman, or another Docker Compose provider

Install `registryctl` without cloning this repo:

```sh
curl -fsSL https://raw.githubusercontent.com/jeremi/registry-registryctl/main/install.sh | sh
```

The installer downloads the current `snapshot` release binary. Snapshot
binaries are currently published for Linux x86_64, Linux aarch64, and macOS
aarch64.

Confirm the CLI is available:

```sh
registryctl --version
```

If your shell cannot find `registryctl`, add the install directory printed by
the installer to your `PATH`.

## Create A Local Spreadsheet API Project

Create a project from the benefits sample:

```sh
registryctl init spreadsheet-api my-first-api --sample benefits
cd my-first-api
```

`registryctl` creates:

```text
my-first-api/
  registryctl.yaml
  compose.yaml
  README.md
  relay/
    config.yaml
    metadata.yaml
  data/
    benefits_casework.xlsx
  secrets/
    local.env
  output/
```

The `secrets/local.env` file contains local demo bearer keys and matching
fingerprints. The Relay config contains only fingerprint references and
commitments.

## Start Registry Relay

Start the local project:

```sh
registryctl start
```

The command starts the published Registry Relay container, waits for health and
readiness, and prints:

```text
Relay API:  http://127.0.0.1:4242
API docs:   http://127.0.0.1:4242/docs
```

Check status:

```sh
registryctl status
```

The service should report `healthz: 200` and `ready: 200`.

## Run The Built-In Smoke Test

Run the smoke checks:

```sh
registryctl smoke
```

The smoke test should pass:

```text
PASS healthz is public
PASS ready is public
PASS anonymous dataset request is denied
PASS metadata key can list datasets
PASS metadata key cannot read rows
PASS row read without Data-Purpose returns 400
PASS row reader can read filtered records
PASS authorized key can fetch runtime OpenAPI
```

`registryctl` writes detailed results to:

```text
output/smoke-results.json
```

## Load Local Demo Keys

Load the generated local keys into your shell:

```sh
set -a
. secrets/local.env
set +a
```

The generated principals are labels wired to Relay scope strings in the
generated config.

| Principal | Environment variable | What it can do |
| --- | --- | --- |
| `metadata_reader` | `METADATA_READER_RAW` | Read catalog and schema metadata |
| `row_reader` | `ROW_READER_RAW` | Read configured entity records with a purpose header |
| `aggregate_reader` | `AGGREGATE_READER_RAW` | Run configured aggregates, if present |

## Prove Anonymous Access Is Denied

Call a protected route without a credential:

```sh
curl -i http://127.0.0.1:4242/v1/datasets
```

Relay should return `401 Unauthorized`.

Call the same route with the metadata key:

```sh
curl -i \
  -H "Authorization: Bearer $METADATA_READER_RAW" \
  http://127.0.0.1:4242/v1/datasets
```

Relay should return `200 OK` and show the dataset visible to that principal.

## Read Spreadsheet Data Through The API

Relay exposes configured entities, not spreadsheet sheet names. The sample
workbook has a `Persons` sheet, but callers read the `person` entity.

Read records for one household:

```sh
curl -sS -G \
  -H "Authorization: Bearer $ROW_READER_RAW" \
  -H "Data-Purpose: https://example.local/purpose/tutorial" \
  --data-urlencode "household_id=hh-1001" \
  http://127.0.0.1:4242/v1/datasets/benefits_casework/entities/person/records
```

The response should include synthetic person records from household `hh-1001`.
Sensitive source columns such as full names, national identifiers, and
addresses are not exposed as public entity fields in this sample.

Try the same request with the metadata-only key:

```sh
curl -i -G \
  -H "Authorization: Bearer $METADATA_READER_RAW" \
  -H "Data-Purpose: https://example.local/purpose/tutorial" \
  --data-urlencode "household_id=hh-1001" \
  http://127.0.0.1:4242/v1/datasets/benefits_casework/entities/person/records
```

Relay should return `403 Forbidden`.

## Open The API Reference

Open the local API docs:

```sh
registryctl open
```

The docs page opens at:

```text
http://127.0.0.1:4242/docs
```

The docs shell is public. The runtime OpenAPI document it loads is protected
and requires a bearer key.

Fetch the runtime OpenAPI document directly:

```sh
curl -sS \
  -H "Authorization: Bearer $METADATA_READER_RAW" \
  http://127.0.0.1:4242/openapi.json
```

## Stop The Local Project

When you are done:

```sh
registryctl stop
```

This stops the local containers. It does not delete your workbook, generated
config, local keys, or smoke results.

## Troubleshooting

| Symptom | Cause | Resolution |
| --- | --- | --- |
| `registryctl` is not found | The install directory is not on `PATH`. | Add the directory printed by the installer, usually `~/.local/bin`, to `PATH`. |
| The installer reports an unsupported platform | No binary is published for that OS or CPU yet. | Use a supported Linux or macOS aarch64 machine, or install from source with Cargo. |
| `registryctl start` cannot find Docker | Docker or another Compose provider is not installed or running. | Start Docker Desktop, Colima, Podman, or your supported provider, then run `registryctl start` again. |
| A row read returns `403 Forbidden` | The key is valid but lacks the row-read scope. | Use `ROW_READER_RAW` for row reads. |
| A row read returns `400 auth.purpose_required` | The entity requires a `Data-Purpose` header. | Send `Data-Purpose: https://example.local/purpose/tutorial` or another purpose URI. |
| A collection row read returns a filter error | The entity requires at least one configured filter. | Add a filter such as `household_id=hh-1001`. |
