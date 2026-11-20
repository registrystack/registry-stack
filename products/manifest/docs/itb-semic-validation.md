# ITB/SEMIC validation smoke checks

An optional smoke script checks generated DCAT and BRegDCAT-AP against the public EU Interoperability Test Bed validators.

The Interoperability Test Bed (ITB) is operated by the Semantic Interoperability Community (SEMIC).
The script is not a certification gate. It is a reproducible compatibility check
for selected generated artifacts.
For what the evidence covers and does not cover, see
[ITB and SEMIC evidence](https://docs.registrystack.org/reference/itb-semic-evidence/).

## Run locally

Run the script from the `products/manifest` directory of a Registry Stack checkout.
It renders and validates the example manifest without calling external services:

```sh
scripts/itb-semic-smoke.sh
```

This validates the manifest with the `registry-manifest` CLI (the script invokes it as `cargo run -p registry-manifest-cli --`), publishes the static
metadata bundle under `target/itb-semic-smoke/example-civil-registration`, and
prints the output path. It does not call the public ITB/SEMIC validators.

Run the remote SHACL checks explicitly:

```sh
ITB_SEMIC_REMOTE=1 scripts/itb-semic-smoke.sh
```

Run ITB JSON validator checks when an `isaitb/json-validator` endpoint is
available:

```sh
docker run -d --rm --name registry-manifest-itb-json \
  -p 18081:8080 \
  isaitb/json-validator:latest

ITB_JSON_VALIDATOR_URL=http://127.0.0.1:18081/json/any/api/validate \
  scripts/itb-semic-smoke.sh
```

Remote reports are saved under `target/itb-semic-smoke/reports`:

| Report | Validator profile |
| --- | --- |
| `schema-vital-events-person-schema-json.json` | JSON Schema Draft 2020-12 |
| `schema-vital-events-vital_event-schema-json.json` | JSON Schema Draft 2020-12 |
| `dcat-ap.json` | `dcatap.3_0_1_base0` |
| `bregdcat-ap-2.0.0.json` | `bregdcatap.2_0_0` |
| `bregdcat-ap-2.1.0.json` | `bregdcatap.2_1_0` |

The script fails when a report contains validation errors. Warnings are printed
and retained in the saved reports because the public BRegDCAT-AP validator
profiles can emit advisory warnings for profile-specific controlled-vocabulary
preferences.

## Known BRegDCAT-AP warnings

The example civil-registration manifest uses a local publisher IRI:
`https://civil-registration.example.gov/authority`. Public BRegDCAT-AP 2.x
validator profiles warn when `dcterms:publisher` is not a Publications Office
corporate-body IRI with `skos:inScheme` set to
`http://publications.europa.eu/resource/authority/corporate-body`. That warning
is useful for EU corporate-body publishers, but it is not a renderer failure for
local registry publishers.

The BRegDCAT-AP 2.0 and 2.1 validator profiles also differ in their warning-level
checks for `dcat:themeTaxonomy`. The rendered artifact includes both the EU
data-theme concept scheme and EuroVoc concept scheme so consumers can see both
catalogue theme taxonomies. The public 2.x warning profiles may still flag one
value while accepting the artifact with zero validation errors.

These warning classes are intentionally documented rather than hidden: the
smoke script retains the validator reports, and public release notes should
carry the profile and warning count when BRegDCAT-AP evidence is cited.
