# BReg and Evidence composition starter

These maintained teaching inputs compose the two products through their native
commands and existing HTTP lookup API. All records, identities and policy names
are synthetic. Follow [the export contract](../EVIDENCE.md) and
[the native BReg development lifecycle](../DEV.md) for their operator boundaries.

| Input | Responsibility |
| --- | --- |
| `registry/registry.yaml` | One stored record, two exact unique selectors, a separate operator and an explicit request-origin Evidence lookup profile. |
| `registry/clients.yaml` | Separate synthetic operator and source clients, plus active, retired and missing-status seed records. Credentials are generated privately by `bregctl dev`. |
| `registry/tests/journeys.yaml` | Native schema rehearsal of create, both authorized lookups and unresolved lookup. |
| `starter/` | Two questions, derivations, fixtures and a reviewed local target settings template for `evidencectl new --starter`. |
| `tests/verify-composition.py` | Maintainer-only verification using native binaries; not part of the adopter workflow. |

Copy the registry directory to an empty local working directory. Create the
Evidence project and export the explicitly selected source contract:

```sh
evidencectl new ./evidence --starter <this-directory>/starter --profile local
bregctl generate evidence-source ./registry \
  --access-profile evidence-source --entity record \
  --selector by-code --selector by-registration-number \
  --fields status --source-id registry-status --connection registry \
  --output ./exports/registry-status
```

Continue with the copied Evidence README to bind a target, import, run fixtures and
build. For live development, first add the source client's explicit absolute
`clientIdFile` and `assertionKeyFile` output paths to the local clients file, pointing
to `evidence/secrets/registry-client-id` and `evidence/secrets/registry-client-key`.
Then start `bregctl dev --project ./registry --clients-file ./registry/clients.yaml`.
The starter's connection uses its default BReg and Mint ports, 8090 and 8091.

The source profile intentionally permits registry-wide exact lookups in this
synthetic model, expressed as `rowBoundaries: []`. It cannot create or patch
records, and cannot read `label`. The operator profile can maintain those fields.
The export requests `status` and only the chosen selector's identity field;
`registration-number` remains the logical identifier while `registrationNumber`
is its HTTP property. An unresolved lookup or absent fact never signs `false`.

Keep generated exports and candidates outside this maintained input tree. Record
value changes require no export. When consumed lookup meaning changes, review a
new export, compare it with `evidencectl source diff`, and coordinate provider and
Evidence candidates before serving the changed contract.

For maintainer verification, install PyYAML and run the test driver with matching
`--bregctl`, `--evidencectl` and `--evidence` binary paths. It uses a disposable
private directory, checks repeatable export bytes and all 22 fixture cases, builds
the target, then proves provenance-only and consumed-behavior revision changes
through native source diff and update. `--work-dir <new-directory>` retains the
synthetic outputs for inspection. It starts no network service.
