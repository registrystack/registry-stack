# BReg and Evidence composition starter

These maintained teaching inputs compose the two products through their native
commands and existing HTTP lookup API. All records, identities and policy names
are synthetic. Follow [the export contract](../EVIDENCE.md) and
[the native BReg development lifecycle](../DEV.md) for their operator boundaries.

For a custom-model journey, derive `organization-selection.yaml` with
`bregctl init --from publicschema --selection`, start and edit a record, then stop
normally. `evidencectl source add ./registry --project ./evidence --source-id
registry-name --selector-profile by-code` guides the code/name lookup authority
and reports the connection it would configure; the same command with `--apply`
configures it. Copy the `named-starter/` question, derivation, and
fixtures into the created project. The archive supplies sample question material;
source setup itself needs no archive or copied endpoint settings.

| Input | Responsibility |
| --- | --- |
| `registry/registry.yaml` | One stored record, two exact unique selectors, a separate operator and an explicit request-origin Evidence lookup profile. |
| `registry/clients.yaml` | Separate synthetic operator and source clients, plus active, retired and missing-status seed records. Credentials are generated privately by `bregctl dev`. |
| `registry/tests/journeys.yaml` | Native schema rehearsal of create, both authorized lookups and unresolved lookup. |
| `organization-selection.yaml` | A custom PublicSchema Organization selection with code and name, no Evidence grant. |
| `named-starter/` | One name-present question to add after guided source setup. |
| `default-starter/` | One question and 11 fixtures compatible with plain `bregctl init`, for adding Evidence after registry use. |
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
build. For a BReg-first workflow, run `bregctl init ./registry`, start and edit a
record, then stop with `bregctl dev stop ./registry` before creating Evidence from
`default-starter/`. Export only `by-code` for that model. Copy the retained source
credentials after Evidence creates its owner-only secrets directory:

```sh
bregctl dev export-client ./registry --client source \
  --client-id-file ./evidence/secrets/registry-client-id \
  --assertion-key-file ./evidence/secrets/registry-client-key
```

For the broader copied registry use `--clients-file ./registry/clients.yaml` on its
first start. Both starters use default BReg and stock issuer ports `8090` and `8091`.
Normal stop/start preserves records, package, and credentials. Do not remove data
or change the retained registry's model or client declarations to add Evidence.

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
synthetic outputs for inspection. It also checks unmodified default init with the
one-question starter and its 11 fixtures. The default run starts no services.

Add `--live`, a matching `--breg` binary path, and available Docker
to execute the retained-record journey. It allocates unused loopback ports,
creates and edits a record before Evidence exists, stops normally during setup,
and verifies the signed answer after restart. It checks retained record and
credential identity plus the source permission ceiling. Final cleanup stops
its Evidence services and removes only its own BReg database and services.
