# BReg and Evidence composition

These synthetic inputs connect independently governed products through public
CLIs and the existing HTTP lookup contract. BReg owns stored records, exact
selectors and source access. Evidence owns assertion meaning, caller grants,
minimum disclosure and signing. An export creates no authority in either product.
See [the export contract](../EVIDENCE.md) and [BReg development](../DEV.md).

| Input | Responsibility |
| --- | --- |
| `registry/` | Explicit native BReg project with two unique selectors, status facts, an operator and a lookup-only source profile. |
| `offline-starter/` | Complete native EvidenceProject with named Functions, a local target, complete target authority and 13 SQLite fixtures. |
| `starter/` | Reviewed authoring fragment, derive Functions and 22 fixtures for two definitions sharing the imported BReg Source. |
| `tests/verify-composition.py` | Offline maintainer proof using matching installed binaries. |

The default `bregctl init` creates a minimal contact directory with editor clients.
It supplies no Evidence lookup profile, source client or unique business key.
Use the explicit registry here for this integration; an existing institutional
registry must deliberately declare the unique selector and source authority it needs.

## Offline authoring and optional source import

Copy `registry/` into a new working directory as `./registry`. Start with the
complete offline project, which needs neither BReg nor a running service:

```sh
evidencectl init ./evidence --starter <this-directory>/offline-starter --profile local
evidencectl check ./evidence
evidencectl test ./evidence --target ./evidence/local-target.yaml
bregctl generate evidence-source ./registry \
  --access-profile evidence-source --record-type record \
  --selector by-code --selector by-registration-number \
  --fields status --source-id registry-status --connection registry \
  --output ./registry-status-export
evidencectl source import ./registry-status-export --project ./evidence
```

Import adds the normalized Source, selector profiles and named preparation and
extraction Functions to `evidence.yaml`. It supplies no assertion or caller grant.
The existing offline definition remains independently runnable.

Follow [the definition fragment instructions](starter/README.md) to add the two
BReg definitions and their Functions and fixtures. Then generate a complete local
target and review its separate authority:

```sh
evidencectl target new ./configured-target --local --project ./evidence
```

Add a `registry` connection to `configured-target/target.yaml`, with the registry
origin and its operator-approved authentication references. For a retained local
registry, [guided connection](#guided-local-connection) derives those bindings.
The offline proof uses synthetic loopback bindings and resolves no credentials.
Run the completed project:

```sh
evidencectl check ./evidence --target ./configured-target
evidencectl test ./evidence --target ./configured-target
evidencectl package ./evidence --target ./configured-target --output ./candidate
```

The candidate contains the immutable `bundle/` and a separate target handoff.
Packaging is offline and does not deploy it. Keep generated exports, credentials
and candidates outside this maintained input tree and out of version control.

## Guided local connection

For a registry already used through `bregctl dev`, stop its retained session
normally and review `evidencectl source add ./registry ./evidence`. Choose an
existing required unique field, the facts, and explicit record scope. The command
reviews by default; `--apply` performs the reviewed connection through public BReg
commands. Its public selector flag is `--entity`, while BReg export uses
`--record-type`. Matching `bregctl` must be on `PATH`.

Guided setup is optional and requires a retained session. It prepares a dedicated
lookup client and policy successor, imports the Source and copies credentials
privately. It does not authorize Evidence callers or define an assertion.
Use the maintained [retained-session procedure](../DEV.md#prepare-a-source-after-using-a-registry)
for activation and recovery. A source identity already present in a project must
be reviewed through `source diff` and `source update`, rather than attached again
under conflicting choices.

The explicit source profile permits registry-wide exact lookups, expressed as
`rowBoundaries: unrestricted`. It cannot list, create or patch records and cannot
read `label`. Exported identity fields bind exact returned records but never
become facts. Missing status or unresolved identity never signs `false`.

## Maintainer proof

Run `tests/verify-composition.py` with matching `--bregctl`, `--evidencectl` and
`--evidence` paths and PyYAML. `--work-dir <new-directory>` retains synthetic
outputs privately. The runner starts no services and proves:

- Native offline initialization, checking, all 35 fixtures and packaging.
- Repeatable export bytes and inventory digests, unreadable-field refusal and
  tampered-import refusal without authored changes.
- Exact selector and returned-identity binding, minimum disclosure, unavailable
  outcomes, SQLite statement bounds and stale extracts through fixtures.
- Two definitions sharing one imported Source, with unrelated provenance leaving
  revisions unchanged and a consumed change leaving the offline definition unchanged.
- Native source update and incompatible fact rename refusal before authored changes.
- Guided connection's matching-tool requirement and missing-session refusal.

The offline runner does not establish successful retained-session attachment,
HTTP authorization, live signing or service operation. Those need the separate
native local lifecycle journey. Value changes need no new export; changes to a
consumed contract need a new export, `source diff`, and reviewed provider and
Evidence candidates before activation.
