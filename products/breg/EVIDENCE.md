# Export a lookup for Evidence

BReg exports an explicitly selected compiled lookup as a reviewed Source contract.
Import merges that Source, its selector profiles, and named preparation/extraction
Functions into an existing normalized EvidenceProject. Evidence owns the
AssertionDefinitions those facts answer, caller grants, minimum disclosure,
signing, and deployment configuration. Live acquisition uses BReg's ordinary HTTP
lookup API.

This is an optional authoring path. Evidence's existing OpenAPI authoring,
custom HTTP adapters and SQLite sources remain usable without an export,
import manifest or named connection.

## Select the technical contract

Start with an authored registry whose selected access profile already grants
the lookup and the readable fields you intend to expose. The exporter reads
the compiled model, including locked modules and derived SQL assets. It does
not change the registry or create an access permission.

```sh
mkdir exports
bregctl generate evidence-source ./registry \
  --access-profile evidence-source --record-type record \
  --selector by-code --selector by-registration-number \
  --fields status --source-id registry-status --connection registry \
  --output ./exports/registry-status
```

Repeat `--selector` to offer alternatives in the same source. Each request
chooses exactly one profile and makes one lookup. There is no fallback search.
Use another export with another `--source-id` when the selected facts, authority
or intended maintenance boundary differ. Several AssertionDefinitions can reuse
one Source without exporting it again.

`--fields` names logical BReg fields, as does `--record-type`. API property aliases
are resolved by the compiler. A `registration-number` field can therefore
become the `registrationNumber` property on the wire while keeping its logical
name in Evidence selectors and facts.

For each selected alternative, the generated request uses the fixed lookup
route, method and access profile, and asks for the selected facts plus only
that alternative's identity fields. Those identity fields must already be
readable. The command reports additional identity fields and generated profile
names; it refuses insufficient authority with a diagnostic.

The output directory must be new. Generate the next version into another
directory so that you can compare and review it before changing an Evidence
project.

## Start with the maintained composition inputs

The default `bregctl init` writes the minimal contact directory. It deliberately
supplies no Evidence lookup grant, source client, or unique business key. The
[composition inputs](evidence/README.md) include an explicit BReg registry with
`code` and `registration-number` selectors and a lookup-only `evidence-source`
profile. Its readable status is separate from its private label.

The complete `evidence/offline-starter/` is an independent normalized
EvidenceProject. Initialize a new editable project, then check its 13 synthetic
SQLite cases without starting a registry or service:

```sh
evidencectl init ./evidence --starter /path/to/offline-starter --profile local
evidencectl check ./evidence
evidencectl test ./evidence --target ./evidence/local-target.yaml
```

Its `evidence.yaml` owns Sources, selector profiles, named Functions, and
AssertionDefinitions. `local-target.yaml` binds local resources;
`dev-authority.yaml` supplies complete disposable caller authority. The tracked
inputs contain secret references; initialization creates owner-only local keys.

After exporting your selected BReg lookup, import it into that existing project:

```sh
evidencectl source import ./exports/registry-status --project ./evidence
```

Import creates no assertion meaning or caller grant. Merge the maintained
`evidence/starter/definitions.yaml.fragment` Functions and AssertionDefinitions
into the existing `evidence.yaml`, and copy its `functions/` and `fixtures/` files.
The fragment is ordinary authoring input, not a complete project or an
`init --starter` template. Keep the independent SQLite definition and imported
Source declarations. The resulting project has three definitions and two Sources,
with 35 synthetic fixture cases across the complete composition.

Generate a fresh complete local target after adding definitions:

```sh
evidencectl target new ./configured-target --local --project ./evidence
```

Review its separate caller grants and add the named `registry` connection to
`configured-target/target.yaml`. Then check, test, and package that exact target:

```sh
evidencectl check ./evidence --target ./configured-target
evidencectl test ./evidence --target ./configured-target
evidencectl package ./evidence --target ./configured-target --output ./candidate
```

Packaging writes an immutable `bundle/` and a separate target handoff; it deploys
neither product. Recorded-source fixtures establish bounded calculation,
identity checks, and refusals. They do not establish live HTTP authorization,
signing, or retained-session operation.

## Add Evidence after local registry use

An existing authored registry can be used before it has an Evidence lookup or
client. Start with a complete EvidenceProject, stop the retained BReg session
normally, then preview guided setup:

```sh
bregctl dev stop ./registry
evidencectl source add ./registry ./evidence
```

Select the Record type, an existing required unique scalar selector, readable
facts, and explicit row scope. Evidence's `source add` uses its public `--entity`
flag for scripted selection; its BReg subprocesses use `--record-type`. They are
separate CLI contracts. Matching `bregctl` must be on `PATH`.

Review the proposed authority before repeating the command with `--apply`.
Setup prepares a dedicated lookup client and policy successor, imports the
Source, copies credentials privately, and derives local connection bindings
from the stopped retained session. It supplies no AssertionDefinition or Evidence
caller grant. Restart BReg to activate the prepared successor over retained
records. Do not use `dev stop --remove` when those records must survive.

For a fixed row scope, use a nonsecret label. The selected value becomes an
authored client claim in `dev-clients.yaml`; a private prompt or input file does
not make that authored claim private. The [development lifecycle](DEV.md#prepare-a-source-after-using-a-registry)
owns retained-session preparation and recovery. An already-imported Source is
maintained through `source diff` and `source update`, rather than attached again
under conflicting choices. A lower-level `dev export-client` copies an explicit
retained client pair and grants no authority.

## Configure the connection in Evidence

The export records a logical connection name, `registry` in this example.
The Evidence operator supplies its fixed base URL, authentication and optional
TLS trust profile in the normalized target's `connections` map. Credentials remain
logical secret references resolved by that deployment. A BReg package or
metadata response never supplies Evidence caller authority.

When the exported Record type declares `accessLog`, the source opts into forwarding
the Evidence requester's verified identity and purpose. The Evidence
connection's verified OAuth client ID must also appear in that Record type's
`accessLog.trustedIntermediaries`; otherwise BReg refuses the forwarded
request. Forwarded attribution does not grant record authority.

Use the existing authentication mode appropriate for the source. A named
connection shares its HTTP pool, admission limit and OAuth token state across
the sources which explicitly reference it within one Evidence process.
Separate names keep separate resource owners. Existing inline source
configuration remains available.

The exporter intentionally refuses a `verified-claim` lookup. Such a lookup
uses claims of the source workload's token, which do not identify the Evidence
caller. Select a reviewed `request` lookup when the caller's authorized
selector values must identify the record.

## Review identity and fact handling

The generated extraction adapter uses Evidence's optional
`extract(response, selectors, context)` form. It checks the returned selected
identity's scalar type and exact value before returning matched facts. Missing,
wrongly typed or mismatched identity fails as a source protocol error. No
AssertionDefinition can skip that check by replacing its derive Function.

Only the explicit fact fields enter the fact set. An absent or null required
fact produces no match and cannot become an authoritative negative answer.
A genuine BReg unresolved lookup is recognized only by its exact declared
Problem Details status, type and code. Other HTTP failures remain failures.

Selectors support bounded nonempty strings, dates, booleans, and UUID/reference
fields using Evidence's `uuid` type. UUID facts carry JSON Schema `format: uuid`.
Both require exactly 36 ASCII characters in the hyphenated 8-4-4-4-12 lowercase
hexadecimal form, the spelling BReg itself returns. Uppercase and other
same-length malformed values are refused before source access or signing.
Composite profiles must fit Evidence's aggregate selector bound. String maxima
allow four UTF-8 bytes per BReg character. Identity values are never normalized
by the adapter. Use the spelling returned by the provider. Vocabulary facts retain their enum; vocabulary selectors require a
reviewed codelist artifact, so this exporter refuses them with adapter guidance.

BReg's unrestricted `int64` selector range exceeds Evidence's exact
safe-integer selector range, so the exporter refuses it instead of silently
narrowing its advertised identity contract. A string selector field that
accepts the empty value, an explicit or defaulted `minimumLength` of `0`, is
refused for the same reason: declare a `minimumLength` of at least 1, or maintain
a reviewed custom adapter. Use a bounded string selector or maintain a
reviewed custom adapter for unsupported shapes. Bounded scalar facts are
supported; structured and spatial facts require a custom adapter.

## Import and update ordinary files

```sh
evidencectl source import ./exports/registry-status --project ./evidence
evidencectl source diff ./exports/registry-status-next --project ./evidence
evidencectl source update ./exports/registry-status-next --project ./evidence
```

The optional [source export contract](../evidence/reference/authoring-projects/SOURCE-EXPORT.md)
defines checksums, explicit customization resolutions, shared artifact
ownership and interrupted-update recovery. Imported files remain ordinary
authored files. Use `evidencectl source detach registry-status ./evidence`
to retain them under your own maintenance.

The consumed `behaviorRevision` covers selected fields, selectors, authority
and reached derived behavior. A reached derived SQL file is fingerprinted as
one implementation, together with its referenced source schemas and row
visibility. An unused derived computation or unrelated field on a simple
stored-field lookup does not change that consumed identity. The complete
`registryRevision` is separate export provenance.

Changing a record's values does not require another export. Changing consumed
lookup behavior does. Build and test the Evidence candidate against the exact
provider candidate before a coordinated deployment. The export is an offline
contract, not a request-time attestation of the currently running provider.
Independently evolving providers require a paused, coordinated cutover when
their consumed meaning changes.

## Consuming Evidence during an action

The separate [Action plan and Evidence guide](immediate-actions.md)
lets a governed Rhai action acquire verified assertions before finalizing its
writes. The [farmer landholding example](acceptance/farmer-landholding-evidence/README.md)
shows preprocessing, early refusal, conditional disclosure and exact offline
mocks. Imported client contracts define the signed processing ceiling; operator
configuration supplies fixed endpoints, credentials and trust. This is distinct
from the lookup export described above, and does not grant BReg authority over
Evidence source access or signing.

### Compare a prior export

Retain `source-export.json` from the deployed export, then run:

```sh
bregctl check ./registry --prior-evidence-export ./previous-export/source-export.json
```

The manifest records selected fact and identity fields, and fields consumed by
reached SQL source relations and read boundaries. The comparison warns with
`breg.evidence-source.field-removed` when a consumed field is absent or renamed;
`--deny-warnings` makes that check exit 1. Unrelated changes are silent. A manifest
for another registry or an absent entity is refused. Regenerate older exports
that lack the dependency inventory before using this comparison. The inventory
is advisory authoring evidence and supplies no runtime authority.
