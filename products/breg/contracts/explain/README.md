# `bregctl explain` wire contract

`bregctl --format json explain <subject> <project>` writes a
`BRegCtlReport` whose `explanation` member is a separately versioned document.
`explain_envelope` in `crates/registry-bregctl/src/lib.rs` inserts the
subject's `apiVersion` and `kind` after serialization. The report keeps its
own `breg/ctl-report/v1alpha1` version.

| Subject | Format | Current version | Schema |
|---|---|---|---|
| `model` | `BRegModelExplanation` | `v1alpha6` | `ModelExplanation.schema.json` |
| `access` | `BRegAccessExplanation` | `v1alpha6` | `AccessExplanation.schema.json` |
| `access --scenario` | `BRegAccessPreview` | `v1alpha4` | `AccessPreview.schema.json` |
| `actions` | `BRegActionsExplanation` | `v1alpha6` | `ActionsExplanation.schema.json` |
| `proposals` | `BRegProposalsExplanation` | `v1alpha2` | `ProposalsExplanation.schema.json` |
| `routes` | `BRegRoutesExplanation` | `v1alpha6` | `RoutesExplanation.schema.json` |
| `queries` | `BRegQueriesExplanation` | `v1alpha5` | `QueriesExplanation.schema.json` |
| `events` | `BRegEventsExplanation` | `v1alpha6` | `EventsExplanation.schema.json` |
| `lifecycle` | `BRegLifecycleExplanation` | `v1alpha7` | `LifecycleExplanation.schema.json` |

Each format's identifier is
`id.registrystack.org/formats/breg/<format>/<version>`, with the format name
in lowercase kebab-case. For example, the model format is
`id.registrystack.org/formats/breg/model-explanation/v1alpha6`.

`lifecycle` accepts no project and describes the engine-owned Proposal state
machine. Every other subject requires a project. `proposals` returns the
same source-free Action definitions as `actions`, filtered to Proposal
execution. The removed `change-requests` subject has no current example or
schema.

## Version changes

Model and Access `v1alpha6` add dataset and access-profile display inventories.
Model also retains field display and module origins, and adds `authoring.documents`.
Each document names a project-relative file and lists the RFC 6901 JSON Pointers
present in the source before defaults or module composition. Paths expose
structure and authored mapping keys, without copying leaf content such as labels
or configuration values. Documents also identify their kind and module.
Each document's `bindings` links an `explanationPointer` against this explanation
to a `sourcePointer` against that source document. These links follow IDs and
module origins, so they remain correct when compilation reorders arrays or a
module extends a Record type. The root explanation binds to `/project`.

Bindings cover datasets, project access profiles, review authorities, Record
types, stored and derived fields, record hooks, Actions, inputs, Proposal hooks,
and statistical datasets. To test authored display, find the object's binding
and append `/display/label` or `/display/description` to its source pointer, then
look for that exact path in the same document's `authoredPaths`. Use the same
approach for an unchanged source member such as a stored field's `required`.
Absence means the source did not author that member, not that every generated
member has a default. Compiled names such as `revision`, `canonicalId`, and
`schema` have no implied source counterpart.

Actions `v1alpha6` and Proposals `v1alpha2` retain optional authored input
`display` separately from the existing `label`, whose fallback remains `apiName`.
Display text is presentation metadata and never changes identity, matching, or
authority. Keep the ID alongside any label in selection and approval interfaces.

Lifecycle `v1alpha7` adds each state's possible `turns`. Submitted work has a conditional
turn whose ordered rules use the same evaluator as runtime Proposal documents.
Consumers must select the corresponding new schema for each changed format.

`v1alpha5` names the native model and Proposal contracts. Model inspection
replaces the old entity/package projection with source-free `recordTypes`,
`actions`, and the compiled `revision`. Action inspection uses those same
normalized definitions, including execution policy, plan, commit guards,
dependencies, and bounds. Access inspection renames its top-level `entities`
to `recordTypes`, route references to `recordType`, and consent record
references to `recordType`. Query operations use `recordType` in place of
`entity`. Record routes use `type: record`; Action routes include `start`
and no longer describe the removed request operations. Lifecycle inspection
replaces the request state machine with the Proposal state machine.

Model field entries always include `id`, `apiName`, `required`, `classification`,
`schema` and `fieldType`, including fields absent from every query projection.
`fieldType` carries the same compiled type object as query field summaries, so
a form can distinguish multiline `text` from a bounded `string` and discover a
reference's target. Its internal shape follows the engine field type contract;
the JSON value `schema` remains the validation contract for field values.

The native formats introduced at `v1alpha5` use the native fields above.
`ProposalsExplanation` originally started at `v1alpha1`. Event inspection adds the owning hook phase and Proposal transition
selection. `AccessPreview` retains `v1alpha4` because its pinned shape is unchanged.

`RoutesExplanation` `v1alpha6` adds `availability` to the closed Action route
kind set for immediate Actions with reference inputs. Consumers select the
`v1alpha6` schema.

`LifecycleExplanation` `v1alpha6` adds the terminal `rejected` state, the
`reject` transition from `submitted`, and the `review-authority-result`
enforcement that only a verified review result performs it. Consumers select
the `v1alpha6` schema.

`EventsExplanation` `v1alpha6` adds the `rejected` and `review-returned`
Proposal transitions to the transition selection a Proposal hook may name.
Consumers select the `v1alpha6` schema.

## Schemas and compatibility

Each schema is draft 2020-12 and self-contained. A pinned object seals its
members with `additionalProperties: false`. Adding, removing, renaming, or
changing a pinned member requires a version bump for that format alone.

`x-registry-passthrough` marks compiler-owned values whose internal shape is
outside this explanation contract. Consumers must validate any opaque data
they use. The annotation states why each node is opaque; JSON Schema
validators ignore the annotation. The Access authority inventory pins
`principalClaims` and the mutually exclusive inventory/error relationship,
while the remaining inventory members stay opaque. Casework provider pairing
independently verifies its sealed context export and grants no BReg authority.

The Lifecycle payload is pinned in full because its model exists solely to
explain this state machine. Actions and Proposals share a source-free
inspection shape; their schemas independently describe it without external
references.

## Canonical examples and verification

`products/platform/config-formats.yaml` registers each schema and canonical
example under `products/breg/examples/formats/explain/`.
`crates/registry-bregctl/tests/explain_contract.rs` reads those registered
example bytes, validates them against the schema, and compares them with the
current formatter's pretty-printed JSON plus a final newline. It also checks
the registered `ctl-report.json` Actions report, multiple native projects,
and malformed pinned values. The committed full report normalizes diagnostic
`findings[].source.file` and `findings[].related[].file` under the repository
root to repository-relative paths before formatting and comparison. All other
report content remains unchanged. This fixture convention does not change the
CLI's source addresses.

The additional `authored-display-*-explanation.json` examples use
`products/breg/fixtures/authoring-display/`. They pin labels and descriptions on
profiles, native and statistical datasets, fields, inputs, and both hook kinds,
including an input with no authored display.

Generate the examples from a binary built from the matching checkout. From
the repository root, with that `bregctl` on `PATH`:

```sh
python3 - <<'PY'
import json
import subprocess
from pathlib import Path

examples = Path('products/breg/examples/formats/explain')
project = 'products/breg/examples/facility'
preview = 'crates/registry-bregctl/tests/fixtures/retained-native/access-review'
commands = {f'{subject}-explanation': [subject, project] for subject in
            ['model', 'access', 'actions', 'proposals', 'events', 'queries', 'routes']}
commands['access-preview'] = ['access', preview, '--scenario', f'{preview}/allowed.json']
commands['lifecycle-explanation'] = ['lifecycle']
for subject in ['model', 'access', 'actions', 'proposals']:
    commands[f'authored-display-{subject}-explanation'] = [
        subject, 'products/breg/fixtures/authoring-display']
for name, args in commands.items():
    report = json.loads(subprocess.check_output(['bregctl', '--format', 'json', 'explain', *args]))
    assert report['ok'], report
    (examples / f'{name}.json').write_text(
        json.dumps(report['explanation'], indent=2, sort_keys=True, ensure_ascii=False) + '\n')
report = json.loads(subprocess.check_output(
    ['bregctl', '--format', 'json', 'explain', 'actions', project]))
root = Path.cwd().resolve()
for finding in report['findings']:
    locations = [finding['source']] if 'source' in finding else []
    locations += finding.get('related', [])
    for location in locations:
        file = Path(location['file'])
        if file.is_relative_to(root):
            location['file'] = str(file.relative_to(root))
(examples.parent / 'ctl-report.json').write_text(
    json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + '\n')
PY
cargo test --locked -p registry-bregctl --test explain_contract
```
