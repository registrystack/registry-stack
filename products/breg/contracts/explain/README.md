# `bregctl explain` wire contract

`bregctl --format json explain <subject> <project>` writes a
`BRegCtlReport` whose `explanation` member is a separately versioned document.
`explain_envelope` in `crates/registry-bregctl/src/lib.rs` inserts the
subject's `apiVersion` and `kind` after serialization. The report keeps its
own `breg/ctl-report/v1alpha1` version.

| Subject | Format | Current version | Schema |
|---|---|---|---|
| `model` | `BRegModelExplanation` | `v1alpha5` | `ModelExplanation.schema.json` |
| `access` | `BRegAccessExplanation` | `v1alpha5` | `AccessExplanation.schema.json` |
| `access --scenario` | `BRegAccessPreview` | `v1alpha4` | `AccessPreview.schema.json` |
| `actions` | `BRegActionsExplanation` | `v1alpha5` | `ActionsExplanation.schema.json` |
| `proposals` | `BRegProposalsExplanation` | `v1alpha1` | `ProposalsExplanation.schema.json` |
| `routes` | `BRegRoutesExplanation` | `v1alpha5` | `RoutesExplanation.schema.json` |
| `queries` | `BRegQueriesExplanation` | `v1alpha5` | `QueriesExplanation.schema.json` |
| `events` | `BRegEventsExplanation` | `v1alpha5` | `EventsExplanation.schema.json` |
| `lifecycle` | `BRegLifecycleExplanation` | `v1alpha5` | `LifecycleExplanation.schema.json` |

Each format's identifier is
`id.registrystack.org/formats/breg/<format>/<version>`, with the format name
in lowercase kebab-case. For example, the model format is
`id.registrystack.org/formats/breg/model-explanation/v1alpha5`.

`lifecycle` accepts no project and describes the engine-owned Proposal state
machine. Every other subject requires a project. `proposals` returns the
same source-free Action definitions as `actions`, filtered to Proposal
execution. The removed `change-requests` subject has no current example or
schema.

## Version changes

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

Consumers of these seven formats must select the corresponding `v1alpha5`
schema and use the native fields above. `ProposalsExplanation` starts at
`v1alpha1`. Event inspection adds the owning hook phase and Proposal transition
selection. `AccessPreview` retains `v1alpha4` because its pinned shape is unchanged.

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
