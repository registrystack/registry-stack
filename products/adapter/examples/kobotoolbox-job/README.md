# KoboToolbox ingestion job examples

Use these examples to prepare one controlled KoboToolbox ingestion pilot.
The maintained pack is based on synthetic fixtures and published KoboToolbox
documentation. The maintainers also ran the direct job with synthetic data on a
real KoboToolbox 2.026.37c server: a submission reached a direct BReg Proposal,
a distinct human Casework approval, and one applied record. An unchanged repeat
skipped, while an edit that reused the same source identity was held and did not
create a second registration. No run record is committed, so treat this as
unverified until your own pilot repeats it. It covers the direct job only; the
Coordinator flow has not completed an equivalent run.

All three jobs reuse the same pinned `kobotoolbox` provider pack and its
`kobo-submissions` source route.
Choose exactly one job and runtime pair for each form:

- `job.yaml` maps the declared projection through the job-owned,
  digest-pinned `mappings/register-household.rhai` (generated from
  `register-household.mapping.yaml`), then starts and submits a
  Base Registry Engine (BReg) Proposal directly. Its operator bindings are in
  `job-runtime.example.yaml`.
- `job.coordinator.yaml` signs the same projection for a named Coordinator
  workflow. Its operator bindings are in `job-runtime.coordinator.example.yaml`.
- `job.hook.yaml` runs the direct job from the same interval and may also be
  woken early by a Basic-authenticated Kobo webhook. Its operator bindings are
  in `job-runtime.hook.example.yaml`; [HOOKS.md](HOOKS.md) owns the ingress and
  TLS-proxy instructions.

Do not run more than one job against one form.
A destination refusal never falls back to the other job.
Use the direct job only when each submission maps to one BReg operation
without lookup or choice.
Use the Coordinator job when the workflow must resolve a target, choose an
operation, wait, or reach a person.

Use the Coordinator job for any form whose submissions are edited after they
are sent. The direct job holds every correction: an edit changes the
submission's revision, the Adapter holds the item with its earlier Proposal
reference, and nothing releases it, so BReg keeps the uncorrected value and the
held count grows. If supervisors routinely correct submissions in Kobo, choose
`job.coordinator.yaml` and let its workflow resolve the earlier record. Use the
direct job for forms that are submitted once and not edited.

## Editing the direct mapping

`mappings/register-household.mapping.yaml` is an `AdapterMapping` model and the
source of truth for the pinned `mappings/register-household.rhai`. The model
sits beside its generated script, inside the directory that owns the job
document, and paths in the model resolve against the model file. Its target
schema, `mappings/register-household-input.schema.json`, mirrors the `register-household`
Action input in [`../kobotoolbox-breg/registry.yaml`](../kobotoolbox-breg/registry.yaml).

| Source selection | Target | Rule |
| --- | --- | --- |
| `_id` | `sourceSubmissionId` | `convert: text`: a string stays as is, an integer becomes its decimal string |
| `respondent_name` | `respondentName` | Copy string |
| `"household.household_size"` | `householdSize` | `convert: integer`: an integer, or an integer string of 1 to 18 digits |

The ingestion target wraps the mapped input in the Proposal shape the job
expects: `#{startInput: #{input: ...}, submitBody: #{}}`. A missing or null
answer, an `_id` that is neither a string nor an integer, and a household size
that is not an integer or integer string all make the script throw. The
runtime maps any mapping failure to a refusal of that one item, with no value
in the message.

To change the mapping, edit the model, regenerate, lock, and check. To map a
new answer, also add its path to `projection.fields` in each job document; a
dotted path reaches the mapping as one literal key, which the model quotes
(`'"household.village"'`). If the Action input changes, update the target
schema mirror with it. Run the commands from the checkout root:

```sh
cargo run --locked -p registry-adapterctl -- mapping generate \
  products/adapter/examples/kobotoolbox-job/mappings/register-household.mapping.yaml
cargo run --locked -p registry-adapterctl -- job lock \
  products/adapter/examples/kobotoolbox-job/job.yaml
cargo run --locked -p registry-adapterctl -- job lock \
  products/adapter/examples/kobotoolbox-job/job.hook.yaml
KOBO_TOKEN=check cargo run --locked -p registry-adapterctl -- job check \
  products/adapter/packs/kobotoolbox/pack.yaml \
  products/adapter/examples/kobotoolbox-job/job.yaml \
  --runtime products/adapter/examples/kobotoolbox-job/job-runtime.example.yaml \
  --profile products/adapter/examples/kobotoolbox-job/profile.yaml \
  --project products/adapter/examples/kobotoolbox-job/project.yaml
```

`adapterctl job check` warns (`adapter.mapping.script-drift`) when the script no
longer matches its model, for example after a hand edit. Preview the mapping
offline over the projected items in `preview/`, each file one projection as the
job delivers it (an accepted string id, an accepted integer id with a numeric
string size, and a submission missing `respondent_name`):

```sh
cargo run --locked -p registry-adapterctl -- mapping preview \
  products/adapter/examples/kobotoolbox-job/mappings/register-household.mapping.yaml \
  --input products/adapter/examples/kobotoolbox-job/preview/accepted-string-id.json \
  --input products/adapter/examples/kobotoolbox-job/preview/accepted-integer-id.json \
  --input products/adapter/examples/kobotoolbox-job/preview/missing-respondent.json
```

The first two are accepted (`--format json` shows the destination input); the
third is refused with `mapping.missing respondentName`, naming the field and
never the value. Preview does not run the
job, a source, or a destination.

`preview/expected.yaml` records what each sample should give: the two accepted
ones, and `missing-respondent` refused at `respondentName`. Preview reads it
beside the samples, reports whether each result matched, and exits 1 when one
differs, so the deliberate refusal reads as refused as expected and a changed
mapping or sample fails the check (`products/adapter/scripts/check-contracts.sh`
runs it).

The generated script replaces a handwritten one that carried this note: the
mapping is example-only programme mapping. The Kobo provider pack stays
reusable, and this job-owned file maps the pack's declared projection into one
synthetic BReg Proposal Action input and is pinned by the job document.

The direct mapping is deliberately example-specific. Programme Action inputs
do not belong in the reusable Kobo provider pack, and changing the mapping
requires updating its digest in the job document, which `adapterctl job lock`
does in place.
Review the mapping, Action, access profile, projection, and destination
binding before a pilot. The BReg half of the direct journey (the `household`
record type, the `register-household` Action, the `ingestion` access profile
and the review policy) is the project in
[`../kobotoolbox-breg/`](../kobotoolbox-breg/README.md).

The projection presents selected dotted paths as literal dotted keys, so the
direct mapping reads `household.household_size` by that exact key. It converts
numeric or string submission IDs to the BReg string field, preserving opaque
string IDs, and converts Kobo's integer-string household-size answer to the
BReg `int64` field. Unsupported types and invalid integer strings refuse.

`adapter-job check` compiles each job from its authored file, the unchanged
provider pack, the local profile and project, and the matching runtime config.
It performs the source endpoint's credential preflight, using synthetic values
in the maintained contract check, but does not contact an endpoint or activate
either destination credential.

Follow the [KoboToolbox ingestion job operations runbook](OPERATIONS.md) to
initialize the store, preview one source page, run bounded passes, and inspect
outcomes.
