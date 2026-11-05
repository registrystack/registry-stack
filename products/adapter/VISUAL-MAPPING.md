# Visual source-to-payload mapping

Status: the mapping format, its checks, the generator, the preview command and the drift warning are implemented in `adapterctl`; the Studio editor is not.

## Outcome and scope

An implementer selects a source and a target schema, fills each target field from the source, previews the result against fixtures, and exports the Rhai and project references Adapter already accepts.
One authoring model produces Consultation data, Evidence facts and ingestion destination inputs, preserving each [host boundary](CONSULTATION.md).
This increment requires no change to transformation execution semantics or deployed runtime formats.
It keeps [D32](CONCEPT.md#16-recorded-decisions): field mapping stays in scripts, and a generated script is an ordinary script.

## Ownership

This product owns the mapping format, its checks, the deterministic generator and the preview.
The pure model, checks and generator live in `registry-adapter-core`; `adapterctl` exposes check, generate and preview commands.
Generation writes the script and reports its digest.
`adapterctl project lock` updates project pins and binding references.
`adapterctl job lock` updates a job's mapping digest pin (and, with `--pack`, its pack pin) in place.
There is exactly one generator.
Registry Studio owns the editor and calls a pinned `adapterctl` for generation, checking and preview, as it already calls a pinned `coordinatorctl`.
An implementer or an agent without Studio authors the same file and runs the same commands.

## Existing foundation and remaining work

The Rust engine already compiles pinned project scripts, executes the transformation entrypoint under resource limits, and validates its output against the pinned target schema.
Hosts retain source access, record identity, lookup classification, continuation, authorization and release policy.
Generated Rhai uses that same boundary as handwritten Rhai.

The remaining work is the Studio editor.
These are authoring and integration changes, not another execution engine or deployed transformation service.

## Saved model and export

The saved model is an authored format, `AdapterMapping`, registered in `products/platform/config-formats.yaml` and read under [the configuration conventions](../platform/CONFIG-CONVENTIONS.md): envelope, closed generated schema, offline check and `adapter.*` diagnostics.
It stores the target schema reference and, for each target field, a source selector or constant, a closed operation and a missing-value rule; it stores no source schema.
Selectors are queries written inline under CFG-EMBED-1; the model holds no code.
Field paths and identifiers determine meaning; labels are presentation.
Save and reopen use the model without reconstructing it from Rhai.
Existing handwritten transformations remain code-authored and are not imported as editable mappings.

The generator produces ordinary Rhai and reports its digest.
`adapterctl project lock` updates the existing script and schema pins and binding references of a project.
`adapterctl job lock` rewrites a job's mapping digest from the generated script's bytes.
The saved model, source descriptions and field catalogue remain authoring inputs; they do not enter the runtime artifact inventory.
The generated script, target schema and existing project and pack pins remain the governed executable result.
The script's header records the digest of the model's parsed content, so any change to what the model says changes the script and its pin; a layout-only edit (comments, a byte order mark, line endings, document markers) does not.
Generation conflicts and invalid exports preserve existing files rather than overwriting them.
Layout rule: the model sits inside the directory tree of the document that owns the script, and paths in the model (`targetSchema`, `script`) resolve against the model file.
The generated header names the model relative to the script, so a model may sit beside its script in a subdirectory.

Each generated script begins with a header naming its model file and the model's digest.
When the script no longer matches its model, `adapterctl check` reports a warning naming both files, and Studio shows the mapping read-only with a notice and one action, Replace hand edits with this mapping.
The author then regenerates, which discards the hand edits, or removes the whole generated header and keeps a handwritten script; keeping a handwritten script is a command-line choice that Studio does not offer.
The marker on the header's first line is what makes a script generated, so a script without it is handwritten.
Generating over a script that another model produced, or over a handwritten script, is refused unless `--force` is passed.
The check covers the scripts a project inventories, the scripts a pack inventories (the model must then lie inside the pack's directory) and, in `adapterctl job check`, the job's direct destination mapping and its pack's scripts.
From the model's side, `adapterctl mapping check` warns when the script at `mapping.script` is not what the model generates now, including when that script is handwritten or another model's; a missing script is not a finding.
This is a warning, not a blocking check: a handwritten script is a supported state, and the warning only makes the divergence visible.

## Targets

The format covers three targets from its first version:

| Host | Source | Target |
| --- | --- | --- |
| Consultation | One source item from a pack read route | The project's data schema, excluding protocol envelopes |
| Evidence | Matched native facts | The Evidence Source's facts schema |
| Ingestion direct destination | One source item | The destination BReg operation's input, or an item-scoped refusal |

For the ingestion target the generator wraps the mapped input in the job's destination shape (for a Proposal, `startInput` and `submitBody`), as the [KoboToolbox job example](examples/kobotoolbox-job/mappings/register-household.rhai) does; that script is generated from its model and is no longer written by hand.
A failed required value, conversion or validation becomes an item-scoped refusal under the profile's mapping problem, never a deployment-level stop ([section 17.3](CONCEPT.md#173-the-pass-the-two-destinations-and-mapping)).
Mapping for a Coordinator event destination runs in a Coordinator Function and is outside this format.

The write direction, a record mapped to a source request body such as the DHIS2 pack's `to-bundle.rhai`, uses the same model with the source request schema as the target.
The format must express it; editor support follows the first slice.

## First editor slice

The editor is a table of the target's fields, one row per field: the field, where its value comes from, and its rule.
Required fields that are not set yet are what is left to do.
A row changes in Studio's side panel: the source (an answer seen in the samples or already mapped, or a fixed value), the rule (As is, Text, Whole number, Date) and, for optional fields only, whether a missing answer refuses the item or leaves the field out.
The rule defaults from the target field's type.
The screen shows field names, not selector text; selectors, the entrypoint and digests sit under Technical details.
Below the fields, a Samples table lists the preview inputs beside the model with their result, Accepted or Refused with the field that refused, and Add sample adds one JSON item.
These are existing Studio parts (data table, side panel, notice, Technical details); the editor needs no new UI part.

The editor has no connector lines, two-tree layout, drag and drop or free-form assignment text; developers and agents edit the YAML model.
What it borrows from Kaoto's DataMapper is the split between a saved model and the artifact generated from it, whose generated XSLT step plays the role our generated Rhai plays; Kaoto's code is not embedded.

The first slice edits the ingestion direct destination, starting with the KoboToolbox job; Consultation follows, then Evidence.
Keyed selections, such as DHIS2 attributes, show read-only until a DHIS2 slice brings the reviewed attribute catalogue.
The write direction stays headless.

The format supports scalar copies and constants, nested target objects, exact keyed selection from a bounded array, explicit string-to-integer and integer-to-string conversion, and canonical `YYYY-MM-DD` date validation.
The generator emits the corresponding Rhai expressions and checks; conversions do not guess formats.
Keyed selection requires one match and rejects duplicates.
Missing values fail by default; explicit omission is allowed only for optional target fields.
Required unmapped fields, conflicting assignments, invalid selectors and unsupported operations block export, with errors addressed to the assignment.

## Source descriptions and examples

The editor lists source fields from the sample items beside the model and from the model's existing selectors; it reads no source schema and infers nothing at generation time.
A new answer appears once a sample carries it.
For an ingestion job, the job's `projection.fields` must also name the answer, and a dotted path reaches the mapping as one literal key, which the model quotes (`'"household.village"'`).
A field catalogue derived from fixtures or form definitions, and a reviewed DHIS2 catalogue of attribute UIDs, labels and types, are later work; the DHIS2 slice displays “Date of birth [Dob00000001]” but persists the UID and exact keyed-array selector.
Removed identifiers and incompatible schema changes require explicit correction.

The read example uses a documented synthetic fixture with these assignments and a separate private canary:

| Source selection | Target | Rule |
| --- | --- | --- |
| `orgUnit` | `registration.organisationUnit` | Copy string |
| `updatedAt` | `registration.lastChangedAt` | Copy string |
| `attributes[attribute = "Dob00000001"].value` | `person.dateOfBirth` | Exactly one match; validate date |

The closed target schema requires those strings, with `format: date` on `dateOfBirth`.
Attribute selection is generic keyed-array selection, with no DHIS2-specific engine operator.
A field mapping does not establish programme membership or enable API operations.

The ingestion example regenerates the KoboToolbox job's `register-household` mapping from a model: a copied submission identifier, a top-level answer, an answer inside a group with explicit string-to-integer conversion, and one preview input refused for a missing required value.
That refused item is a preview input and a job seam test, not a pack fixture.

## Preview and deferred enhancements

Preview runs the generated script through the existing Rust transformation API and shows its validated result or a value-free refusal.
It runs on source items the author supplies, such as a documented synthetic fixture; pack fixtures hold upstream exchanges rather than source items, so for Consultation the end-to-end proof over them stays with `adapterctl fixtures replay`.
The ingestion target previews the operation input inside the destination shape; the write direction is generated and checked only.
Static authoring errors identify assignments.
For a generated script, a refusal names the target field and the reason (`mapping.missing`, `mapping.duplicate` or `mapping.conversion`), never the value; preview accepts the thrown text only when it matches the generator's own shape for a field of this model, and the runtime refusal stays categorical.
`mapping check` and `generate` apply the same compile acceptance as the runtime, so a target schema the runtime would refuse (`adapterctl.mapping-schema-not-public`) fails before preview.
Uniform native input-schema validation is not in this increment.
For ingestion, preview validates the output against an authored mirror of the destination operation input, which is kept in sync with the operation by hand.
Preview performs no source acquisition, credential resolution, signing or activation.

Richer runtime diagnostics, uniform native input validation and runtime coverage of authoring provenance are optional follow-ups, not editor prerequisites.
General loops, general conditions, arbitrary code nodes, XML/XSLT, handwritten-Rhai import and live-source preview are also outside this increment.

## Definition of done

1. `AdapterMapping` is registered with a generated, drift-checked schema; the model, checks and generator run headlessly through `adapterctl` and emit artifacts accepted by the existing Rust API without new runtime formats.
2. Studio generates and previews only through the pinned `adapterctl`; no second generator exists.
3. Browser tests cover setting, changing and clearing a field's source and rule from the keyboard, save and reopen, a refused sample that names its field, and the read-only state of a hand-edited script.
4. The DHIS2 read example previews through Rust and proves nested targets, configured attribute selection and private-canary exclusion.
5. The KoboToolbox ingestion example regenerates its mapping from a model, produces the destination input for accepted items, and refuses the missing-value item as an item-scoped refusal.
6. Tests cover missing and duplicate matches, invalid dates, conversions, required-field gaps and extra output, with static errors or the named preview refusals as appropriate.
7. Authoring changes require revalidation and regeneration; identifiers never silently retarget.
8. A hand-edited generated script produces the drift warning in `adapterctl check`, and Studio shows it read-only with one replace action; generation conflicts preserve existing files and handwritten projects still work.
9. Generated mappings work for Consultation, Evidence and the ingestion direct destination with their existing host boundaries; a write-direction model generates and checks headlessly.
10. Unit, integration and browser end-to-end tests and owning authoring checks pass; the examples document the supported subset and diagnostic limits.
