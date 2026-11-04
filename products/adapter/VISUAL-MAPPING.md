# Visual source-to-payload mapping

Status: the mapping format, its checks, the generator, the preview command and the drift warning are implemented in `adapterctl`; the Studio editor is not.

## Outcome and scope

An implementer selects a source and a target schema, connects fields, previews the result against fixtures, and exports the Rhai and project references Adapter already accepts.
One authoring model produces Consultation data, Evidence facts and ingestion destination inputs, preserving each [host boundary](CONSULTATION.md).
This increment requires no change to transformation execution semantics or deployed runtime formats.
It keeps [D32](CONCEPT.md#16-recorded-decisions): field mapping stays in scripts, and a generated script is an ordinary script.

## Ownership

This product owns the mapping format, its checks, the deterministic generator and the preview.
The pure model, checks and generator live in `registry-adapter-core`; `adapterctl` exposes check, generate and preview commands.
Generation writes the script and reports its digest.
`adapterctl project lock` updates project pins and binding references.
Job pins are updated by hand from the reported digest until a job lock command exists; this is current behaviour.
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
It stores stable assignments, source and target schema references, field selectors, closed operations and missing-value rules.
Selectors are queries written inline under CFG-EMBED-1; the model holds no code.
Field paths and identifiers determine meaning; labels are presentation.
Layout and viewport preferences are stored separately and never change an assignment.
Save and reopen use the model without reconstructing it from Rhai.
Existing handwritten transformations remain code-authored and are not imported as editable mappings.

The generator produces ordinary Rhai and reports its digest.
`adapterctl project lock` updates the existing script and schema pins and binding references of a project.
A job's mapping digest is edited by hand until a job lock command exists.
The saved model, source descriptions and field catalogue remain authoring inputs; they do not enter the runtime artifact inventory or continuation digest.
The generated script, target schema and existing project and pack pins remain the governed executable result.
Changed authoring inputs trigger revalidation and regeneration; unchanged executable artifacts keep their runtime identity.
Generation conflicts and invalid exports preserve existing files rather than overwriting them.
Layout rule: the model sits inside the directory tree of the document that owns the script, and paths in the model (`targetSchema`, `script`) resolve against the model file.
The generated header names the model relative to the script, so a model may sit beside its script in a subdirectory.

Each generated script begins with a header naming its model file and the model's digest.
When the script no longer matches its model, `adapterctl check` reports a warning naming both files, and Studio opens the script as code instead of as a mapping.
The author then regenerates, which discards the hand edits, or removes the whole generated header and keeps a handwritten script.
The marker on the header's first line is what makes a script generated, so a script without it is handwritten.
Generating over a script that another model produced, or over a handwritten script, is refused unless `--force` is passed.
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

The editor shows source and target as two trees joined by connector lines.
Each target row also shows its assignment as editable text, so the line and the text are two views of one assignment.
That text is the keyboard path: every action available by dragging is available by typing or from a menu on the row.
Collapsing a subtree routes its lines to the nearest visible ancestor; scrolling keeps lines attached to their rows.
Lines are drawn from the model; the mapper is not a free canvas, and diagram libraries are reserved for route and flow views.
The interaction follows Kaoto's DataMapper, whose generated XSLT step plays the role our generated Rhai plays; the patterns are borrowed and Kaoto's code is not embedded.

The first slice edits Consultation and Evidence read mappings.
The ingestion target and the write direction are proven headlessly through `adapterctl` in this increment.

Support scalar copies and constants, nested target objects, exact keyed selection from a bounded array, explicit string-to-integer and integer-to-string conversion, and canonical `YYYY-MM-DD` date validation.
The generator emits the corresponding Rhai expressions and checks; conversions do not guess formats.
Keyed selection requires one match and rejects duplicates.
Missing values fail by default; explicit omission is allowed only for optional target fields.
Required unmapped fields, conflicting assignments, invalid selectors and unsupported operations block export, with errors addressed to the assignment.

## Source descriptions and examples

The editor needs a native source schema or reviewed descriptor, supplied from pack assets or selected project authoring metadata.
This is authoring information, separate from public API capability discovery.
A draft field catalogue may be derived from a pack's captured fixtures or, for KoboToolbox and ODK Central, from the form definition.
A derived catalogue records field paths and types, never field values.
It is a draft a reviewer accepts and saves; it is never inferred at generation time.
DHIS2 can additionally use a reviewed local catalogue of attribute UIDs, labels and types; automatic live discovery is deferred.
Display “Date of birth [Dob00000001]”, but persist the UID and exact keyed-array selector.
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

Preview runs the generated script through the existing Rust transformation API and shows its validated result or categorical, value-free failure.
It runs on source items the author supplies, such as a documented synthetic fixture; pack fixtures hold upstream exchanges rather than source items, so for Consultation the end-to-end proof over them stays with `adapterctl fixtures replay`.
The ingestion target previews the operation input inside the destination shape; the write direction is generated and checked only.
Static authoring errors identify assignments; runtime failures use the diagnostics the engine currently provides.
Do not promise field-level runtime errors or uniform native input-schema validation in this increment.
For ingestion, preview validates the output against an authored mirror of the destination operation input, which is kept in sync with the operation by hand.
Preview performs no source acquisition, credential resolution, signing or activation.

Richer runtime diagnostics, uniform native input validation and runtime coverage of authoring provenance are optional follow-ups, not editor prerequisites.
General loops, general conditions, arbitrary code nodes, XML/XSLT, handwritten-Rhai import and live-source preview are also outside this increment.

## Definition of done

1. `AdapterMapping` is registered with a generated, drift-checked schema; the model, checks and generator run headlessly through `adapterctl` and emit artifacts accepted by the existing Rust API without new runtime formats.
2. Studio generates and previews only through the pinned `adapterctl`; no second generator exists.
3. Browser tests cover creation, reconnection, removal, save and reopen, keyboard editing through the assignment text, collapse and scroll, and stable field connections.
4. The DHIS2 read example previews through Rust and proves nested targets, configured attribute selection and private-canary exclusion.
5. The KoboToolbox ingestion example regenerates its mapping from a model, produces the destination input for accepted items, and refuses the missing-value item as an item-scoped refusal.
6. Tests cover missing and duplicate matches, invalid dates, conversions, required-field gaps and extra output using static or existing categorical errors as appropriate.
7. Authoring metadata changes require revalidation; layout changes leave executable artifacts unchanged; identifiers never silently retarget.
8. A hand-edited generated script produces the drift warning in `adapterctl check`, and Studio opens it as code; generation conflicts preserve existing files and handwritten projects still work.
9. Generated mappings work for Consultation, Evidence and the ingestion direct destination with their existing host boundaries; a write-direction model generates and checks headlessly.
10. Unit, integration and browser end-to-end tests and owning authoring checks pass; the examples document the supported subset and diagnostic limits.
