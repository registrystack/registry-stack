# Visual source-to-payload mapping

Status: proposed authoring feature; the transformation execution engine is implemented, while this editor and generator are not.

## Outcome and scope

An implementer selects a source and payload schema, connects fields in React Flow, previews a fixture, and exports the Rhai and project references already accepted by Adapter.
The same authoring model can produce Consultation data or Evidence facts, preserving the [existing host boundaries](CONSULTATION.md).
This increment requires no change to transformation execution semantics or deployed runtime formats.

## Existing foundation and remaining work

The Rust engine already compiles pinned project scripts, executes `entrypoint(source)` under resource limits, and validates its output against the pinned target schema.
Hosts retain source access, record identity, lookup classification, continuation, authorization and release policy.
Visually generated Rhai uses that same boundary as handwritten Rhai.

The authoring application still needs the React Flow editor, a saved mapping model, deterministic Rhai generation and a preview bridge invoking the existing Rust compile/apply API.
These are authoring and integration changes, not another execution engine or deployed transformation service.
The mapping model and generator must also be testable without the browser.

## Saved model and export

One versioned authoring document stores stable assignments, source/target schema references, field selectors, expressions and missing-value rules.
React Flow displays that model; layout and viewport preferences are stored separately.
Field paths and identifiers determine meaning; labels are presentation.
Save/reopen uses the model without reconstructing it from Rhai.
Existing handwritten transformations remain code-authored and are not automatically imported as editable graphs.

The generator produces ordinary Rhai and updates the existing script/schema inventory pins and binding references.
The saved model, source descriptions and field catalogue remain authoring inputs; this increment does not add them to the runtime artifact inventory or continuation digest.
The generated script, target schema and existing project/pack pins remain the governed executable result.
Changed authoring inputs trigger revalidation and regeneration; unchanged executable artifacts need not change runtime identity.
Generated-file conflicts and invalid exports preserve existing files rather than overwriting them.

## First editor slice

Render source and target trees with field handles, types, required fields, editable connections and static field-addressed errors.
Provide a keyboard-operable form for the same actions as dragging; collapsing and scrolling retain correct connections.

Support scalar copies and constants, nested target objects, exact keyed selection from a bounded array, explicit string-to-integer conversion, and canonical `YYYY-MM-DD` date validation.
The generator emits the corresponding Rhai expressions and checks; conversions do not guess formats.
Keyed selection requires one match and rejects duplicates.
Missing values fail by default; explicit omission is allowed only for optional target fields.
Required unmapped fields, conflicting assignments, invalid selectors and unsupported operations block export.

## Source descriptions and example

The editor needs a native source schema or reviewed descriptor, supplied from pack assets or selected project authoring metadata.
This is authoring information, separate from public API capability discovery.
The target is the project's payload schema, excluding protocol envelopes.
DHIS2 can additionally use a reviewed local catalogue of attribute UIDs, labels and types; automatic live discovery is deferred.
Display “Date of birth [Dob00000001]”, but persist the UID and exact keyed-array selector.
Removed identifiers and incompatible schema changes require explicit correction.

Use a documented synthetic fixture with these assignments and a separate private canary:

| Source selection | Target | Rule |
| --- | --- | --- |
| `orgUnit` | `organisationUnit` | Copy string |
| `updatedAt` | `lastChangedAt` | Copy string |
| `attributes[attribute = "Dob00000001"].value` | `dateOfBirth` | Exactly one match; validate date |

The closed target schema requires those strings, with `format: date` on `dateOfBirth`.
Attribute selection is generic keyed-array selection, with no DHIS2-specific engine operator.
A field mapping does not establish programme membership or enable API operations.

## Preview and deferred enhancements

The preview bridge supplies a local fixture to the existing Rust transformation API and shows its validated result or categorical, value-free failure.
Static authoring errors identify assignments; runtime failures use the diagnostics the engine currently provides.
Do not promise field-level runtime errors or uniform native input-schema validation in this increment.
Preview performs no source acquisition, credential resolution, signing or activation.

Richer runtime diagnostics, uniform native input validation and runtime coverage of authoring provenance are optional follow-ups, not editor prerequisites.
General loops, general conditions, arbitrary code nodes, XML/XSLT, handwritten-Rhai import and live-source preview are also outside this increment.

## Definition of done

1. A versioned model and deterministic generator work headlessly and emit artifacts accepted by the existing Rust API without new runtime formats.
2. Browser tests cover creation, reconnection, removal, save/reopen, keyboard interaction and stable field connections.
3. The example previews through Rust and proves nested targets, configured attribute selection and private-canary exclusion.
4. Tests cover missing/duplicate matches, invalid dates, conversions, required-field gaps and extra output using static or existing categorical errors as appropriate.
5. Authoring metadata changes require revalidation; layout changes leave executable artifacts unchanged and identifiers never silently retarget.
6. Generated mappings work for both Consultation and Evidence with their existing host boundaries.
7. UI and headless generation agree; export conflicts preserve existing files and handwritten projects still work.
8. Unit, integration and browser end-to-end tests and owning authoring checks pass; the example documents the supported subset and diagnostic limits.
