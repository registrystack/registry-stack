// SPDX-License-Identifier: Apache-2.0

//! A neutral registry that declares event records and the immediate
//! Actions that write them, shared by the PostgreSQL event record tests.
//!
//! The record types are `grant` (a subject whose status an Action changes),
//! `grant-pause-decision` (an event record with distinct decision and effective
//! dates and a correction link), `item` and `custody-record` (subjects), and
//! `custody-handover` (an event record with several subjects and an authored
//! unique source event).

pub const PACKAGE_ID: &str = "event-record-examples-registry";

pub const PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: event-record-examples-registry, version: "1", defaultLanguage: en, canonicalBaseIri: https://event-record-examples.example.test}
datasets: [{id: test-dataset}]
vocabularies:
  - {id: grant-status, values: [active, paused]}
  - {id: custody-status, values: [held, released]}
recordTypes:
  - id: grant
    primaryDataset: test-dataset
    route: grants
    mutationMode: mutable
    tombstone: true
    classification: restricted
    fields:
      - {id: grant-number, type: string, minimumLength: 1, maximumLength: 40, required: true, classification: restricted}
      - {id: status, type: vocabulary-code, vocabulary: grant-status, required: true, classification: restricted}
  - id: grant-pause-decision
    primaryDataset: test-dataset
    route: grant-pause-decisions
    mutationMode: create-only
    classification: restricted
    fields:
      - {id: grant, type: reference, target: grant, required: true, classification: restricted}
      - {id: decided-on, type: date, required: true, classification: restricted}
      - {id: effective-from, type: date, required: true, classification: restricted}
      - {id: effective-until, type: date, required: false, classification: restricted}
      - {id: basis-reference, type: string, maximumLength: 80, required: false, classification: restricted}
      - {id: corrects, type: reference, target: grant-pause-decision, required: false, classification: restricted}
    constraints:
      - {id: effective-order, type: compare, left: effective-from, operator: less-than, right: effective-until}
    eventRecord:
      label: Grant pause decided
      subjects:
        - {role: grant, field: grant, label: Grant, target: grant}
      occurredAt: {at: decided-on}
      effective: {start: effective-from, end: effective-until}
      sources:
        - {role: basis, field: basis-reference, label: Basis, external: {namespace: "urn:example:synthetic:notices"}}
      correction: {field: corrects, relation: corrects}
  - id: item
    primaryDataset: test-dataset
    route: items
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: item-number, type: string, minimumLength: 1, maximumLength: 40, required: true, classification: restricted}
  - id: custody-record
    primaryDataset: test-dataset
    route: custody-records
    mutationMode: mutable
    tombstone: true
    classification: restricted
    fields:
      - {id: holder-reference, type: string, minimumLength: 1, maximumLength: 80, required: true, classification: restricted}
      - {id: status, type: vocabulary-code, vocabulary: custody-status, required: true, classification: restricted}
  - id: custody-handover
    primaryDataset: test-dataset
    route: custody-handovers
    mutationMode: create-only
    classification: restricted
    fields:
      - {id: item, type: reference, target: item, required: true, classification: restricted}
      - {id: previous-custody, type: reference, target: custody-record, required: true, classification: restricted}
      - {id: new-custody, type: reference, target: custody-record, required: true, classification: restricted}
      - {id: agreed-not-before, type: date, required: false, classification: restricted}
      - {id: agreed-before, type: date, required: false, classification: restricted}
      - {id: effective-at, type: timestamp, required: true, classification: restricted}
      - {id: deed-reference, type: string, minimumLength: 1, maximumLength: 80, required: true, classification: restricted}
    constraints:
      - {id: one-per-deed, type: unique, fields: [deed-reference]}
    eventRecord:
      label: Custody handed over
      subjects:
        - {role: item, field: item, label: Item, target: item}
        - {role: previous-custody, field: previous-custody, label: Previous custody, target: custody-record}
        - {role: new-custody, field: new-custody, label: New custody, target: custody-record}
      occurredAt: {start: agreed-not-before, end: agreed-before, meaning: within}
      effective: {at: effective-at}
      sources:
        - {role: deed, field: deed-reference, label: Deed, external: {namespace: "urn:example:synthetic:deeds"}}
      sourceEventId:
        field: deed-reference
        namespace: "urn:example:synthetic:deeds"
        duplicates: reject
        constraint: one-per-deed
actions:
  - id: open-grant
    execution: {mode: immediate}
    inputs:
      - {id: grant-number, apiName: grantNumber, type: string, minimumLength: 1, maximumLength: 40, required: true, classification: restricted}
    plan:
      type: fixed
      effects:
        - id: opened
          target: {recordType: grant}
          operation: create
          set:
            grant-number: {fromInput: grant-number}
            status: {value: active}
  - id: open-item
    execution: {mode: immediate}
    inputs:
      - {id: item-number, apiName: itemNumber, type: string, minimumLength: 1, maximumLength: 40, required: true, classification: restricted}
    plan:
      type: fixed
      effects:
        - id: opened
          target: {recordType: item}
          operation: create
          set:
            item-number: {fromInput: item-number}
  - id: open-custody
    execution: {mode: immediate}
    inputs:
      - {id: holder-reference, apiName: holderReference, type: string, minimumLength: 1, maximumLength: 80, required: true, classification: restricted}
    plan:
      type: fixed
      effects:
        - id: opened
          target: {recordType: custody-record}
          operation: create
          set:
            holder-reference: {fromInput: holder-reference}
            status: {value: held}
  - id: pause-grant
    execution: {mode: immediate}
    inputs:
      - {id: grant, apiName: grantId, type: reference, target: grant, required: true, classification: restricted}
      - {id: decided-on, apiName: decidedOn, type: date, required: true, classification: restricted}
      - {id: effective-from, apiName: effectiveFrom, type: date, required: true, classification: restricted}
    commitGuards:
      targets: [{input: grant, field: status, equals: active, reason: grant-not-active}]
    plan:
      type: fixed
      effects:
        - id: status-change
          target: {fromInput: grant}
          operation: patch
          set:
            status: {value: paused}
        - id: decision
          target: {recordType: grant-pause-decision}
          operation: create
          set:
            grant: {fromInput: grant}
            decided-on: {fromInput: decided-on}
            effective-from: {fromInput: effective-from}
  - id: record-grant-pause
    execution: {mode: immediate}
    inputs:
      - {id: grant, apiName: grantId, type: reference, target: grant, required: true, classification: restricted}
      - {id: decided-on, apiName: decidedOn, type: date, required: true, classification: restricted}
      - {id: effective-from, apiName: effectiveFrom, type: date, required: true, classification: restricted}
      - {id: effective-until, apiName: effectiveUntil, type: date, required: false, classification: restricted}
    commitGuards:
      targets: [{input: grant, field: status, equals: active, reason: grant-not-active}]
    plan:
      type: fixed
      effects:
        - id: decision
          target: {recordType: grant-pause-decision}
          operation: create
          set:
            grant: {fromInput: grant}
            decided-on: {fromInput: decided-on}
            effective-from: {fromInput: effective-from}
            effective-until: {fromInput: effective-until}
  - id: correct-grant-pause
    execution: {mode: immediate}
    inputs:
      - {id: grant, apiName: grantId, type: reference, target: grant, required: true, classification: restricted}
      - {id: original, apiName: originalDecisionId, type: reference, target: grant-pause-decision, required: true, classification: restricted}
      - {id: decided-on, apiName: decidedOn, type: date, required: true, classification: restricted}
      - {id: effective-from, apiName: effectiveFrom, type: date, required: true, classification: restricted}
    commitGuards:
      targets: [{input: original, field: grant, equalsFromInput: grant, reason: wrong-grant}]
    plan:
      type: fixed
      effects:
        - id: correction
          target: {recordType: grant-pause-decision}
          operation: create
          set:
            grant: {fromInput: grant}
            decided-on: {fromInput: decided-on}
            effective-from: {fromInput: effective-from}
            corrects: {fromInput: original}
  - id: hand-over-custody
    execution: {mode: immediate}
    inputs:
      - {id: item, apiName: itemId, type: reference, target: item, required: true, classification: restricted}
      - {id: previous-custody, apiName: previousCustodyId, type: reference, target: custody-record, required: true, classification: restricted}
      - {id: new-holder, apiName: newHolder, type: string, minimumLength: 1, maximumLength: 80, required: true, classification: restricted}
      - {id: deed-reference, apiName: deedReference, type: string, minimumLength: 1, maximumLength: 80, required: true, classification: restricted}
      - {id: effective-at, apiName: effectiveAt, type: timestamp, required: true, classification: restricted}
    commitGuards:
      targets: [{input: previous-custody, field: status, equals: held, reason: custody-not-held}]
    plan:
      type: fixed
      effects:
        - id: new-custody
          target: {recordType: custody-record}
          operation: create
          set:
            holder-reference: {fromInput: new-holder}
            status: {value: held}
        - id: release
          target: {fromInput: previous-custody}
          operation: patch
          set:
            status: {value: released}
        - id: handover
          target: {recordType: custody-handover}
          operation: create
          set:
            item: {fromInput: item}
            previous-custody: {fromInput: previous-custody}
            new-custody: {fromEffect: new-custody}
            effective-at: {fromInput: effective-at}
            deed-reference: {fromInput: deed-reference}
accessProfiles:
  - id: registrar
    default: true
    principalClaim: registry_principal
    requiredScopes: unrestricted
    permissions:
      records:
        - {recordType: grant, operations: [get, list], readableFields: [grant-number, status], rowBoundaries: unrestricted}
        - {recordType: grant-pause-decision, operations: [get, list], readableFields: [grant, decided-on, effective-from, effective-until, basis-reference, corrects], rowBoundaries: unrestricted}
        - {recordType: custody-record, operations: [get, list], readableFields: [holder-reference, status], rowBoundaries: unrestricted}
        - {recordType: custody-handover, operations: [get, list], readableFields: [item, previous-custody, new-custody, agreed-not-before, agreed-before, effective-at, deed-reference], rowBoundaries: unrestricted}
      actions:
        - {action: open-grant, operations: [invoke], targets: [{recordType: grant, rowBoundaries: unrestricted}], results: [opened]}
        - {action: open-item, operations: [invoke], targets: [{recordType: item, rowBoundaries: unrestricted}], results: [opened]}
        - {action: open-custody, operations: [invoke], targets: [{recordType: custody-record, rowBoundaries: unrestricted}], results: [opened]}
        - action: pause-grant
          operations: [invoke]
          targets: [{recordType: grant, rowBoundaries: unrestricted}, {recordType: grant-pause-decision, rowBoundaries: unrestricted}]
          results: [status-change, decision]
        - action: record-grant-pause
          operations: [invoke]
          targets: [{recordType: grant, rowBoundaries: unrestricted}, {recordType: grant-pause-decision, rowBoundaries: unrestricted}]
          results: [decision]
        - action: correct-grant-pause
          operations: [invoke]
          targets: [{recordType: grant, rowBoundaries: unrestricted}, {recordType: grant-pause-decision, rowBoundaries: unrestricted}]
          results: [correction]
        - action: hand-over-custody
          operations: [invoke]
          targets: [{recordType: item, rowBoundaries: unrestricted}, {recordType: custody-record, rowBoundaries: unrestricted}, {recordType: custody-handover, rowBoundaries: unrestricted}]
          results: [new-custody, release, handover]
  - id: event-record-history
    principalClaim: registry_principal
    requiredScopes: unrestricted
    permissions:
      records:
        - {recordType: grant-pause-decision, operations: [revisions, snapshot], revisionAccess: true, readableFields: [grant, decided-on, effective-from, effective-until, corrects], rowBoundaries: unrestricted}
        - {recordType: custody-handover, operations: [revisions, snapshot], revisionAccess: true, readableFields: [item, previous-custody, new-custody, effective-at, deed-reference], rowBoundaries: unrestricted}
"#;

pub fn compiled() -> registry_breg::CompiledRegistry {
    let project = registry_breg::contract::parse_project_yaml(PROJECT.as_bytes())
        .expect("event record examples project parses");
    registry_breg::compiler::compile_project(
        &project,
        &[],
        registry_breg::compiler::CompileProfile::Authoring,
    )
    .expect("event record examples project compiles")
}
