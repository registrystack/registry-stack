# Registry Config Report

Shared configuration diagnostic and explanation report contracts for Registry
products and local tooling.

This crate is intentionally thin. It owns versioned JSON Schemas, serde types,
canonical fixtures, report status vocabulary, required-environment
classification vocabulary, and classifier-driven redaction helpers. It does not
own product runtime config fields, product validation rules, bundle signature
verification, anti-rollback, emergency overrides, or config bundle verification
reports.

## Assets

- `schemas/registry.config.diagnostic_report.v1.schema.json` defines product
  diagnostic reports emitted by product validation commands.
- `schemas/registry.config.explanation.v1.schema.json` defines JSON config
  explanation output.
- `schemas/registryctl.validation.report.v1.schema.json` defines registryctl
  aggregate validation reports with embedded product diagnostics.
- `fixtures/diagnostics/*.json` are canonical product diagnostic fixtures.
- `fixtures/explanations/*.json` is the canonical config explanation fixture.
- `fixtures/registryctl/*.json` is the canonical registryctl aggregate fixture.
- `fixtures/invalid/*.json` are pinned negative schema fixtures used by contract
  tests.

## Schema Evolution Checklist

Before changing a schema version:

- add a migration note naming the old and new schema versions;
- update canonical passing fixtures and at least one invalid schema fixture;
- update consumer-side contract tests for every repo that consumes the schema;
- keep old schema constants available until every active consumer has migrated;
- record whether the first external release compatibility gate has been crossed.
