// SPDX-License-Identifier: Apache-2.0
//! Navigation edges in the Discovery, Manifest, Render, and wallet-delivery contracts.
//! These rules describe authored names and local files, never remote resources or credentials.

use super::spec::{DocumentRules, FileRule, NameRule, ProductKind, ProductSpec, Scope};

pub(super) fn spec(product: ProductKind) -> Option<ProductSpec> {
    let (marker, discriminator, version_prefix, kind, documents) = match product {
        ProductKind::Discovery => (
            "origins.yaml",
            "schemaVersion",
            "registry-discovery/origins/",
            "",
            DISCOVERY,
        ),
        ProductKind::Manifest => (
            "metadata.yaml",
            "schema_version",
            "registry-manifest/v1",
            "",
            MANIFEST,
        ),
        ProductKind::Render => (
            "manifest.yaml",
            "apiVersion",
            "id.registrystack.org/formats/render/bundle/",
            "RenderBundle",
            RENDER,
        ),
        // Delivery has no product discriminator. It requires explicit editor setup so an ordinary
        // version: 1 YAML document can never cause this family to claim a directory.
        ProductKind::EvidenceOid4vci => ("", "", "", "", OID4VCI),
        _ => return None,
    };
    Some(ProductSpec {
        product,
        marker,
        discriminator,
        version_prefix,
        kind,
        documents,
    })
}

// Discovery's evidence type and requirement identifiers name externally published vocabulary.
// They are visible symbols, but they are not unresolved local references and are never fetched.
const DISCOVERY: &[DocumentRules] = &[
    DocumentRules {
        pattern: "@document",
        declarations: &[NameRule::global("origins/*/originId", "origin")],
        references: &[],
        files: &[],
    },
    DocumentRules {
        pattern: "mappings/*",
        declarations: &[
            NameRule::global("mappingId", "mapping"),
            // The same requirement can have a mapping in each jurisdiction. Document scoping
            // prevents those independent mappings from looking like duplicate declarations.
            NameRule {
                path: "requirementId",
                kind: "requirement",
                scope: Scope::Document,
                suffix: None,
                reports_unresolved: true,
                ignored_when_present: None,
                only_when: None,
            },
            NameRule {
                path: "alternatives/*/evidenceTypeListId",
                kind: "evidence-type-list",
                scope: Scope::Document,
                suffix: None,
                reports_unresolved: true,
                ignored_when_present: None,
                only_when: None,
            },
        ],
        references: &[],
        files: &[],
    },
];

// Source: registry-manifest-core's MetadataManifest and validate_* cross-reference checks.
// Field names belong to an entity inside a dataset, not to the entire metadata document.
const MANIFEST: &[DocumentRules] = &[DocumentRules {
    pattern: "@document",
    declarations: &[
        NameRule::global("catalog/id", "catalog"),
        NameRule::global("vocabularies/$key", "vocabulary"),
        NameRule::global("evaluation_profiles/*/id", "evaluation-profile"),
        NameRule::global("evaluation_profiles/*/ruleset", "evaluation-ruleset"),
        NameRule::global("requirements/*/id", "requirement"),
        NameRule::scoped(
            "requirements/*/evidence_type_lists/*/id",
            "evidence-type-list",
            1,
            "id",
        ),
        NameRule::global("evidence_types/*/id", "evidence-type"),
        NameRule::global("authorities/*/id", "authority"),
        NameRule::global("public_services/*/id", "public-service"),
        NameRule::scoped("public_services/*/channels/*/id", "channel", 1, "id"),
        NameRule::global("data_services/*/id", "data-service"),
        NameRule::global("distributions/*/id", "distribution"),
        NameRule::global("forms/*/id", "form"),
        NameRule::scoped("forms/*/sections/*/id", "form-section", 1, "id"),
        NameRule::scoped("forms/*/fields/*/id", "form-field", 1, "id"),
        NameRule::scoped("forms/*/sections/*/fields/*/id", "form-field", 3, "id"),
        NameRule::global("datasets/*/id", "dataset"),
        NameRule::scoped("datasets/*/entities/*/name", "entity", 0, "id"),
        NameRule {
            path: "datasets/*/entities/*/fields/*/name",
            kind: "field",
            scope: Scope::Composite(&[(0, "id"), (1, "name")]),
            suffix: None,
            reports_unresolved: true,
            ignored_when_present: None,
            only_when: None,
        },
        NameRule {
            path: "datasets/*/entities/*/relationships/*/name",
            kind: "relationship",
            scope: Scope::Composite(&[(0, "id"), (1, "name")]),
            suffix: None,
            reports_unresolved: true,
            ignored_when_present: None,
            only_when: None,
        },
        NameRule::global("datasets/*/evidence_offerings/*/id", "evidence-offering"),
        NameRule::global("codelists/*/id", "codelist"),
        NameRule::scoped("codelists/*/concepts/*/code", "code", 0, "id"),
    ],
    references: &[
        NameRule::global("evidence_types/*/proves/*", "requirement"),
        NameRule::global(
            "requirements/*/evidence_type_lists/*/evidence_types/*",
            "evidence-type",
        ),
        NameRule::global("public_services/*/competent_authority", "authority"),
        NameRule::global("public_services/*/holds_requirements/*", "requirement"),
        NameRule::global("public_services/*/produces/*", "dataset"),
        NameRule::global("public_services/*/data_services/*", "data-service"),
        NameRule::global("public_services/*/forms/*", "form"),
        NameRule::global("data_services/*/serves_datasets/*", "dataset"),
        NameRule::global("distributions/*/dataset", "dataset"),
        NameRule::global("distributions/*/access_service", "data-service"),
        NameRule::global("forms/*/service", "public-service"),
        NameRule::scoped("forms/*/channel", "channel", 0, "service"),
        NameRule::global("forms/*/fields/*/supports_requirement", "requirement"),
        NameRule::global(
            "forms/*/sections/*/fields/*/supports_requirement",
            "requirement",
        ),
        NameRule::scoped("forms/*/fields/*/visible_when/field", "form-field", 2, "id"),
        NameRule::scoped(
            "forms/*/sections/*/visible_when/field",
            "form-field",
            2,
            "id",
        ),
        NameRule::scoped(
            "forms/*/sections/*/fields/*/visible_when/field",
            "form-field",
            4,
            "id",
        ),
        NameRule::global("datasets/*/entities/*/fields/*/codelist", "codelist"),
        NameRule {
            path: "datasets/*/entities/*/identifiers/*/name",
            kind: "field",
            scope: Scope::Composite(&[(0, "id"), (1, "name")]),
            suffix: None,
            reports_unresolved: true,
            ignored_when_present: None,
            only_when: None,
        },
        NameRule::scoped(
            "datasets/*/entities/*/relationships/*/target_entity",
            "entity",
            0,
            "id",
        ),
        NameRule {
            ignored_when_present: Some("target_entity"),
            ..NameRule::scoped(
                "datasets/*/entities/*/relationships/*/target",
                "entity",
                0,
                "id",
            )
        },
        NameRule::global(
            "datasets/*/evidence_offerings/*/evidence_type",
            "evidence-type",
        ),
        NameRule {
            only_when: Some(("kind", "registry-evidence")),
            ..NameRule::global(
                "datasets/*/evidence_offerings/*/access/ruleset",
                "evaluation-ruleset",
            )
        },
        NameRule::scoped("datasets/*/evidence_offerings/*/entity", "entity", 1, "id"),
        NameRule {
            path: "datasets/*/evidence_offerings/*/lookup_keys/*",
            kind: "field",
            scope: Scope::Composite(&[(2, "id"), (0, "entity")]),
            suffix: None,
            reports_unresolved: true,
            ignored_when_present: None,
            only_when: None,
        },
    ],
    files: &[],
}];

// Source: registry-render::manifest::DocumentSpec and Bundle's labels/<locale>.yaml resolution.
// Templates, JSON schemas, and label tables are navigation targets. They are not parsed as product
// manifests, and neither Typst includes nor external assets are executed or fetched by the editor.
const RENDER: &[DocumentRules] = &[DocumentRules {
    pattern: "@document",
    declarations: &[NameRule::global("documents/*/id", "document")],
    references: &[],
    files: &[
        FileRule::root("documents/*/entryFile", false),
        FileRule::root("documents/*/schemaFile", false),
        FileRule {
            path: "documents/*/labels/*",
            prefix: "labels/",
            suffix: ".yaml",
            relative_to_document: false,
            index_target: false,
        },
    ],
}];

// A delivery runtime names its client key by secret reference, resolved by the configured secret
// provider when the service starts, so no member is a navigable file and key bytes never enter
// the index.
const OID4VCI: &[DocumentRules] = &[DocumentRules {
    pattern: "@document",
    declarations: &[NameRule::global("$key", "configuration-section")],
    references: &[],
    files: &[],
}];
