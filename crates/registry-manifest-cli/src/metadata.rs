// SPDX-License-Identifier: Apache-2.0
//! Reading a metadata manifest (`manifest/metadata`) through the shared
//! reader, then the rules `validate_manifest` applies, each placed at the
//! member it names.

use std::{collections::BTreeMap, path::Path};

use registry_manifest_core::{
    is_runtime_only_key, is_secret_bearing_key, source_manifest_digest, validate_manifest,
    LocalizedText, MetadataError, MetadataManifest, MetadataManifestFields, ValidationCondition,
};
use registry_platform_yaml::{
    duplicate_display_text_diagnostics, duplicate_display_text_location_diagnostics,
    escape_pointer_segment, local_id_collision_diagnostics, AuthoredDisplayText,
    AuthoredDisplayTextLocation, AuthoredId, Diagnostic, Document, Expect, LocalId, Node,
    NodeValue, Reader, Report, Severity,
};

use crate::{contents, Contents, Findings, METADATA_FORMAT, METADATA_SCHEMA_VERSION};

const RUNTIME_ONLY_MESSAGE: &str =
    "this key configures a running service, and a metadata manifest describes data portably \
     without runtime configuration";
const RUNTIME_ONLY_ACTION: &str =
    "Remove the member, and keep it in the runtime configuration of the service that uses it.";
const SECRET_BEARING_MESSAGE: &str =
    "this key names a credential or secret, which a metadata manifest never carries";
const SECRET_BEARING_ACTION: &str =
    "Remove the member, and keep the credential in the secret provider of the service that \
     uses it.";

/// A metadata manifest the reader and `validate_manifest` accepted, with
/// the document its findings are placed in.
pub struct ReadManifest {
    pub manifest: MetadataManifest,
    pub document: Document,
}

/// Read a metadata manifest. `file` is the name every diagnostic carries.
///
/// The reader refuses `${...}` (CFG-SEC-2), YAML anchors and aliases,
/// unknown and duplicate keys, and nulls. A runtime-only or secret-bearing
/// key is refused at the key, wherever it is written, before the manifest
/// is decoded; every rule `validate_manifest` applies is then reported at
/// the member it names. Warnings travel in the document.
pub fn read_metadata(file: &str, bytes: &[u8]) -> Result<ReadManifest, Vec<Diagnostic>> {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let mut document = Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::one(&METADATA_FORMAT))
        .map_err(Report::into_diagnostics)?;
    let mut refused = Vec::new();
    if let Some(entry) = document.root().get("schema_version") {
        let current = matches!(
            &entry.value.value,
            NodeValue::String(text) if text.text == METADATA_SCHEMA_VERSION
        );
        if !current {
            refused.push(unsupported_version(&document));
        }
    }
    if refused.is_empty() {
        refused_keys(&document, document.root(), "", &mut refused);
    }
    if !refused.is_empty() {
        let mut diagnostics = document.warnings().into_diagnostics();
        diagnostics.extend(refused);
        return Err(diagnostics);
    }
    let fields = document
        .decode::<MetadataManifestFields>()
        .map_err(Report::into_diagnostics)?;
    let manifest = MetadataManifest::from(fields);
    let validation = validate_manifest(&manifest);
    let integrity_errors = manifest_integrity_diagnostics(&manifest, &mut document);
    if validation.is_err() || !integrity_errors.is_empty() {
        let mut diagnostics = document.warnings().into_diagnostics();
        if let Err(error) = validation {
            diagnostics.extend(metadata_error_diagnostics(&document, error));
        }
        diagnostics.extend(integrity_errors);
        return Err(diagnostics);
    }
    Ok(ReadManifest { manifest, document })
}

fn manifest_integrity_diagnostics(
    manifest: &MetadataManifest,
    document: &mut Document,
) -> Vec<Diagnostic> {
    fn collisions(document: &Document, code: &str, values: &[(String, String)]) -> Vec<Diagnostic> {
        let entries = values
            .iter()
            .map(|(id, pointer)| AuthoredId { id, pointer })
            .collect::<Vec<_>>();
        local_id_collision_diagnostics(document, code, &entries)
    }
    fn list_ids<'a>(
        base: &str,
        values: impl IntoIterator<Item = &'a str>,
    ) -> Vec<(String, String)> {
        values
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id.to_owned(), format!("{base}/{index}/id")))
            .collect()
    }
    fn localized_warnings<'a>(
        document: &Document,
        code: &str,
        kind: &str,
        values: impl IntoIterator<Item = (&'a str, &'a LocalizedText, String)>,
    ) -> Vec<Diagnostic> {
        let mut by_language = BTreeMap::<String, Vec<(String, String, String)>>::new();
        for (id, text, pointer) in values {
            match text {
                LocalizedText::Plain(text) => by_language
                    .entry("en".to_owned())
                    .or_default()
                    .push((id.to_owned(), text.clone(), pointer)),
                LocalizedText::Localized(texts) => {
                    for (language, text) in texts {
                        by_language.entry(language.clone()).or_default().push((
                            id.to_owned(),
                            text.clone(),
                            format!("{pointer}/{}", escape_pointer_segment(language)),
                        ));
                    }
                }
            }
        }
        let mut warnings = Vec::new();
        for entries in by_language.values() {
            let borrowed = entries
                .iter()
                .map(|(id, text, pointer)| AuthoredDisplayText { id, text, pointer })
                .collect::<Vec<_>>();
            warnings.extend(duplicate_display_text_diagnostics(
                document, code, kind, &borrowed,
            ));
        }
        warnings
    }
    fn plain_warnings<'a>(
        document: &Document,
        code: &str,
        kind: &str,
        values: impl IntoIterator<Item = (&'a str, &'a str, String)>,
    ) -> Vec<Diagnostic> {
        let values = values
            .into_iter()
            .map(|(id, text, pointer)| (id.to_owned(), text.to_owned(), pointer))
            .collect::<Vec<_>>();
        let entries = values
            .iter()
            .map(|(id, text, pointer)| AuthoredDisplayText { id, text, pointer })
            .collect::<Vec<_>>();
        duplicate_display_text_diagnostics(document, code, kind, &entries)
    }
    fn localized_location_warnings<'a>(
        document: &Document,
        code: &str,
        kind: &str,
        values: impl IntoIterator<Item = (&'a LocalizedText, String)>,
    ) -> Vec<Diagnostic> {
        let mut by_language = BTreeMap::<String, Vec<(String, String)>>::new();
        for (text, pointer) in values {
            match text {
                LocalizedText::Plain(text) => by_language
                    .entry("en".to_owned())
                    .or_default()
                    .push((text.clone(), pointer)),
                LocalizedText::Localized(texts) => {
                    for (language, text) in texts {
                        by_language.entry(language.clone()).or_default().push((
                            text.clone(),
                            format!("{pointer}/{}", escape_pointer_segment(language)),
                        ));
                    }
                }
            }
        }
        let mut warnings = Vec::new();
        for entries in by_language.values() {
            let borrowed = entries
                .iter()
                .map(|(text, pointer)| AuthoredDisplayTextLocation { text, pointer })
                .collect::<Vec<_>>();
            warnings.extend(duplicate_display_text_location_diagnostics(
                document, code, kind, &borrowed,
            ));
        }
        warnings
    }

    let mut errors = Vec::new();
    for (code, values) in [
        (
            "manifest.metadata.profile-id-collision",
            list_ids(
                "/profiles",
                manifest.profiles.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.evaluation-profile-id-collision",
            list_ids(
                "/evaluation_profiles",
                manifest
                    .evaluation_profiles
                    .iter()
                    .map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.ecosystem-binding-id-collision",
            list_ids(
                "/ecosystem_bindings",
                manifest
                    .ecosystem_bindings
                    .iter()
                    .map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.requirement-id-collision",
            list_ids(
                "/requirements",
                manifest.requirements.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.evidence-type-id-collision",
            list_ids(
                "/evidence_types",
                manifest.evidence_types.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.authority-id-collision",
            list_ids(
                "/authorities",
                manifest.authorities.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.public-service-id-collision",
            list_ids(
                "/public_services",
                manifest.public_services.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.data-service-id-collision",
            list_ids(
                "/data_services",
                manifest.data_services.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.distribution-id-collision",
            list_ids(
                "/distributions",
                manifest.distributions.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.form-id-collision",
            list_ids("/forms", manifest.forms.iter().map(|item| item.id.as_str())),
        ),
        (
            "manifest.metadata.dataset-id-collision",
            list_ids(
                "/datasets",
                manifest.datasets.iter().map(|item| item.id.as_str()),
            ),
        ),
        (
            "manifest.metadata.codelist-id-collision",
            list_ids(
                "/codelists",
                manifest.codelists.iter().map(|item| item.id.as_str()),
            ),
        ),
    ] {
        errors.extend(collisions(document, code, &values));
    }
    for (index, service) in manifest.public_services.iter().enumerate() {
        errors.extend(collisions(
            document,
            "manifest.metadata.channel-id-collision",
            &list_ids(
                &format!("/public_services/{index}/channels"),
                service.channels.iter().map(|item| item.id.as_str()),
            ),
        ));
    }
    for (index, form) in manifest.forms.iter().enumerate() {
        errors.extend(collisions(
            document,
            "manifest.metadata.form-section-id-collision",
            &list_ids(
                &format!("/forms/{index}/sections"),
                form.sections.iter().map(|item| item.id.as_str()),
            ),
        ));
        let mut fields = list_ids(
            &format!("/forms/{index}/fields"),
            form.fields.iter().map(|item| item.id.as_str()),
        );
        for (section_index, section) in form.sections.iter().enumerate() {
            fields.extend(list_ids(
                &format!("/forms/{index}/sections/{section_index}/fields"),
                section.fields.iter().map(|item| item.id.as_str()),
            ));
        }
        errors.extend(collisions(
            document,
            "manifest.metadata.form-field-id-collision",
            &fields,
        ));
    }
    for (index, dataset) in manifest.datasets.iter().enumerate() {
        errors.extend(collisions(
            document,
            "manifest.metadata.dataset-public-service-id-collision",
            &dataset
                .public_services
                .iter()
                .enumerate()
                .filter_map(|(service_index, service)| {
                    service
                        .id
                        .as_ref()
                        .filter(|id| LocalId::new(id.as_str()).is_ok())
                        .map(|id| {
                            (
                                id.clone(),
                                format!("/datasets/{index}/public_services/{service_index}/id"),
                            )
                        })
                })
                .collect::<Vec<_>>(),
        ));
        errors.extend(collisions(
            document,
            "manifest.metadata.entity-id-collision",
            &dataset
                .entities
                .iter()
                .enumerate()
                .map(|(entity_index, entity)| {
                    (
                        entity.name.clone(),
                        format!("/datasets/{index}/entities/{entity_index}/name"),
                    )
                })
                .collect::<Vec<_>>(),
        ));
        errors.extend(collisions(
            document,
            "manifest.metadata.evidence-offering-id-collision",
            &list_ids(
                &format!("/datasets/{index}/evidence_offerings"),
                dataset
                    .evidence_offerings
                    .iter()
                    .map(|item| item.id.as_str()),
            ),
        ));
        for (entity_index, entity) in dataset.entities.iter().enumerate() {
            for (code, member, values) in [
                (
                    "manifest.metadata.entity-field-id-collision",
                    "fields",
                    entity
                        .fields
                        .iter()
                        .map(|item| item.name.as_str())
                        .collect::<Vec<_>>(),
                ),
                (
                    "manifest.metadata.entity-relationship-id-collision",
                    "relationships",
                    entity
                        .relationships
                        .iter()
                        .map(|item| item.name.as_str())
                        .collect(),
                ),
            ] {
                errors.extend(collisions(
                    document,
                    code,
                    &values
                        .into_iter()
                        .enumerate()
                        .map(|(item_index, id)| {
                            (
                                id.to_owned(),
                                format!(
                                    "/datasets/{index}/entities/{entity_index}/{member}/{item_index}/name"
                                ),
                            )
                        })
                        .collect::<Vec<_>>(),
                ));
            }
        }
    }
    for (requirement_index, requirement) in manifest.requirements.iter().enumerate() {
        let total = requirement.evidence_type_lists.len();
        errors.extend(collisions(
            document,
            "manifest.metadata.evidence-type-list-id-collision",
            &requirement
                .evidence_type_lists
                .iter()
                .enumerate()
                .map(|(list_index, list)| {
                    let id = list.id.clone().unwrap_or_else(|| {
                        if total == 1 {
                            "evidence-type-list".to_owned()
                        } else {
                            format!("evidence-type-list-{}", list_index + 1)
                        }
                    });
                    (
                        id,
                        format!(
                            "/requirements/{requirement_index}/evidence_type_lists/{list_index}/id"
                        ),
                    )
                })
                .collect::<Vec<_>>(),
        ));
    }

    let warning_groups = [
        (
            "manifest.metadata.duplicate-dataset-title",
            "datasets",
            manifest
                .datasets
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/datasets/{index}/title"),
                    )
                })
                .collect::<Vec<_>>(),
        ),
        (
            "manifest.metadata.duplicate-form-title",
            "forms",
            manifest
                .forms
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/forms/{index}/title"),
                    )
                })
                .collect(),
        ),
        (
            "manifest.metadata.duplicate-evidence-type-title",
            "evidence types",
            manifest
                .evidence_types
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/evidence_types/{index}/title"),
                    )
                })
                .collect(),
        ),
        (
            "manifest.metadata.duplicate-requirement-title",
            "requirements",
            manifest
                .requirements
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/requirements/{index}/title"),
                    )
                })
                .collect(),
        ),
        (
            "manifest.metadata.duplicate-service-title",
            "public services",
            manifest
                .public_services
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/public_services/{index}/title"),
                    )
                })
                .collect(),
        ),
        (
            "manifest.metadata.duplicate-data-service-title",
            "data services",
            manifest
                .data_services
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/data_services/{index}/title"),
                    )
                })
                .collect(),
        ),
    ];
    let mut warnings = Vec::new();
    for (code, kind, values) in warning_groups {
        warnings.extend(localized_warnings(document, code, kind, values));
    }
    warnings.extend(plain_warnings(
        document,
        "manifest.metadata.duplicate-authority-name",
        "authorities",
        manifest
            .authorities
            .iter()
            .enumerate()
            .map(|(index, item)| {
                (
                    item.id.as_str(),
                    item.name.as_str(),
                    format!("/authorities/{index}/name"),
                )
            }),
    ));
    warnings.extend(localized_warnings(
        document,
        "manifest.metadata.duplicate-ecosystem-binding-title",
        "ecosystem bindings",
        manifest
            .ecosystem_bindings
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                item.title.as_ref().map(|title| {
                    (
                        item.id.as_str(),
                        title,
                        format!("/ecosystem_bindings/{index}/title"),
                    )
                })
            }),
    ));
    warnings.extend(localized_warnings(
        document,
        "manifest.metadata.duplicate-distribution-title",
        "distributions",
        manifest
            .distributions
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                item.title.as_ref().map(|title| {
                    (
                        item.id.as_str(),
                        title,
                        format!("/distributions/{index}/title"),
                    )
                })
            }),
    ));
    for (service_index, service) in manifest.public_services.iter().enumerate() {
        warnings.extend(localized_warnings(
            document,
            "manifest.metadata.duplicate-channel-title",
            "service channels",
            service
                .channels
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    item.title.as_ref().map(|title| {
                        (
                            item.id.as_str(),
                            title,
                            format!("/public_services/{service_index}/channels/{index}/title"),
                        )
                    })
                }),
        ));
    }
    for (requirement_index, requirement) in manifest.requirements.iter().enumerate() {
        let total = requirement.evidence_type_lists.len();
        let ids = requirement
            .evidence_type_lists
            .iter()
            .enumerate()
            .map(|(index, list)| {
                list.id.clone().unwrap_or_else(|| {
                    if total == 1 {
                        "evidence-type-list".to_owned()
                    } else {
                        format!("evidence-type-list-{}", index + 1)
                    }
                })
            })
            .collect::<Vec<_>>();
        warnings.extend(localized_warnings(
            document,
            "manifest.metadata.duplicate-evidence-type-list-title",
            "evidence type lists",
            requirement
                .evidence_type_lists
                .iter()
                .zip(&ids)
                .enumerate()
                .filter_map(|(index, (item, id))| {
                    Some((
                        id.as_str(),
                        item.title.as_ref()?,
                        format!(
                            "/requirements/{requirement_index}/evidence_type_lists/{index}/title"
                        ),
                    ))
                }),
        ));
    }
    for (dataset_index, dataset) in manifest.datasets.iter().enumerate() {
        warnings.extend(localized_warnings(
            document,
            "manifest.metadata.duplicate-entity-title",
            "entities",
            dataset
                .entities
                .iter()
                .enumerate()
                .filter_map(|(index, entity)| {
                    entity.title.as_ref().map(|title| {
                        (
                            entity.name.as_str(),
                            title,
                            format!("/datasets/{dataset_index}/entities/{index}/title"),
                        )
                    })
                }),
        ));
        warnings.extend(localized_warnings(
            document,
            "manifest.metadata.duplicate-evidence-offering-title",
            "evidence offerings",
            dataset
                .evidence_offerings
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        &item.title,
                        format!("/datasets/{dataset_index}/evidence_offerings/{index}/title"),
                    )
                }),
        ));
        warnings.extend(localized_location_warnings(
            document,
            "manifest.metadata.duplicate-dataset-public-service-title",
            "dataset public services",
            dataset
                .public_services
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        &item.title,
                        format!("/datasets/{dataset_index}/public_services/{index}/title"),
                    )
                }),
        ));
    }
    for (codelist_index, codelist) in manifest.codelists.iter().enumerate() {
        warnings.extend(localized_location_warnings(
            document,
            "manifest.metadata.duplicate-codelist-concept-label",
            "codelist concepts",
            codelist
                .concepts
                .iter()
                .enumerate()
                .filter_map(|(index, concept)| {
                    concept.label.as_ref().map(|label| {
                        (
                            label,
                            format!("/codelists/{codelist_index}/concepts/{index}/label"),
                        )
                    })
                }),
        ));
    }
    for (form_index, form) in manifest.forms.iter().enumerate() {
        warnings.extend(localized_warnings(
            document,
            "manifest.metadata.duplicate-form-section-title",
            "form sections",
            form.sections
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    item.title.as_ref().map(|title| {
                        (
                            item.id.as_str(),
                            title,
                            format!("/forms/{form_index}/sections/{index}/title"),
                        )
                    })
                }),
        ));
        let mut fields = form
            .fields
            .iter()
            .enumerate()
            .map(|(index, item)| {
                (
                    item.id.as_str(),
                    &item.label,
                    format!("/forms/{form_index}/fields/{index}/label"),
                )
            })
            .collect::<Vec<_>>();
        for (section_index, section) in form.sections.iter().enumerate() {
            fields.extend(section.fields.iter().enumerate().map(|(index, item)| {
                (
                    item.id.as_str(),
                    &item.label,
                    format!("/forms/{form_index}/sections/{section_index}/fields/{index}/label"),
                )
            }));
        }
        warnings.extend(localized_warnings(
            document,
            "manifest.metadata.duplicate-form-field-label",
            "form fields",
            fields,
        ));
    }
    for warning in warnings {
        document.push_warning(warning);
    }
    errors
}

/// Every runtime-only or secret-bearing key at or below `node`. The value
/// of a refused key is not searched: the whole member goes.
fn refused_keys(document: &Document, node: &Node, pointer: &str, found: &mut Vec<Diagnostic>) {
    match &node.value {
        NodeValue::Mapping(entries) => {
            for entry in entries {
                let child = format!("{pointer}/{}", escape_pointer_segment(&entry.key));
                if is_runtime_only_key(&entry.key) {
                    found.push(document.diagnostic_at_key(
                        Severity::Error,
                        "manifest.metadata.runtime-only-key",
                        &child,
                        RUNTIME_ONLY_MESSAGE,
                        RUNTIME_ONLY_ACTION,
                    ));
                } else if is_secret_bearing_key(&entry.key) {
                    found.push(document.diagnostic_at_key(
                        Severity::Error,
                        "manifest.metadata.secret-bearing-key",
                        &child,
                        SECRET_BEARING_MESSAGE,
                        SECRET_BEARING_ACTION,
                    ));
                } else {
                    refused_keys(document, &entry.value, &child, found);
                }
            }
        }
        NodeValue::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                refused_keys(document, item, &format!("{pointer}/{index}"), found);
            }
        }
        _ => {}
    }
}

fn unsupported_version(document: &Document) -> Diagnostic {
    document.diagnostic_at_value(
        Severity::Error,
        "manifest.metadata.unsupported-version",
        "/schema_version",
        "this release reads metadata manifests whose schema_version is registry-manifest/v1",
        "Set schema_version to registry-manifest/v1, and write the manifest in that version's \
         shape.",
    )
}

/// The shared code for a repeated id (CFG-ID-5), which the manifest answers
/// beside the reader whichever of them finds the copy.
const DUPLICATE_ID_CODE: &str = "config.duplicate-id";

/// The diagnostics for a manifest `validate_manifest` or `compile_manifest`
/// refused. Each rule's code is `manifest.metadata.<condition>`, except a
/// repeated id, which is `config.duplicate-id`; it is
/// placed at the member it names, or at the nearest enclosing member the
/// file writes when the member is absent, and its path is always the
/// member's own.
pub fn metadata_error_diagnostics(document: &Document, error: MetadataError) -> Vec<Diagnostic> {
    match error {
        MetadataError::VersionUnsupported => vec![unsupported_version(document)],
        MetadataError::Validation { errors } => errors
            .into_iter()
            .map(|error| {
                let pointer = validation_pointer(&error.path);
                let mut written = pointer.as_str();
                while document.root().pointer(written).is_none() {
                    written = written.rfind('/').map_or("", |at| &written[..at]);
                }
                let code = match error.condition {
                    ValidationCondition::DuplicateId => DUPLICATE_ID_CODE.to_owned(),
                    condition => format!("manifest.metadata.{}", condition.code()),
                };
                let mut diagnostic = document.diagnostic_at_value(
                    Severity::Error,
                    &code,
                    written,
                    &error.message,
                    error.condition.suggested_action(),
                );
                diagnostic.path = pointer;
                diagnostic
            })
            .collect(),
    }
}

/// The RFC 6901 pointer for a `validate_manifest` path:
/// `datasets[0].entities[1].name` is `/datasets/0/entities/1/name`, and a
/// vocabulary prefix stays one segment however it is written.
pub fn validation_pointer(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    if let Some(prefix) = path.strip_prefix("vocabularies.") {
        return format!("/vocabularies/{}", escape_pointer_segment(prefix));
    }
    let mut pointer = String::new();
    for segment in path.split('.') {
        let (name, indexes) = segment.split_at(segment.find('[').unwrap_or(segment.len()));
        pointer.push('/');
        pointer.push_str(&escape_pointer_segment(name));
        for index in indexes.split(['[', ']']).filter(|index| !index.is_empty()) {
            pointer.push('/');
            pointer.push_str(index);
        }
    }
    pointer
}

/// The `source_manifest_digest` of an accepted manifest, or the diagnostic
/// that says why it cannot be computed.
pub fn manifest_digest(read: &ReadManifest) -> Result<String, Box<Diagnostic>> {
    source_manifest_digest(&read.manifest).map_err(|_| {
        Box::new(read.document.diagnostic_at_value(
            Severity::Error,
            "manifest.metadata.not-canonicalizable",
            "",
            "the manifest holds a number canonical JSON cannot represent, so its source \
             digest cannot be computed",
            "Write every number in the manifest as a finite value that IEEE 754 binary64 \
             represents exactly.",
        ))
    })
}

/// What `validate` found in one metadata manifest file.
pub struct MetadataCheck {
    /// The manifest, when nothing refused it.
    pub manifest: Option<ReadManifest>,
    pub report: Report,
    /// The file could not be read, so the check is incomplete.
    pub unavailable: bool,
}

/// Read and check the metadata manifest at `path`.
pub fn check_metadata_file(path: &Path) -> MetadataCheck {
    let mut findings = Findings::default();
    let manifest = match contents(path) {
        Contents::Missing => {
            findings.unreadable(
                "manifest.metadata.missing-file",
                path,
                "the metadata manifest does not exist",
                "Pass the path of an existing metadata manifest.",
            );
            None
        }
        Contents::Unreadable => {
            findings.unreadable(
                "manifest.metadata.unreadable",
                path,
                "the metadata manifest is not a regular file this process can read",
                "Pass a regular file, and give this process permission to read it.",
            );
            None
        }
        Contents::Bytes(bytes) => {
            findings.files = 1;
            match read_metadata(&path.display().to_string(), &bytes) {
                Ok(read) => {
                    findings.extend(read.document.warnings().into_diagnostics());
                    Some(read)
                }
                Err(diagnostics) => {
                    findings.extend(diagnostics);
                    None
                }
            }
        }
    };
    let (report, unavailable) = findings.into_report();
    MetadataCheck {
        manifest,
        report,
        unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_manifest_core::ValidationError;

    const MINIMAL: &str = "schema_version: registry-manifest/v1\ncatalog:\n  id: demo\n  \
                           base_url: https://metadata.example.test\n  title: Demo\n  \
                           publisher:\n    name: Publisher\n";

    fn refused(text: &str) -> Vec<Diagnostic> {
        match read_metadata("metadata.yaml", text.as_bytes()) {
            Ok(_) => panic!("the manifest was accepted"),
            Err(diagnostics) => diagnostics,
        }
    }

    #[test]
    fn validation_paths_become_pointers() {
        assert_eq!(validation_pointer(""), "");
        assert_eq!(validation_pointer("catalog.base_url"), "/catalog/base_url");
        assert_eq!(
            validation_pointer("datasets[0].entities[12].fields[3].name"),
            "/datasets/0/entities/12/fields/3/name"
        );
        assert_eq!(
            validation_pointer("vocabularies.a.b/c~d"),
            "/vocabularies/a.b~1c~0d"
        );
    }

    #[test]
    fn a_minimal_manifest_is_accepted() {
        let read = read_metadata("metadata.yaml", MINIMAL.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        assert_eq!(read.manifest.catalog.id, "demo");
        assert!(manifest_digest(&read).is_ok());
    }

    #[test]
    fn metadata_check_keeps_a_positioned_duplicate_authority_name_warning() {
        let text = format!(
            "{MINIMAL}authorities:\n  - id: registry-office\n    name: Registry Office\n  - id: registry-copy\n    name: registry office\n"
        );
        let read = read_metadata("metadata.yaml", text.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        let warnings = read.document.warnings();
        let finding = warnings
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "manifest.metadata.duplicate-authority-name")
            .expect("the duplicate name warning survives metadata checking");
        assert_eq!(finding.path, "/authorities/1/name");
        assert_eq!(finding.related[0].path, "/authorities/0/name");
        assert!(finding.message.contains("`registry-office`"));
        assert!(finding.message.contains("`registry-copy`"));
        assert!(!finding.message.contains("Registry Office"));
    }

    #[test]
    fn metadata_check_refuses_separator_lookalikes_in_the_authority_namespace() {
        let text = format!(
            "{MINIMAL}authorities:\n  - id: registry-office\n    name: First office\n  - id: registry_office\n    name: Second office\n"
        );
        let diagnostics = refused(&text);
        let finding = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "manifest.metadata.authority-id-collision")
            .expect("the authority collision has its own finding");
        assert_eq!(finding.path, "/authorities/1/id");
        assert_eq!(finding.related[0].path, "/authorities/0/id");
        assert!(finding.message.contains("`registry-office`"));
        assert!(finding.message.contains("`registry_office`"));
    }

    #[test]
    fn metadata_check_refuses_nested_definition_id_lookalikes() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: people\n    title: People\n    public_services:\n      - id: registry-office\n        title: First\n      - id: registry_office\n        title: Second\n"
        );
        let diagnostics = refused(&text);
        let finding = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "manifest.metadata.dataset-public-service-id-collision"
            })
            .expect("the dataset public service collision has its own finding");
        assert_eq!(finding.path, "/datasets/0/public_services/1/id");
        assert_eq!(finding.related[0].path, "/datasets/0/public_services/0/id");

        let text = format!(
            "{MINIMAL}requirements:\n  - id: identity\n    title: Identity\n    evidence_type_lists:\n      - id: passport-proof\n        evidence_types: [passport]\n      - id: passport_proof\n        evidence_types: [passport]\nevidence_types:\n  - id: passport\n    title: Passport\n    proves: [identity]\n"
        );
        let diagnostics = refused(&text);
        let finding = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "manifest.metadata.evidence-type-list-id-collision"
            })
            .expect("the evidence type list collision has its own finding");
        assert_eq!(finding.path, "/requirements/0/evidence_type_lists/1/id");
        assert_eq!(
            finding.related[0].path,
            "/requirements/0/evidence_type_lists/0/id"
        );
    }

    #[test]
    fn evidence_type_lists_use_their_effective_ids_for_integrity_checks() {
        let text = format!(
            "{MINIMAL}requirements:\n  - id: identity\n    title: Identity\n    evidence_type_lists:\n      - evidence_types: [passport]\n      - id: evidence_type_list_1\n        evidence_types: [passport]\nevidence_types:\n  - id: passport\n    title: Passport\n    proves: [identity]\n"
        );
        let diagnostics = refused(&text);
        let collision = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "manifest.metadata.evidence-type-list-id-collision"
            })
            .expect("an implicit list ID shares the authored list namespace");
        assert_eq!(collision.path, "/requirements/0/evidence_type_lists/1/id");
        assert_eq!(
            collision.related[0].path,
            "/requirements/0/evidence_type_lists/0/id"
        );

        let text = format!(
            "{MINIMAL}requirements:\n  - id: identity\n    title: Identity\n    evidence_type_lists:\n      - title: Review\n        evidence_types: [passport]\n      - title: \"R\\u200Beview\"\n        evidence_types: [passport]\nevidence_types:\n  - id: passport\n    title: Passport\n    proves: [identity]\n"
        );
        let read = read_metadata("metadata.yaml", text.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        let warning = read
            .document
            .warnings()
            .diagnostics()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "manifest.metadata.duplicate-evidence-type-list-title"
            })
            .cloned()
            .expect("implicit list IDs still participate in title checks");
        assert_eq!(warning.path, "/requirements/0/evidence_type_lists/1/title");
        assert_eq!(
            warning.related[0].path,
            "/requirements/0/evidence_type_lists/0/title"
        );
    }

    #[test]
    fn global_dataset_service_iris_are_not_local_id_separator_collisions() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: people\n    title: People\n    public_services:\n      - id: https://example.test/service-a\n        title: First\n      - id: https://example.test/service_a\n        title: Second\n"
        );
        read_metadata("metadata.yaml", text.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
    }

    #[test]
    fn form_fields_share_one_id_and_label_namespace_across_sections() {
        let form = "public_services:\n  - id: registry-service\n    title: Registry service\n    description: Registry service description\nforms:\n  - id: intake\n    title: Intake\n    service: registry-service\n    fields:\n      - id: case-number\n        label: Case number\n    sections:\n      - id: details\n        fields:\n          - id: case_number\n            label: Other value\n";
        let diagnostics = refused(&format!("{MINIMAL}{form}"));
        let collision = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "manifest.metadata.form-field-id-collision")
            .expect("top-level and section fields share the form field namespace");
        assert_eq!(collision.path, "/forms/0/sections/0/fields/0/id");
        assert_eq!(collision.related[0].path, "/forms/0/fields/0/id");

        let form = form
            .replace("case_number", "alternate-number")
            .replace("label: Other value", "label: \"case\\u200f number\"");
        let read = read_metadata("metadata.yaml", format!("{MINIMAL}{form}").as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        let warning = read
            .document
            .warnings()
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "manifest.metadata.duplicate-form-field-label")
            .cloned()
            .expect("top-level and section fields share the form label namespace");
        assert_eq!(warning.path, "/forms/0/sections/0/fields/0/label");
        assert_eq!(warning.related[0].path, "/forms/0/fields/0/label");
    }

    #[test]
    fn codelist_concept_labels_warn_without_echoing_arbitrary_codes() {
        let text = format!(
            "{MINIMAL}codelists:\n  - id: status\n    scheme_iri: https://example.test/status\n    concepts:\n      - code: \"first <code>\"\n        label: Active\n      - code: \"second <code>\"\n        label:\n          en: \"A\\u200Bctive\"\n"
        );
        let read = read_metadata("metadata.yaml", text.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        let warning = read
            .document
            .warnings()
            .diagnostics()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "manifest.metadata.duplicate-codelist-concept-label"
            })
            .cloned()
            .expect("peer concept labels compare within one codelist and language");
        assert_eq!(warning.path, "/codelists/0/concepts/1/label/en");
        assert_eq!(warning.related[0].path, "/codelists/0/concepts/0/label");
        assert!(!warning.message.contains("first <code>"));
        assert!(!warning.message.contains("second <code>"));
        assert!(!warning.related[0].message.contains("first <code>"));
    }

    #[test]
    fn plain_and_english_localized_titles_share_one_comparison_scope() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: first\n    title: Review\n  - id: second\n    title:\n      en: \"R\\u200Beview\"\n"
        );
        let read = read_metadata("metadata.yaml", text.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        let warning = read
            .document
            .warnings()
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "manifest.metadata.duplicate-dataset-title")
            .cloned()
            .expect("plain text is the English shorthand for warning comparison");
        assert_eq!(warning.path, "/datasets/1/title/en");
        assert_eq!(warning.related[0].path, "/datasets/0/title");
    }

    #[test]
    fn duplicate_title_warnings_survive_unrelated_semantic_errors() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: first\n    title: Review\n  - id: second\n    title: \"R\\u200Beview\"\ndistributions:\n  - id: broken\n    dataset: missing\n    download_url: https://example.test/data.json\n"
        );
        let diagnostics = refused(&text);
        for code in [
            "manifest.metadata.duplicate-dataset-title",
            "manifest.metadata.unknown-reference",
        ] {
            assert!(
                diagnostics.iter().any(|diagnostic| diagnostic.code == code),
                "missing {code}: {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn anonymous_dataset_service_titles_still_share_the_peer_scope() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: people\n    title: People\n    public_services:\n      - title: Review\n      - title:\n          en: \"R\\u200Beview\"\n"
        );
        let read = read_metadata("metadata.yaml", text.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        let warning = read
            .document
            .warnings()
            .diagnostics()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "manifest.metadata.duplicate-dataset-public-service-title"
            })
            .cloned()
            .expect("anonymous peer titles participate in duplicate checks");
        assert_eq!(warning.path, "/datasets/0/public_services/1/title/en");
        assert_eq!(
            warning.related[0].path,
            "/datasets/0/public_services/0/title"
        );
    }

    #[test]
    fn a_rule_is_placed_at_the_member_it_names() {
        let text = MINIMAL.replace("https://metadata.example.test", "metadata.example.test");
        let diagnostics = refused(&text);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "manifest.metadata.invalid-url");
        assert_eq!(diagnostic.path, "/catalog/base_url");
        let source = diagnostic.source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(4), Some(13)));
        assert!(!diagnostic.message.contains("metadata.example.test"));
    }

    #[test]
    fn an_absent_member_is_placed_at_its_nearest_written_parent() {
        let text = format!(
            "{MINIMAL}ecosystem_bindings:\n  - id: binding\n    version: \"1\"\n    \
             profile: demo\n    type: governed-evidence\n"
        );
        let diagnostics = refused(&text);
        let missing = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/ecosystem_bindings/0/evidence_pack")
            .unwrap_or_else(|| panic!("no finding names the evidence pack: {diagnostics:#?}"));
        assert_eq!(missing.code, "manifest.metadata.missing-member");
        let source = missing.source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(9), Some(5)));
    }

    #[test]
    fn runtime_only_and_secret_bearing_keys_are_refused_at_the_key() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: people\n    title: People\n    source: table\n    \
             policy:\n      api_key: planted\n"
        );
        let diagnostics = refused(&text);
        let codes = diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                ("manifest.metadata.runtime-only-key", "/datasets/0/source"),
                (
                    "manifest.metadata.secret-bearing-key",
                    "/datasets/0/policy/api_key"
                ),
            ]
        );
        let source = diagnostics[0].source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(11), Some(5)));
        assert!(diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.message.contains("planted")));
    }

    #[test]
    fn cfg_id_5_a_repeated_id_in_a_named_item_list_is_refused_at_the_copy() {
        for (list, item) in [
            ("profiles", "{id: p, version: \"1\"}"),
            (
                "evaluation_profiles",
                "{id: e, ruleset: r, claim_id: c, subject_id_type: s}",
            ),
            ("requirements", "{id: r, title: R}"),
            ("evidence_types", "{id: t, title: T}"),
            ("authorities", "{id: a, name: A}"),
            ("public_services", "{id: s, title: S}"),
            ("data_services", "{id: d, title: D}"),
            ("distributions", "{id: x, dataset: people}"),
            ("forms", "{id: f, title: F, service: s}"),
            ("datasets", "{id: people, title: People}"),
            (
                "codelists",
                "{id: c, scheme_iri: https://codelists.example.test/c}",
            ),
        ] {
            let text = format!("{MINIMAL}{list}:\n  - {item}\n  - {item}\n");
            let diagnostics = refused(&text);
            let found = diagnostics
                .iter()
                .map(|diagnostic| {
                    (
                        diagnostic.code.as_str(),
                        diagnostic.path.as_str(),
                        diagnostic
                            .related
                            .iter()
                            .map(|related| related.path.as_str())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                found,
                [(
                    "config.duplicate-id",
                    format!("/{list}/1/id").as_str(),
                    vec![format!("/{list}/0/id").as_str()],
                )],
                "{list}"
            );
        }
    }

    #[test]
    fn a_repeated_id_the_reader_does_not_catch_answers_the_shared_code() {
        let read = read_metadata("metadata.yaml", MINIMAL.as_bytes()).unwrap();
        let error = MetadataError::Validation {
            errors: vec![
                ValidationError {
                    condition: ValidationCondition::DuplicateId,
                    path: "catalog.id".to_owned(),
                    message: "an id must be unique".to_owned(),
                },
                ValidationError {
                    condition: ValidationCondition::DuplicateValue,
                    path: "catalog.title".to_owned(),
                    message: "values must be unique".to_owned(),
                },
            ],
        };
        let found = metadata_error_diagnostics(&read.document, error)
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            found,
            [
                ("config.duplicate-id".to_owned(), "/catalog/id".to_owned()),
                (
                    "manifest.metadata.duplicate-value".to_owned(),
                    "/catalog/title".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn another_schema_version_is_refused_before_its_shape_is_read() {
        let text = MINIMAL.replace("registry-manifest/v1", "registry-manifest/v0")
            + "retired_member: true\n";
        let diagnostics = refused(&text);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "manifest.metadata.unsupported-version");
        assert_eq!(diagnostics[0].path, "/schema_version");
    }

    #[test]
    fn substitution_is_refused_in_a_manifest() {
        let text = MINIMAL.replace("title: Demo", "title: ${TITLE}");
        let diagnostics = refused(&text);
        assert_eq!(diagnostics[0].code, "config.substitution-not-allowed");
        assert_eq!(diagnostics[0].path, "/catalog/title");
    }
}
