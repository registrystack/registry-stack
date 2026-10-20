// SPDX-License-Identifier: Apache-2.0
//! Product-specific authoring integrity checks over positioned BReg documents.

use std::collections::BTreeMap;

use registry_platform_yaml::{
    duplicate_display_text_diagnostics, duplicate_display_text_location_diagnostics,
    local_id_collision_diagnostics, lookalike_local_id_pairs, AuthoredDisplayText,
    AuthoredDisplayTextLocation, AuthoredId, Decoded,
};

use crate::contract::{
    ActionExecutionSource, ActionPlanSource, ActionSource, ConstraintSource, EntityExtensionSource,
    EntitySource, FieldTypeSource, ManifestProjectionTextSource, RegistryModule, RegistryProject,
};

type LocatedId = (String, String);
type LocatedDisplayText = (String, String, String);
type LocatedDisplayTextLocation = (String, String);

fn id_entries(values: &[LocatedId]) -> Vec<AuthoredId<'_>> {
    values
        .iter()
        .map(|(id, pointer)| AuthoredId { id, pointer })
        .collect()
}

fn display_entries(values: &[LocatedDisplayText]) -> Vec<AuthoredDisplayText<'_>> {
    values
        .iter()
        .map(|(id, text, pointer)| AuthoredDisplayText { id, text, pointer })
        .collect()
}

fn display_location_entries(
    values: &[LocatedDisplayTextLocation],
) -> Vec<AuthoredDisplayTextLocation<'_>> {
    values
        .iter()
        .map(|(text, pointer)| AuthoredDisplayTextLocation { text, pointer })
        .collect()
}

fn indexed_ids<T>(base: &str, values: &[T], id: impl Fn(&T) -> &str) -> Vec<LocatedId> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| (id(value).to_owned(), format!("{base}/{index}/id")))
        .collect()
}

fn display_labels<T>(
    base: &str,
    values: &[T],
    id: impl Fn(&T) -> &str,
    label: impl Fn(&T) -> Option<&str>,
) -> Vec<LocatedDisplayText> {
    values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            label(value).map(|label| {
                (
                    id(value).to_owned(),
                    label.to_owned(),
                    format!("{base}/{index}/display/label"),
                )
            })
        })
        .collect()
}

fn localized_display_texts(
    default_language: &str,
    id: Option<&str>,
    pointer: &str,
    text: &ManifestProjectionTextSource,
    identified: &mut BTreeMap<String, Vec<LocatedDisplayText>>,
    anonymous: &mut BTreeMap<String, Vec<LocatedDisplayTextLocation>>,
) {
    let mut add = |language: &str, text: &str, pointer: String| {
        let language = language.to_ascii_lowercase();
        if let Some(id) = id {
            identified
                .entry(language)
                .or_default()
                .push((id.to_owned(), text.to_owned(), pointer));
        } else {
            anonymous
                .entry(language)
                .or_default()
                .push((text.to_owned(), pointer));
        }
    };
    match text {
        ManifestProjectionTextSource::Plain(text) => {
            add(default_language, text.as_str(), pointer.to_owned());
        }
        ManifestProjectionTextSource::Localized(values) => {
            for (language, text) in values {
                add(
                    language.as_str(),
                    text.as_str(),
                    format!(
                        "{pointer}/{}",
                        registry_platform_yaml::escape_pointer_segment(language.as_str())
                    ),
                );
            }
        }
    }
}

fn entity_field_display_labels(base: &str, entity: &EntitySource) -> Vec<LocatedDisplayText> {
    let mut values = display_labels(
        &format!("{base}/fields"),
        &entity.fields,
        |field| &field.id,
        |field| field.display.label.as_deref(),
    );
    for (derived_index, derived) in entity.derived.iter().enumerate() {
        values.extend(display_labels(
            &format!("{base}/derived/{derived_index}/fields"),
            &derived.fields,
            |field| &field.id,
            |field| field.display.label.as_deref(),
        ));
    }
    values
}

fn extension_field_display_labels(
    base: &str,
    extension: &EntityExtensionSource,
) -> Vec<LocatedDisplayText> {
    let mut values = display_labels(
        &format!("{base}/fields"),
        &extension.fields,
        |field| &field.id,
        |field| field.display.label.as_deref(),
    );
    for (derived_index, derived) in extension.derived.iter().enumerate() {
        values.extend(display_labels(
            &format!("{base}/derived/{derived_index}/fields"),
            &derived.fields,
            |field| &field.id,
            |field| field.display.label.as_deref(),
        ));
    }
    values
}

fn add_collisions(
    document: &registry_platform_yaml::Document,
    errors: &mut Vec<registry_platform_yaml::Diagnostic>,
    code: &str,
    values: &[LocatedId],
) {
    errors.extend(local_id_collision_diagnostics(
        document,
        code,
        &id_entries(values),
    ));
}

fn add_cross_group_collisions(
    document: &registry_platform_yaml::Document,
    errors: &mut Vec<registry_platform_yaml::Diagnostic>,
    code: &str,
    first: &[LocatedId],
    second: &[LocatedId],
) {
    let mut values = first.to_vec();
    let boundary = values.len();
    values.extend_from_slice(second);
    for (left, right) in lookalike_local_id_pairs(values.iter().map(|(id, _)| id.as_str())) {
        if (left < boundary) == (right < boundary) {
            continue;
        }
        let pair = [
            AuthoredId {
                id: &values[left].0,
                pointer: &values[left].1,
            },
            AuthoredId {
                id: &values[right].0,
                pointer: &values[right].1,
            },
        ];
        errors.extend(local_id_collision_diagnostics(document, code, &pair));
    }
}

fn add_duplicate_labels(
    document: &registry_platform_yaml::Document,
    warnings: &mut Vec<registry_platform_yaml::Diagnostic>,
    code: &str,
    kind: &str,
    values: &[LocatedDisplayText],
) {
    warnings.extend(duplicate_display_text_diagnostics(
        document,
        code,
        kind,
        &display_entries(values),
    ));
}

fn add_duplicate_locations(
    document: &registry_platform_yaml::Document,
    warnings: &mut Vec<registry_platform_yaml::Diagnostic>,
    code: &str,
    kind: &str,
    values: &[LocatedDisplayTextLocation],
) {
    warnings.extend(duplicate_display_text_location_diagnostics(
        document,
        code,
        kind,
        &display_location_entries(values),
    ));
}

fn map_ids(base: &str, values: &BTreeMap<String, FieldTypeSource>) -> Vec<LocatedId> {
    values
        .keys()
        .map(|id| {
            (
                id.clone(),
                format!(
                    "{base}/{}",
                    registry_platform_yaml::escape_pointer_segment(id)
                ),
            )
        })
        .collect()
}

fn constraint_ids(base: &str, values: &[ConstraintSource]) -> Vec<LocatedId> {
    values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            value
                .explicit_id()
                .map(|id| (id.to_owned(), format!("{base}/{index}/id")))
        })
        .collect()
}

fn entity_integrity(
    document: &registry_platform_yaml::Document,
    errors: &mut Vec<registry_platform_yaml::Diagnostic>,
    base: &str,
    entity: &EntitySource,
) {
    let mut fields = indexed_ids(&format!("{base}/fields"), &entity.fields, |field| &field.id);
    for (derived_index, derived) in entity.derived.iter().enumerate() {
        fields.extend(indexed_ids(
            &format!("{base}/derived/{derived_index}/fields"),
            &derived.fields,
            |field| &field.id,
        ));
    }
    add_collisions(document, errors, "breg.field.id-collision", &fields);
    for (code, values) in [
        (
            "breg.derived.id-collision",
            indexed_ids(&format!("{base}/derived"), &entity.derived, |item| &item.id),
        ),
        (
            "breg.constraint.id-collision",
            constraint_ids(&format!("{base}/constraints"), &entity.constraints),
        ),
        (
            "breg.index.id-collision",
            indexed_ids(&format!("{base}/indexes"), &entity.indexes, |item| &item.id),
        ),
        (
            "breg.access-profile.id-collision",
            indexed_ids(
                &format!("{base}/accessProfiles"),
                &entity.access_profiles,
                |item| &item.id,
            ),
        ),
        (
            "breg.selector-profile.id-collision",
            indexed_ids(
                &format!("{base}/selectorProfiles"),
                &entity.selector_profiles,
                |item| &item.id,
            ),
        ),
        (
            "breg.read-path.id-collision",
            indexed_ids(&format!("{base}/readPaths"), &entity.read_paths, |item| {
                &item.id
            }),
        ),
    ] {
        add_collisions(document, errors, code, &values);
    }
}

#[allow(clippy::too_many_lines)]
fn extension_integrity(
    document: &registry_platform_yaml::Document,
    errors: &mut Vec<registry_platform_yaml::Diagnostic>,
    entities: &[EntitySource],
    extensions: &[EntityExtensionSource],
) {
    #[derive(Default)]
    struct Namespaces {
        fields: Vec<LocatedId>,
        derived: Vec<LocatedId>,
        constraints: Vec<LocatedId>,
        indexes: Vec<LocatedId>,
        profiles: Vec<LocatedId>,
        selectors: Vec<LocatedId>,
        read_paths: Vec<LocatedId>,
    }

    let mut targets = BTreeMap::<String, Namespaces>::new();
    for (entity_index, entity) in entities.iter().enumerate() {
        let base = format!("/recordTypes/{entity_index}");
        let target = targets.entry(entity.id.clone()).or_default();
        target.fields.extend(indexed_ids(
            &format!("{base}/fields"),
            &entity.fields,
            |field| &field.id,
        ));
        for (derived_index, derived) in entity.derived.iter().enumerate() {
            target.fields.extend(indexed_ids(
                &format!("{base}/derived/{derived_index}/fields"),
                &derived.fields,
                |field| &field.id,
            ));
        }
        target.derived.extend(indexed_ids(
            &format!("{base}/derived"),
            &entity.derived,
            |item| &item.id,
        ));
        target.constraints.extend(constraint_ids(
            &format!("{base}/constraints"),
            &entity.constraints,
        ));
        target.indexes.extend(indexed_ids(
            &format!("{base}/indexes"),
            &entity.indexes,
            |item| &item.id,
        ));
        target.profiles.extend(indexed_ids(
            &format!("{base}/accessProfiles"),
            &entity.access_profiles,
            |item| &item.id,
        ));
        target.selectors.extend(indexed_ids(
            &format!("{base}/selectorProfiles"),
            &entity.selector_profiles,
            |item| &item.id,
        ));
        target.read_paths.extend(indexed_ids(
            &format!("{base}/readPaths"),
            &entity.read_paths,
            |item| &item.id,
        ));
    }
    for (extension_index, extension) in extensions.iter().enumerate() {
        let base = format!("/extendRecordTypes/{extension_index}");
        let target = targets.entry(extension.entity.clone()).or_default();
        target.fields.extend(indexed_ids(
            &format!("{base}/fields"),
            &extension.fields,
            |field| &field.id,
        ));
        for (derived_index, derived) in extension.derived.iter().enumerate() {
            target.fields.extend(indexed_ids(
                &format!("{base}/derived/{derived_index}/fields"),
                &derived.fields,
                |field| &field.id,
            ));
        }
        target.derived.extend(indexed_ids(
            &format!("{base}/derived"),
            &extension.derived,
            |item| &item.id,
        ));
        target.constraints.extend(constraint_ids(
            &format!("{base}/constraints"),
            &extension.constraints,
        ));
        target.indexes.extend(indexed_ids(
            &format!("{base}/indexes"),
            &extension.indexes,
            |item| &item.id,
        ));
        target.profiles.extend(indexed_ids(
            &format!("{base}/accessProfiles"),
            &extension.access_profiles,
            |item| &item.id,
        ));
        target.selectors.extend(indexed_ids(
            &format!("{base}/selectorProfiles"),
            &extension.selector_profiles,
            |item| &item.id,
        ));
        target.read_paths.extend(indexed_ids(
            &format!("{base}/readPaths"),
            &extension.read_paths,
            |item| &item.id,
        ));
    }
    for target in targets.values() {
        for (code, values) in [
            ("breg.field.id-collision", &target.fields),
            ("breg.derived.id-collision", &target.derived),
            ("breg.constraint.id-collision", &target.constraints),
            ("breg.index.id-collision", &target.indexes),
            ("breg.access-profile.id-collision", &target.profiles),
            ("breg.selector-profile.id-collision", &target.selectors),
            ("breg.read-path.id-collision", &target.read_paths),
        ] {
            add_collisions(document, errors, code, values);
        }
    }
}

fn action_integrity(
    document: &registry_platform_yaml::Document,
    errors: &mut Vec<registry_platform_yaml::Diagnostic>,
    base: &str,
    action: &ActionSource,
) {
    for (code, values) in [
        (
            "breg.action-input.id-collision",
            indexed_ids(&format!("{base}/inputs"), &action.inputs, |item| &item.id),
        ),
        (
            "breg.action-evidence.id-collision",
            indexed_ids(&format!("{base}/evidence"), &action.evidence, |item| {
                &item.id
            }),
        ),
        (
            "breg.commit-evidence.id-collision",
            indexed_ids(
                &format!("{base}/commitGuards/evidence"),
                &action.commit_guards.evidence,
                |item| &item.id,
            ),
        ),
    ] {
        add_collisions(document, errors, code, &values);
    }
    if let ActionPlanSource::Function { writes, .. } = &action.plan {
        let values = indexed_ids(&format!("{base}/plan/writes"), writes, |item| &item.id);
        add_collisions(document, errors, "breg.action-write.id-collision", &values);
    }
    if let ActionPlanSource::Fixed { effects } = &action.plan {
        let values = effects
            .iter()
            .enumerate()
            .filter_map(|(index, effect)| {
                effect
                    .id
                    .as_ref()
                    .map(|id| (id.clone(), format!("{base}/plan/effects/{index}/id")))
            })
            .collect::<Vec<_>>();
        add_collisions(document, errors, "breg.action-effect.id-collision", &values);
    }
    if let ActionExecutionSource::Proposal { proposal } = &action.execution {
        for (code, values) in [
            (
                "breg.attachment.id-lookalike",
                indexed_ids(
                    &format!("{base}/execution/proposal/attachments"),
                    &proposal.attachments,
                    |item| &item.id,
                ),
            ),
            (
                "breg.proposal-hook.id-collision",
                indexed_ids(
                    &format!("{base}/execution/proposal/hooks"),
                    &proposal.hooks,
                    |item| &item.id,
                ),
            ),
        ] {
            add_collisions(document, errors, code, &values);
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn project_diagnostics(
    decoded: &mut Decoded<RegistryProject>,
) -> Vec<registry_platform_yaml::Diagnostic> {
    let project = &decoded.value;
    let document = &decoded.document;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for (code, values) in [
        (
            "breg.evidence-provider.id-collision",
            indexed_ids("/evidenceProviders", &project.evidence_providers, |item| {
                &item.id
            }),
        ),
        (
            "breg.module.id-collision",
            indexed_ids("/modules", &project.modules, |item| &item.id),
        ),
        (
            "breg.record-type.id-collision",
            indexed_ids("/recordTypes", &project.entities, |item| &item.id),
        ),
        (
            "breg.dataset.id-collision",
            indexed_ids("/datasets", &project.datasets, |item| &item.id),
        ),
        (
            "breg.review-authority.id-collision",
            indexed_ids("/reviewAuthorities", &project.review_authorities, |item| {
                &item.id
            }),
        ),
        (
            "breg.value-type.id-collision",
            map_ids("/valueTypes", &project.value_types),
        ),
        (
            "breg.function.id-collision",
            indexed_ids("/functions", &project.functions, |item| &item.id),
        ),
        (
            "breg.action.id-collision",
            indexed_ids("/actions", &project.actions, |item| &item.id),
        ),
        (
            "breg.access-profile.id-collision",
            indexed_ids("/accessProfiles", &project.access_profiles, |item| &item.id),
        ),
        (
            "breg.vocabulary.id-collision",
            indexed_ids("/vocabularies", &project.vocabularies, |item| &item.id),
        ),
        (
            "breg.statistical-dataset.id-collision",
            project
                .statistical_datasets
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str().to_owned(),
                        format!("/statisticalDatasets/{index}/id"),
                    )
                })
                .collect(),
        ),
    ] {
        add_collisions(document, &mut errors, code, &values);
    }
    if let Some(recipients) = &project.recipients {
        let mut values = indexed_ids(
            "/recipients/organizations",
            &recipients.organizations,
            |item| &item.id,
        );
        values.extend(indexed_ids(
            "/recipients/groups",
            &recipients.groups,
            |item| &item.id,
        ));
        add_collisions(
            document,
            &mut errors,
            "breg.recipient.id-collision",
            &values,
        );
    }
    if let Some(projection) = &project.manifest_projection {
        let base = "/manifestProjection";
        for (code, values) in [
            (
                "breg.manifest.application-profile-id-collision",
                indexed_ids(
                    &format!("{base}/catalog/applicationProfiles"),
                    &projection.catalog.application_profiles,
                    |item| &item.id,
                ),
            ),
            (
                "breg.manifest.dataset-id-collision",
                indexed_ids(&format!("{base}/datasets"), &projection.datasets, |item| {
                    &item.id
                }),
            ),
            (
                "breg.manifest.data-service-id-collision",
                indexed_ids(
                    &format!("{base}/dataServices"),
                    &projection.data_services,
                    |item| &item.id,
                ),
            ),
            (
                "breg.manifest.distribution-id-collision",
                indexed_ids(
                    &format!("{base}/distributions"),
                    &projection.distributions,
                    |item| &item.id,
                ),
            ),
            (
                "breg.manifest.entity-id-collision",
                indexed_ids(&format!("{base}/entities"), &projection.entities, |item| {
                    &item.id
                }),
            ),
            (
                "breg.manifest.vocabulary-id-collision",
                indexed_ids(
                    &format!("{base}/vocabularies"),
                    &projection.vocabularies,
                    |item| &item.id,
                ),
            ),
        ] {
            add_collisions(document, &mut errors, code, &values);
        }
        for (index, entity) in projection.entities.iter().enumerate() {
            let values = indexed_ids(
                &format!("{base}/entities/{index}/fields"),
                &entity.fields,
                |item| &item.id,
            );
            add_collisions(
                document,
                &mut errors,
                "breg.manifest.field-id-collision",
                &values,
            );
        }
    }
    for (index, entity) in project.entities.iter().enumerate() {
        entity_integrity(
            document,
            &mut errors,
            &format!("/recordTypes/{index}"),
            entity,
        );
        let entity_profiles = indexed_ids(
            &format!("/recordTypes/{index}/accessProfiles"),
            &entity.access_profiles,
            |profile| &profile.id,
        );
        let project_profiles = project
            .access_profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| {
                profile
                    .permissions
                    .entities
                    .iter()
                    .any(|grant| grant.entity == entity.id)
            })
            .map(|(profile_index, profile)| {
                (
                    profile.id.clone(),
                    format!("/accessProfiles/{profile_index}/id"),
                )
            })
            .collect::<Vec<_>>();
        add_cross_group_collisions(
            document,
            &mut errors,
            "breg.access-profile.id-collision",
            &project_profiles,
            &entity_profiles,
        );
    }
    let hooks = project
        .entities
        .iter()
        .enumerate()
        .flat_map(|(entity_index, entity)| {
            indexed_ids(
                &format!("/recordTypes/{entity_index}/hooks"),
                &entity.hooks,
                |hook| &hook.id,
            )
        })
        .collect::<Vec<_>>();
    add_collisions(document, &mut errors, "breg.hook.id-collision", &hooks);
    for (index, action) in project.actions.iter().enumerate() {
        action_integrity(document, &mut errors, &format!("/actions/{index}"), action);
    }

    let warning_groups = [
        (
            "breg.access-profile.duplicate-label",
            "access profiles",
            display_labels(
                "/accessProfiles",
                &project.access_profiles,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
        (
            "breg.statistical-dataset.duplicate-label",
            "statistical datasets",
            display_labels(
                "/statisticalDatasets",
                &project.statistical_datasets,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
        (
            "breg.dataset.duplicate-label",
            "datasets",
            display_labels(
                "/datasets",
                &project.datasets,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
        (
            "breg.review-authority.duplicate-label",
            "review authorities",
            display_labels(
                "/reviewAuthorities",
                &project.review_authorities,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
        (
            "breg.record-type.duplicate-label",
            "record types",
            display_labels(
                "/recordTypes",
                &project.entities,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
        (
            "breg.action.duplicate-label",
            "actions",
            display_labels(
                "/actions",
                &project.actions,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
    ];
    for (code, kind, values) in &warning_groups {
        add_duplicate_labels(document, &mut warnings, code, kind, values);
    }
    add_project_display_warnings(document, &mut warnings, project);
    add_profile_and_hook_display_warnings(
        document,
        &mut warnings,
        &project.entities,
        &[],
        &project.access_profiles,
    );
    add_nested_display_warnings(
        document,
        &mut warnings,
        "/recordTypes",
        &project.entities,
        "/actions",
        &project.actions,
    );
    for warning in warnings {
        decoded.document.push_warning(warning);
    }
    errors
}

#[allow(clippy::too_many_lines)]
fn add_project_display_warnings(
    document: &registry_platform_yaml::Document,
    warnings: &mut Vec<registry_platform_yaml::Diagnostic>,
    project: &RegistryProject,
) {
    if let Some(recipients) = &project.recipients {
        for (code, kind, values) in [
            (
                "breg.recipient-organization.duplicate-name",
                "recipient organizations",
                recipients
                    .organizations
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        (
                            item.id.clone(),
                            item.name.clone(),
                            format!("/recipients/organizations/{index}/name"),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            (
                "breg.recipient-group.duplicate-name",
                "recipient groups",
                recipients
                    .groups
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        (
                            item.id.clone(),
                            item.name.clone(),
                            format!("/recipients/groups/{index}/name"),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
        ] {
            add_duplicate_labels(document, warnings, code, kind, &values);
        }
    }

    let Some(projection) = &project.manifest_projection else {
        return;
    };
    let default_language = &project.project.default_language;
    for (code, kind, values) in [
        (
            "breg.manifest-dataset.duplicate-title",
            "manifest datasets",
            projection
                .datasets
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        format!("/manifestProjection/datasets/{index}/title"),
                        Some(&item.title),
                    )
                })
                .collect::<Vec<_>>(),
        ),
        (
            "breg.manifest-data-service.duplicate-title",
            "manifest data services",
            projection
                .data_services
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        format!("/manifestProjection/dataServices/{index}/title"),
                        Some(&item.title),
                    )
                })
                .collect::<Vec<_>>(),
        ),
        (
            "breg.manifest-distribution.duplicate-title",
            "manifest distributions",
            projection
                .distributions
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        format!("/manifestProjection/distributions/{index}/title"),
                        item.title.as_ref(),
                    )
                })
                .collect::<Vec<_>>(),
        ),
        (
            "breg.manifest-entity.duplicate-title",
            "manifest entities",
            projection
                .entities
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    (
                        item.id.as_str(),
                        format!("/manifestProjection/entities/{index}/title"),
                        item.title.as_ref(),
                    )
                })
                .collect::<Vec<_>>(),
        ),
    ] {
        let mut identified = BTreeMap::new();
        let mut anonymous = BTreeMap::new();
        for (id, pointer, text) in values {
            if let Some(text) = text {
                localized_display_texts(
                    default_language,
                    Some(id),
                    &pointer,
                    text,
                    &mut identified,
                    &mut anonymous,
                );
            }
        }
        for values in identified.values() {
            add_duplicate_labels(document, warnings, code, kind, values);
        }
    }

    for (vocabulary_index, vocabulary) in projection.vocabularies.iter().enumerate() {
        let mut identified = BTreeMap::new();
        let mut anonymous = BTreeMap::new();
        for (concept_index, concept) in vocabulary.concepts.iter().enumerate() {
            if let Some(label) = &concept.label {
                localized_display_texts(
                    default_language,
                    None,
                    &format!(
                        "/manifestProjection/vocabularies/{vocabulary_index}/concepts/{concept_index}/label"
                    ),
                    label,
                    &mut identified,
                    &mut anonymous,
                );
            }
        }
        for values in anonymous.values() {
            add_duplicate_locations(
                document,
                warnings,
                "breg.manifest-vocabulary-concept.duplicate-label",
                "manifest vocabulary concepts",
                values,
            );
        }
    }
}

fn add_nested_display_warnings(
    document: &registry_platform_yaml::Document,
    warnings: &mut Vec<registry_platform_yaml::Diagnostic>,
    entity_base: &str,
    entities: &[EntitySource],
    action_base: &str,
    actions: &[ActionSource],
) {
    for (entity_index, entity) in entities.iter().enumerate() {
        let values = entity_field_display_labels(&format!("{entity_base}/{entity_index}"), entity);
        add_duplicate_labels(
            document,
            warnings,
            "breg.field.duplicate-label",
            "fields",
            &values,
        );
    }
    for (action_index, action) in actions.iter().enumerate() {
        let values = display_labels(
            &format!("{action_base}/{action_index}/inputs"),
            &action.inputs,
            |input| &input.id,
            |input| input.display.label.as_deref(),
        );
        add_duplicate_labels(
            document,
            warnings,
            "breg.action-input.duplicate-label",
            "action inputs",
            &values,
        );
        if let ActionExecutionSource::Proposal { proposal } = &action.execution {
            let values = display_labels(
                &format!("{action_base}/{action_index}/execution/proposal/hooks"),
                &proposal.hooks,
                |hook| &hook.id,
                |hook| hook.display.label.as_deref(),
            );
            add_duplicate_labels(
                document,
                warnings,
                "breg.proposal-hook.duplicate-label",
                "Proposal hooks",
                &values,
            );
        }
    }
    let refusals = actions
        .iter()
        .enumerate()
        .flat_map(|(action_index, action)| match &action.plan {
            ActionPlanSource::Function { refusals, .. } => refusals
                .iter()
                .enumerate()
                .map(|(refusal_index, refusal)| {
                    (
                        refusal.label.clone(),
                        format!("{action_base}/{action_index}/plan/refusals/{refusal_index}/label"),
                    )
                })
                .collect::<Vec<_>>(),
            ActionPlanSource::Fixed { .. } => Vec::new(),
        })
        .collect::<Vec<_>>();
    add_duplicate_locations(
        document,
        warnings,
        "breg.action-refusal.duplicate-label",
        "action refusals",
        &refusals,
    );
}

fn add_profile_and_hook_display_warnings(
    document: &registry_platform_yaml::Document,
    warnings: &mut Vec<registry_platform_yaml::Diagnostic>,
    entities: &[EntitySource],
    extensions: &[EntityExtensionSource],
    project_profiles: &[crate::contract::ProjectAccessProfileSource],
) {
    let mut profiles = BTreeMap::<&str, Vec<LocatedDisplayText>>::new();
    let mut hooks = Vec::new();
    let members = entities
        .iter()
        .enumerate()
        .map(|(index, entity)| {
            (
                entity.id.as_str(),
                format!("/recordTypes/{index}"),
                &entity.access_profiles,
                &entity.hooks,
            )
        })
        .chain(extensions.iter().enumerate().map(|(index, extension)| {
            (
                extension.entity.as_str(),
                format!("/extendRecordTypes/{index}"),
                &extension.access_profiles,
                &extension.hooks,
            )
        }));
    for (entity, base, local_profiles, local_hooks) in members {
        profiles.entry(entity).or_default().extend(display_labels(
            &format!("{base}/accessProfiles"),
            local_profiles,
            |profile| &profile.id,
            |profile| profile.display.label.as_deref(),
        ));
        hooks.extend(display_labels(
            &format!("{base}/hooks"),
            local_hooks,
            |hook| &hook.id,
            |hook| hook.display.label.as_deref(),
        ));
    }
    for (entity, values) in profiles {
        add_duplicate_labels(
            document,
            warnings,
            "breg.access-profile.duplicate-label",
            "access profiles",
            &values,
        );
        // Root profile pairs are already checked once in their own inventory.
        // Only compare their applicable grants with local profiles here.
        for (index, profile) in project_profiles.iter().enumerate() {
            if !profile
                .permissions
                .entities
                .iter()
                .any(|grant| grant.entity == entity)
            {
                continue;
            }
            if let Some(label) = &profile.display.label {
                for local in &values {
                    add_duplicate_labels(
                        document,
                        warnings,
                        "breg.access-profile.duplicate-label",
                        "access profiles",
                        &[
                            (
                                profile.id.clone(),
                                label.clone(),
                                format!("/accessProfiles/{index}/display/label"),
                            ),
                            local.clone(),
                        ],
                    );
                }
            }
        }
    }
    add_duplicate_labels(
        document,
        warnings,
        "breg.hook.duplicate-label",
        "record hooks",
        &hooks,
    );
}

#[allow(clippy::too_many_lines)]
pub(crate) fn module_diagnostics(
    decoded: &mut Decoded<RegistryModule>,
) -> Vec<registry_platform_yaml::Diagnostic> {
    let module = &decoded.value;
    let document = &decoded.document;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for (code, values) in [
        (
            "breg.record-type.id-collision",
            indexed_ids("/recordTypes", &module.entities, |item| &item.id),
        ),
        (
            "breg.value-type.id-collision",
            map_ids("/valueTypes", &module.value_types),
        ),
        (
            "breg.function.id-collision",
            indexed_ids("/functions", &module.functions, |item| &item.id),
        ),
        (
            "breg.action.id-collision",
            indexed_ids("/actions", &module.actions, |item| &item.id),
        ),
    ] {
        add_collisions(document, &mut errors, code, &values);
    }
    extension_integrity(
        document,
        &mut errors,
        &module.entities,
        &module.extend_entities,
    );
    let mut hooks = module
        .entities
        .iter()
        .enumerate()
        .flat_map(|(entity_index, entity)| {
            indexed_ids(
                &format!("/recordTypes/{entity_index}/hooks"),
                &entity.hooks,
                |hook| &hook.id,
            )
        })
        .collect::<Vec<_>>();
    hooks.extend(module.extend_entities.iter().enumerate().flat_map(
        |(extension_index, extension)| {
            indexed_ids(
                &format!("/extendRecordTypes/{extension_index}/hooks"),
                &extension.hooks,
                |hook| &hook.id,
            )
        },
    ));
    add_collisions(document, &mut errors, "breg.hook.id-collision", &hooks);
    for (index, action) in module.actions.iter().enumerate() {
        action_integrity(document, &mut errors, &format!("/actions/{index}"), action);
    }

    for (code, kind, values) in [
        (
            "breg.record-type.duplicate-label",
            "record types",
            display_labels(
                "/recordTypes",
                &module.entities,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
        (
            "breg.action.duplicate-label",
            "actions",
            display_labels(
                "/actions",
                &module.actions,
                |item| &item.id,
                |item| item.display.label.as_deref(),
            ),
        ),
    ] {
        add_duplicate_labels(document, &mut warnings, code, kind, &values);
    }
    add_nested_display_warnings(
        document,
        &mut warnings,
        "/recordTypes",
        &[],
        "/actions",
        &module.actions,
    );
    add_profile_and_hook_display_warnings(
        document,
        &mut warnings,
        &module.entities,
        &module.extend_entities,
        &[],
    );

    let mut merged_field_labels = BTreeMap::<String, Vec<LocatedDisplayText>>::new();
    for (entity_index, entity) in module.entities.iter().enumerate() {
        merged_field_labels
            .entry(entity.id.clone())
            .or_default()
            .extend(entity_field_display_labels(
                &format!("/recordTypes/{entity_index}"),
                entity,
            ));
    }
    for (extension_index, extension) in module.extend_entities.iter().enumerate() {
        merged_field_labels
            .entry(extension.entity.clone())
            .or_default()
            .extend(extension_field_display_labels(
                &format!("/extendRecordTypes/{extension_index}"),
                extension,
            ));
    }
    for values in merged_field_labels.values() {
        add_duplicate_labels(
            document,
            &mut warnings,
            "breg.field.duplicate-label",
            "fields",
            values,
        );
    }
    for warning in warnings {
        decoded.document.push_warning(warning);
    }
    errors
}
