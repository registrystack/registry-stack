// SPDX-License-Identifier: Apache-2.0
//! Pure authoring checks for request-owned binary slots. A slot participates in
//! field authority but never becomes a scalar column or a query input.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    AccessProfileSource, EntitySource, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_CONTENT_TYPES,
    MAX_ATTACHMENT_SLOTS,
};
use crate::diagnostics::Diagnostic;
use crate::logical_names::{default_api_name, reserved_logical_name};
use crate::model::{request_query_field_id_for_api, CompiledAttachmentSlot};

pub(super) fn validate(entity: &EntitySource, errors: &mut Vec<Diagnostic>) {
    let base = format!("entities[id={}].attachments", entity.id);
    if !entity.attachments.is_empty() && entity.change_request.is_none() {
        errors.push(Diagnostic::error(
            "attachment.entity.not_request",
            &base,
            "attachment slots require a change-request entity",
        ));
    }
    if entity.attachments.len() > MAX_ATTACHMENT_SLOTS {
        errors.push(Diagnostic::error(
            "attachment.slots.bounds_invalid",
            &base,
            "a request entity supports at most eight attachment slots",
        ));
    }
    let fields = entity
        .fields
        .iter()
        .map(|field| (&field.id, field.api_name.as_deref()))
        .chain(entity.derived.iter().flat_map(|derived| {
            derived
                .fields
                .iter()
                .map(|field| (&field.id, field.api_name.as_deref()))
        }))
        .flat_map(|(id, api_name)| {
            [
                id.clone(),
                api_name
                    .map(str::to_owned)
                    .unwrap_or_else(|| default_api_name(id)),
            ]
        })
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    for (index, slot) in entity.attachments.iter().enumerate() {
        let path = format!("{base}[{index}]");
        super::validate_id(&slot.id, &format!("{path}.id"), errors);
        if reserved_logical_name(&slot.id)
            || request_query_field_id_for_api(&slot.id).is_some()
            || fields.contains(&slot.id)
        {
            errors.push(Diagnostic::error(
                "attachment.id.collision",
                format!("{path}.id"),
                "an attachment ID must not collide with a stored, derived, API, or server-owned field name",
            ));
        }
        if !ids.insert(&slot.id) {
            errors.push(Diagnostic::error(
                "attachment.id.duplicate",
                format!("{path}.id"),
                "an attachment slot ID is duplicated",
            ));
        }
        if slot.maximum_bytes == 0 || slot.maximum_bytes > MAX_ATTACHMENT_BYTES {
            errors.push(Diagnostic::error(
                "attachment.maximum_bytes.bounds_invalid",
                format!("{path}.maximumBytes"),
                "attachment maximumBytes must be between 1 and 16777216 (16 MiB)",
            ));
        }
        if slot.content_types.is_empty() || slot.content_types.len() > MAX_ATTACHMENT_CONTENT_TYPES
        {
            errors.push(Diagnostic::error(
                "attachment.content_types.bounds_invalid",
                format!("{path}.contentTypes"),
                "an attachment slot requires between one and sixteen content types",
            ));
        }
        let mut types = BTreeSet::new();
        for (type_index, content_type) in slot.content_types.iter().enumerate() {
            let type_path = format!("{path}.contentTypes[{type_index}]");
            if !valid_content_type(content_type) {
                errors.push(Diagnostic::error(
                    "attachment.content_type.invalid",
                    &type_path,
                    "an attachment content type must be a lowercase concrete type/subtype without parameters or wildcards",
                ));
            }
            if !types.insert(content_type) {
                errors.push(Diagnostic::error(
                    "attachment.content_type.duplicate",
                    type_path,
                    "attachment content types must be unique",
                ));
            }
        }
    }
}

fn valid_content_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    [kind, subtype].into_iter().all(|component| {
        !component.is_empty()
            && component.len() <= 127
            && (component.as_bytes()[0].is_ascii_lowercase()
                || component.as_bytes()[0].is_ascii_digit())
            && component.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    })
}

pub(super) fn validate_profile(
    entity: &EntitySource,
    profile: &AccessProfileSource,
    errors: &mut Vec<Diagnostic>,
) {
    for slot in &entity.attachments {
        let base = format!(
            "entities[id={}].accessProfiles[id={}]",
            entity.id, profile.id
        );
        for (member, fields) in [
            ("filterableFields", &profile.filterable_fields),
            ("sortableFields", &profile.sortable_fields),
        ] {
            if fields.contains(&slot.id) {
                errors.push(Diagnostic::error(
                    "attachment.access.processing_unsupported",
                    format!("{base}.{member}[value={}]", slot.id),
                    "attachment slots cannot be filtered or sorted",
                ));
            }
        }
        for (index, boundary) in profile.row_boundaries.iter().enumerate() {
            if boundary.field == slot.id {
                errors.push(Diagnostic::error(
                    "attachment.access.processing_unsupported",
                    format!("{base}.rowBoundaries[{index}].field"),
                    "attachment slots cannot be row-boundary inputs",
                ));
            }
        }
        if profile.anonymous {
            for (member, fields) in [
                ("readableFields", &profile.readable_fields),
                ("writableFields", &profile.writable_fields),
            ] {
                if fields.contains(&slot.id) {
                    errors.push(Diagnostic::error(
                        "attachment.access.authentication_required",
                        format!("{base}.{member}[value={}]", slot.id),
                        "attachment metadata and content require authenticated request access",
                    ));
                }
            }
        }
    }
}

pub(super) fn compile(entity: &EntitySource) -> BTreeMap<String, CompiledAttachmentSlot> {
    entity
        .attachments
        .iter()
        .map(|slot| {
            (
                slot.id.clone(),
                CompiledAttachmentSlot {
                    id: slot.id.clone(),
                    required: slot.required,
                    maximum_bytes: slot.maximum_bytes,
                    content_types: slot.content_types.clone(),
                    classification: slot.classification,
                },
            )
        })
        .collect()
}
