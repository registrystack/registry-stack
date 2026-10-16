// SPDX-License-Identifier: Apache-2.0
//! Pure authoring checks for bounded binary attachment slots.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    AttachmentSlotSource, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_CONTENT_TYPES, MAX_ATTACHMENT_SLOTS,
};
use crate::diagnostics::Diagnostic;
use crate::logical_names::reserved_logical_name;
use crate::model::CompiledAttachmentSlot;

pub(crate) fn validate_slots(
    slots: &[AttachmentSlotSource],
    field_names: &BTreeSet<String>,
    base: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if slots.len() > MAX_ATTACHMENT_SLOTS {
        errors.push(Diagnostic::error(
            "breg.attachment.slots-bounds-invalid",
            base,
            "a Proposal supports at most eight attachment slots",
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, slot) in slots.iter().enumerate() {
        let path = format!("{base}[{index}]");
        super::validate_id(&slot.id, &format!("{path}.id"), errors);
        if reserved_logical_name(&slot.id) || field_names.contains(&slot.id) {
            errors.push(Diagnostic::error(
                "breg.attachment.id-collision",
                format!("{path}.id"),
                "an attachment ID must not collide with a stored, derived, API, or server-owned field name",
            ));
        }
        if !ids.insert(&slot.id) {
            errors.push(Diagnostic::error(
                "breg.attachment.id-duplicate",
                format!("{path}.id"),
                "an attachment slot ID is duplicated",
            ));
        }
        if slot.maximum_bytes == 0 || slot.maximum_bytes > MAX_ATTACHMENT_BYTES {
            errors.push(Diagnostic::error(
                "breg.attachment.maximum-bytes-bounds-invalid",
                format!("{path}.maximumBytes"),
                "attachment maximumBytes must be between 1 and 16777216 (16 MiB)",
            ));
        }
        if slot.content_types.is_empty() || slot.content_types.len() > MAX_ATTACHMENT_CONTENT_TYPES
        {
            errors.push(Diagnostic::error(
                "breg.attachment.content-types-bounds-invalid",
                format!("{path}.contentTypes"),
                "an attachment slot requires between one and sixteen content types",
            ));
        }
        let mut types = BTreeSet::new();
        for (type_index, content_type) in slot.content_types.iter().enumerate() {
            let type_path = format!("{path}.contentTypes[{type_index}]");
            if !valid_content_type(content_type) {
                errors.push(Diagnostic::error(
                    "breg.attachment.content-type-invalid",
                    &type_path,
                    "an attachment content type must be a lowercase concrete type/subtype without parameters or wildcards",
                ));
            }
            if !types.insert(content_type) {
                errors.push(Diagnostic::error(
                    "breg.attachment.content-type-duplicate",
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

pub(crate) fn compile_slots(
    slots: &[AttachmentSlotSource],
) -> BTreeMap<String, CompiledAttachmentSlot> {
    slots
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
