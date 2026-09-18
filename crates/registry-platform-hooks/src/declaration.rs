// SPDX-License-Identifier: Apache-2.0

//! Hook declarations: the project-side half of the hook configuration.
//!
//! A hooks document is an ordered list. Nothing registers implicitly, every
//! hook carries an explicit `id`, and declaration order is the execution order
//! among hooks on one trigger; that is the answer to import-order signals.
//! `trigger`, `when`, and `projection` are product vocabulary carried
//! opaquely: the library never validates them.

use std::collections::BTreeSet;

use registry_platform_canonical_json::parse_json_strict;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::error::{bounded_token, redacted_message};

/// The one handler ABI defined in hook contract version one.
pub const HOOK_HANDLER_ABI_V1: &str = "registry.hook-handler/v1";

/// When the hook runs relative to the triggering transaction.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Runs inside the triggering transaction and may refuse or shape the
    /// change. Local handler kinds only.
    Before,
    /// Runs after commit in the post-commit worker and cannot affect the
    /// triggering transaction.
    After,
}

impl HookPhase {
    /// The declaration spelling of the phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// One declared hook: a product trigger bound to one handler.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HookDeclaration {
    /// Explicit, unique hook identity. Declaration order is the execution
    /// order among hooks on one trigger.
    pub id: String,
    /// When the hook runs relative to the triggering transaction.
    pub phase: HookPhase,
    /// The product's committed change or lifecycle transition. Product
    /// vocabulary: the library never defines or validates a trigger.
    pub trigger: String,
    /// The product's condition document, validated by the product against its
    /// own condition language. Carried opaquely so a product keeps the
    /// condition shape it already has unchanged on adoption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Value>,
    /// Declared field identifiers the product may project into `data`.
    /// Product-validated; carried opaquely.
    pub projection: BTreeSet<String>,
    /// Where the handler runs.
    pub handler: HookHandlerSource,
}

/// Where a hook's handler runs.
///
/// The pairing rule: `rhai` requires `script`, `wasm` requires `module`,
/// `url` requires `destinationId`, and each
/// kind requires exactly its own fields and nothing else. `abi` is required on
/// `rhai` and `wasm` and forbidden on `url`; its value is closed and checked at
/// compile time in [`crate::validate_hooks`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HookHandlerSource {
    /// A reviewed Rhai script in the project.
    Rhai {
        /// Script path in the project.
        script: String,
        /// The handler ABI the script speaks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi: Option<String>,
    },
    /// A reviewed WASM module in the project.
    Wasm {
        /// Module path in the project.
        module: String,
        /// The handler ABI the module speaks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi: Option<String>,
    },
    /// A logical destination bound to a URL and a secret at runtime. The
    /// runtime names the binding it looks the key up in; the project carries
    /// no URL or secret.
    Url {
        /// Key in the runtime destination binding.
        destination_id: String,
    },
}

impl HookHandlerSource {
    /// The handler kind's declaration spelling.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Rhai { .. } => "rhai",
            Self::Wasm { .. } => "wasm",
            Self::Url { .. } => "url",
        }
    }
}

/// The project's declared hooks, in declaration order.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HooksDocument {
    /// Every declared hook. Order is preserved and is the execution order.
    pub hooks: Vec<HookDeclaration>,
}

impl HooksDocument {
    /// Parse a hooks document from untrusted JSON bytes.
    ///
    /// Untrusted input goes through the shared strict parser, which rejects
    /// duplicate object members at every depth; the caller remains responsible
    /// for bounding `bytes` before parsing. Shape violations, including
    /// kind/source pairing violations in either direction, are refused here.
    /// Compile-time semantic rules live in [`crate::validate_hooks`].
    ///
    /// # Errors
    ///
    /// Returns [`HookDeclarationError`] when the bytes are not strict JSON or
    /// do not match the declaration shape. A shape refusal names the member
    /// path it failed at, so an author of a long document is told which hook
    /// to look at.
    pub fn from_strict_json(bytes: &[u8]) -> Result<Self, HookDeclarationError> {
        use serde::de::IntoDeserializer as _;

        let value = parse_json_strict(bytes)?;
        serde_path_to_error::deserialize(value.into_deserializer()).map_err(|error| {
            let path = bounded_token(&error.path().to_string());
            HookDeclarationError::Shape {
                path,
                message: redacted_message(&error.into_inner().to_string()),
            }
        })
    }

    /// Apply the compile-time rules to the declared hooks, in order.
    ///
    /// # Errors
    ///
    /// Returns the first [`crate::validate::HookValidationError`] in
    /// declaration order.
    pub fn validate(&self) -> Result<(), crate::validate::HookValidationError> {
        crate::validate::validate_hooks(&self.hooks)
    }
}

/// Failure to parse a hooks document.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookDeclarationError {
    /// The document is not strict JSON.
    #[error("hooks document is not strict JSON: {0}")]
    Json(#[from] registry_platform_canonical_json::StrictJsonError),
    /// The document violates the declaration shape, at `path`. The
    /// deserializer's own wording, with the untrusted values it repeats
    /// redacted and bounded.
    #[error("hooks document violates the hook declaration shape at `{path}`: {message}")]
    Shape {
        /// The member path the refusal happened at, `.` at the document root.
        path: String,
        /// The redacted deserializer wording.
        message: String,
    },
}

impl HookDeclarationError {
    /// The stable diagnostic code for this refusal.
    ///
    /// Codes are part of the contract: operators and products match on them,
    /// so existing codes never change meaning and new refusals get new codes.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "hook.declaration.not_strict_json",
            Self::Shape { .. } => "hook.declaration.bad_shape",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MAX_DISPLAYED_TOKEN_BYTES;
    use serde_json::json;

    fn wasm_handler() -> Value {
        json!({
            "kind": "wasm",
            "module": "handlers/birth-followup.wasm",
            "abi": HOOK_HANDLER_ABI_V1,
        })
    }

    fn declaration_json(handler: Value) -> Value {
        json!({
            "id": "birth-registered-followup",
            "phase": "after",
            "trigger": "created",
            "projection": ["givenName", "familyName"],
            "handler": handler,
        })
    }

    #[test]
    fn parses_a_full_declaration_and_round_trips() {
        let document = json!({
            "hooks": [{
                "id": "birth-registered-followup",
                "phase": "after",
                "trigger": "created",
                "when": {"kind": "fields", "changed": ["familyName"]},
                "projection": ["givenName", "familyName"],
                "handler": wasm_handler(),
            }],
        });

        let parsed =
            HooksDocument::from_strict_json(&serde_json::to_vec(&document).expect("serializes"))
                .expect("parses");
        assert_eq!(parsed.hooks.len(), 1);
        let hook = &parsed.hooks[0];
        assert_eq!(hook.id, "birth-registered-followup");
        assert_eq!(hook.phase, HookPhase::After);
        assert_eq!(hook.trigger, "created");
        assert_eq!(
            hook.when,
            Some(json!({"kind": "fields", "changed": ["familyName"]}))
        );
        assert_eq!(
            hook.projection,
            BTreeSet::from(["givenName".to_owned(), "familyName".to_owned()])
        );
        assert_eq!(
            hook.handler,
            HookHandlerSource::Wasm {
                module: "handlers/birth-followup.wasm".to_owned(),
                abi: Some(HOOK_HANDLER_ABI_V1.to_owned()),
            }
        );
        assert_eq!(
            serde_json::to_value(hook).expect("serializes"),
            json!({
                "id": "birth-registered-followup",
                "phase": "after",
                "trigger": "created",
                "when": {"kind": "fields", "changed": ["familyName"]},
                // The projection is a set, so serialization order is sorted.
                "projection": ["familyName", "givenName"],
                "handler": wasm_handler(),
            })
        );
    }

    #[test]
    fn phase_spelling_is_snake_case() {
        let before: HookPhase = serde_json::from_value(json!("before")).expect("parses");
        let after: HookPhase = serde_json::from_value(json!("after")).expect("parses");
        assert_eq!(before, HookPhase::Before);
        assert_eq!(after, HookPhase::After);
        assert_eq!(before.as_str(), "before");
        assert_eq!(after.as_str(), "after");
        assert!(serde_json::from_value::<HookPhase>(json!("mid")).is_err());
    }

    #[test]
    fn rhai_handler_requires_script_and_nothing_else() {
        let missing: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"kind": "rhai", "abi": HOOK_HANDLER_ABI_V1}));
        assert!(missing.is_err(), "missing script refused");

        let extra: Result<HookHandlerSource, _> = serde_json::from_value(json!({
            "kind": "rhai",
            "script": "handlers/followup.rhai",
            "abi": HOOK_HANDLER_ABI_V1,
            "module": "handlers/followup.wasm",
        }));
        assert!(extra.is_err(), "extra module field refused");
    }

    #[test]
    fn wasm_handler_requires_module_and_nothing_else() {
        let missing: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"kind": "wasm", "abi": HOOK_HANDLER_ABI_V1}));
        assert!(missing.is_err(), "missing module refused");

        for extra_field in ["script", "destinationId", "when"] {
            let mut handler = wasm_handler();
            handler[extra_field] = json!("extra");
            let extra: Result<HookHandlerSource, _> = serde_json::from_value(handler);
            assert!(extra.is_err(), "extra {extra_field} field refused");
        }
    }

    #[test]
    fn url_handler_requires_destination_id_and_nothing_else() {
        let missing: Result<HookHandlerSource, _> = serde_json::from_value(json!({"kind": "url"}));
        assert!(missing.is_err(), "missing destinationId refused");

        let accepted: HookHandlerSource =
            serde_json::from_value(json!({"kind": "url", "destinationId": "case-intake"}))
                .expect("parses");
        assert_eq!(
            accepted,
            HookHandlerSource::Url {
                destination_id: "case-intake".to_owned(),
            }
        );
        assert_eq!(accepted.kind(), "url");

        for extra_field in ["module", "abi"] {
            let extra: Result<HookHandlerSource, _> = serde_json::from_value(json!({
                "kind": "url",
                "destinationId": "case-intake",
                extra_field: "extra",
            }));
            assert!(extra.is_err(), "extra {extra_field} field refused");
        }
    }

    #[test]
    fn unknown_handler_kind_is_refused() {
        let unknown: Result<HookHandlerSource, _> =
            serde_json::from_value(json!({"kind": "lambda", "function": "followup"}));
        assert!(unknown.is_err(), "closed kind set refuses unknown kinds");
    }

    #[test]
    fn declaration_order_is_preserved() {
        let document = json!({
            "hooks": [
                {"id": "a-first", "phase": "after", "trigger": "created",
                 "projection": [], "handler": wasm_handler()},
                {"id": "b-second", "phase": "after", "trigger": "created",
                 "projection": [], "handler": wasm_handler()},
                {"id": "c-third", "phase": "after", "trigger": "patched",
                 "projection": [], "handler": wasm_handler()},
            ],
        });

        let parsed =
            HooksDocument::from_strict_json(&serde_json::to_vec(&document).expect("serializes"))
                .expect("parses");
        let ids: Vec<&str> = parsed.hooks.iter().map(|hook| hook.id.as_str()).collect();
        assert_eq!(ids, ["a-first", "b-second", "c-third"]);
    }

    #[test]
    fn strict_parse_refuses_duplicate_members_at_every_depth() {
        let duplicated_handler = r#"{"hooks":[{"id":"a","phase":"after","trigger":"created","projection":[],"handler":{"kind":"url","destinationId":"a","destinationId":"b"}}]}"#;
        for raw in [
            br#"{"hooks":[],"hooks":[]}"#.to_vec(),
            duplicated_handler.as_bytes().to_vec(),
        ] {
            let error = HooksDocument::from_strict_json(&raw).expect_err("duplicate refused");
            assert!(
                error.to_string().contains("duplicate JSON object member"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn unknown_document_fields_are_refused() {
        let raw = br#"{"hooks":[],"extra":true}"#;
        let error = HooksDocument::from_strict_json(raw).expect_err("unknown field refused");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn declaration_json_carries_the_abi_opaquely_until_validation() {
        // An unknown ABI string parses: the closed-set check is a compile-time
        // rule with a pinned diagnostic, not a parse accident.
        let mut handler = wasm_handler();
        handler["abi"] = json!("registry.action-handler/v1");
        let parsed: HookDeclaration =
            serde_json::from_value(declaration_json(handler)).expect("parses");
        assert_eq!(
            parsed.handler,
            HookHandlerSource::Wasm {
                module: "handlers/birth-followup.wasm".to_owned(),
                abi: Some("registry.action-handler/v1".to_owned()),
            }
        );
    }

    #[test]
    fn handler_kind_spelling_is_pinned() {
        let rhai: HookHandlerSource = serde_json::from_value(json!({
            "kind": "rhai", "script": "handlers/followup.rhai", "abi": HOOK_HANDLER_ABI_V1,
        }))
        .expect("parses");
        assert_eq!(rhai.kind(), "rhai");
        assert_eq!(wasm_handler_serialized().kind(), "wasm");
    }

    #[test]
    fn document_validate_applies_the_compile_time_rules_after_parse() {
        let document = json!({
            "hooks": [
                {"id": "a-first", "phase": "after", "trigger": "created",
                 "projection": [], "handler": wasm_handler()},
                {"id": "b-second", "phase": "before", "trigger": "patched",
                 "projection": [], "handler": {"kind": "url", "destinationId": "case-intake"}},
            ],
        });
        let parsed =
            HooksDocument::from_strict_json(&serde_json::to_vec(&document).expect("serializes"))
                .expect("parses");
        let error = parsed.validate().expect_err("before with url is refused");
        assert_eq!(error.code(), "hook.declaration.before_phase_remote_handler");
        assert_eq!(error.index(), Some(1));
    }

    #[test]
    fn an_empty_document_parses_and_validates() {
        let parsed = HooksDocument::from_strict_json(br#"{"hooks":[]}"#).expect("parses");
        assert!(parsed.hooks.is_empty());
        parsed.validate().expect("no hooks, no refusals");
    }

    #[test]
    fn a_shape_violation_names_the_member_path() {
        let document = json!({
            "hooks": [
                {"id": "a-first", "phase": "after", "trigger": "created",
                 "projection": [], "handler": wasm_handler()},
                {"id": "b-second", "phase": "after", "trigger": "created",
                 "projection": [], "handler": {"kind": "wasm", "abi": HOOK_HANDLER_ABI_V1}},
            ],
        });
        let error =
            HooksDocument::from_strict_json(&serde_json::to_vec(&document).expect("serializes"))
                .expect_err("the second handler has no module");
        assert!(
            error.to_string().contains("hooks[1].handler"),
            "the path to the offending member is reported: {error}"
        );
    }

    #[test]
    fn an_untrusted_member_name_never_reaches_display_unbounded() {
        let huge = "x".repeat(64 * 1024);
        let raw =
            serde_json::to_vec(&json!({"hooks": [], huge.clone(): true})).expect("serializes");
        let rendered = HooksDocument::from_strict_json(&raw)
            .expect_err("unknown member refused")
            .to_string();
        assert!(rendered.len() < 1_024, "{} bytes rendered", rendered.len());
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn every_declaration_code_is_distinct_and_in_its_namespace() {
        let variants = [
            HookDeclarationError::Json(
                parse_json_strict(b"{").expect_err("a truncated object is not strict JSON"),
            ),
            HookDeclarationError::Shape {
                path: String::new(),
                message: String::new(),
            },
        ];
        let codes: Vec<&str> = variants.iter().map(HookDeclarationError::code).collect();
        assert_eq!(
            codes.iter().collect::<BTreeSet<_>>().len(),
            codes.len(),
            "codes are distinct: {codes:?}"
        );
        for code in codes {
            assert!(
                code.starts_with("hook.declaration."),
                "{code} is outside the namespace"
            );
        }
    }

    fn wasm_handler_serialized() -> HookHandlerSource {
        serde_json::from_value(wasm_handler()).expect("parses")
    }
}
